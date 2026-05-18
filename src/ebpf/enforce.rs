// SPDX-License-Identifier: GPL-2.0-only

//! Enforcement XDP program.
//!
//! The data path is:
//!
//! 1. Look up the ingress interface index in the
//!    [`UDP_IN_IF2LPM`](IFACE_TO_LPM) hash-of-maps. If the interface has no
//!    policy attached, pass.
//! 2. Run a longest-prefix match against the source IPv4 address on the
//!    per-interface LPM trie. The trie returns the canonical [`Ipv4Cidr`] of
//!    the matching rule (or `None` ⇒ default action).
//! 3. Look up `(matched_prefix, src_port)` in the flat
//!    [`UDP_IN_PORT_ACT`](PORT_ACTION) hash. If miss, try the `(matched_prefix,
//!    PORT_ANY)` "any source port" fallback.
//! 4. If everything missed, return the per-interface default action from
//!    [`UDP_IN_IFACE_DFLT`](IFACE_DEFAULT_ACTION), defaulting to `XDP_PASS` if
//!    even that map has no entry for this interface.

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::{Array, HashOfMaps, LpmTrie, lpm_trie::Key as LpmKey},
    macros::{btf_map, map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use efence_core::{
    ACTION_DROP, ACTION_PASS, CFG_BLOB_LEN, EfenceErrorCode, Ipv4Cidr,
    MAX_IFACES, MAX_PREFIX_PORT_ENTRIES, MAX_PREFIXES, PORT_ANY, PrefixPort,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::ptr_at;

// ---------------------------------------------------------------------------
// Maps
//
// `IFACE_TO_LPM` is a BTF hash-of-maps; its inner template is a BTF
// LPM trie. The two trailing const generics on the outer match the
// userspace capacity (`MAX_IFACES`) and `0` flags.
//
// `IFACE_DEFAULT_ACTION` and `PORT_ACTION` are *legacy* hash maps
// declared with `#[map]`. aya's BTF map set does not yet include a
// `HashMap`, so for flat (un-nested) hash tables we fall back to the
// legacy map definition path; aya supports both in the same ELF.
// ---------------------------------------------------------------------------

/// Per-interface UDP-ingress LPM trie.
#[btf_map(name = "UDP_IN_IF2LPM")]
static IFACE_TO_LPM: HashOfMaps<
    u32,
    LpmTrie<[u8; 4], Ipv4Cidr, { MAX_PREFIXES as usize }>,
    { MAX_IFACES as usize },
    0,
> = HashOfMaps::new();

/// `(matched_prefix, src_port)` → action lookup.
#[map(name = "UDP_IN_PORT_ACT")]
static PORT_ACTION: HashMap<PrefixPort, u32> =
    HashMap::<PrefixPort, u32>::with_max_entries(MAX_PREFIX_PORT_ENTRIES, 0);

/// Per-interface default action.
#[map(name = "UDP_IN_IFACE_DFLT")]
static IFACE_DEFAULT_ACTION: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(MAX_IFACES, 0);

/// Serialized JSON blob of the userspace `EfenceConfig`. Opaque to the
/// kernel program: it is only ever read by `efctl show`. Declared here
/// so the verifier-loaded program owns the pin lifetime.
#[btf_map(name = "CFG")]
static CFG: Array<u8, CFG_BLOB_LEN, 0> = Array::new();

/// Length in bytes of the meaningful prefix of [`CFG`].
#[btf_map(name = "CFG_LEN")]
static CFG_LEN: Array<u32, 1, 0> = Array::new();

// ---------------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------------

#[xdp]
pub fn efence_net_ingress_apply(ctx: XdpContext) -> u32 {
    match try_efence_net_ingress_apply(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_efence_net_ingress_apply(
    ctx: &XdpContext,
) -> Result<u32, EfenceErrorCode> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let proto = unsafe { (*ipv4hdr).proto() }
        .map_err(|_| EfenceErrorCode::InvalidProtocol)?;
    if proto != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip: [u8; 4] = unsafe { (*ipv4hdr).src_addr };

    let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let src_port: u16 = unsafe { (*udphdr).src_port() };

    let ifindex = ctx.ingress_ifindex() as u32;

    Ok(decide(ifindex, src_ip, src_port))
}

#[inline(always)]
fn decide(ifindex: u32, src_ip: [u8; 4], src_port: u16) -> u32 {
    // Step 1: look up the per-interface LPM trie.
    let inner_lpm = match unsafe { IFACE_TO_LPM.get(&ifindex) } {
        Some(t) => t,
        // No policy attached to this interface: let it through.
        None => return xdp_action::XDP_PASS,
    };

    // Step 2: longest-prefix match against the source IPv4 address. The
    // LPM key carries the *maximum* prefix length (32) so it matches
    // any inserted prefix up to /32.
    let lpm_key = LpmKey::new(32, src_ip);
    let matched_prefix: Ipv4Cidr = match inner_lpm.get(&lpm_key) {
        Some(p) => *p,
        // No matching prefix: fall through to the per-iface default.
        None => return iface_default_action(ifindex),
    };

    // Step 3: exact (prefix, port) match, with PORT_ANY fallback.
    let key_exact = PrefixPort::new(matched_prefix, src_port);
    if let Some(action) = unsafe { PORT_ACTION.get(key_exact) } {
        return action_to_xdp(*action);
    }
    let key_any = PrefixPort::new(matched_prefix, PORT_ANY);
    if let Some(action) = unsafe { PORT_ACTION.get(key_any) } {
        return action_to_xdp(*action);
    }

    // Step 4: per-interface default.
    iface_default_action(ifindex)
}

#[inline(always)]
fn iface_default_action(ifindex: u32) -> u32 {
    let action = match unsafe { IFACE_DEFAULT_ACTION.get(ifindex) } {
        Some(a) => *a,
        None => ACTION_PASS,
    };
    action_to_xdp(action)
}

#[inline(always)]
fn action_to_xdp(action: u32) -> u32 {
    match action {
        ACTION_DROP => xdp_action::XDP_DROP,
        ACTION_PASS => xdp_action::XDP_PASS,
        _ => xdp_action::XDP_PASS,
    }
}
