// SPDX-License-Identifier: GPL-2.0-only

//! Monitor-only XDP program: never drops, only emits ring-buffer events
//! for observed TCP/UDP IPv4 traffic.

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::ring_buf::RingBuf,
    helpers::bpf_ktime_get_boot_ns,
    macros::{btf_map, xdp},
    programs::XdpContext,
};
use aya_log_ebpf::{info, warn};
use efence_core::{
    EfenceErrorCode, TCP4_EVENTS_RING_BUF_SIZE, Tcp4EventRaw,
    UDP4_EVENTS_RING_BUF_SIZE, Udp4EventRaw,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::ptr_at;

#[btf_map]
static UDP4_EVENTS: RingBuf<Udp4EventRaw, UDP4_EVENTS_RING_BUF_SIZE, 0> =
    RingBuf::new();

fn submit_udp4_event(ctx: &XdpContext, event: Udp4EventRaw) {
    match UDP4_EVENTS.reserve(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {
            warn!(ctx, "UDP4_EVENTS ring buffer is full, dropping event",);
        }
    }
}

#[btf_map]
static TCP4_EVENTS: RingBuf<Tcp4EventRaw, TCP4_EVENTS_RING_BUF_SIZE, 0> =
    RingBuf::new();

fn submit_tcp4_event(ctx: &XdpContext, event: Tcp4EventRaw) {
    match TCP4_EVENTS.reserve(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {
            warn!(ctx, "TCP4_EVENTS ring buffer is full, dropping event",);
        }
    }
}

#[xdp]
pub fn efence_net_ingress_monitor(ctx: XdpContext) -> u32 {
    if try_efence_net_ingress_monitor(&ctx).is_err() {
        warn!(&ctx, "error processing packet");
    }
    xdp_action::XDP_PASS
}

fn try_efence_net_ingress_monitor(
    ctx: &XdpContext,
) -> Result<(), EfenceErrorCode> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;

    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(());
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let src = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

    let proto = unsafe { (*ipv4hdr).proto() }
        .map_err(|_| EfenceErrorCode::InvalidProtocol)?;

    match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let ack = unsafe { (*tcphdr).ack() };
            let syn = unsafe { (*tcphdr).syn() };
            if ack != 0 && syn == 0 {
                let ip_hdr_len = unsafe { (*ipv4hdr).ihl() as u16 * 4 };
                let tcp_hdr_len = unsafe { (*tcphdr).doff() as u16 * 4 };
                let ip_tot_len = unsafe { (*ipv4hdr).tot_len() };
                if ip_tot_len == ip_hdr_len + tcp_hdr_len {
                    let src_port =
                        u16::from_be_bytes(unsafe { (*tcphdr).source });
                    let dst_port =
                        u16::from_be_bytes(unsafe { (*tcphdr).dest });
                    let tstamp = unsafe { bpf_ktime_get_boot_ns() };
                    submit_tcp4_event(
                        ctx,
                        Tcp4EventRaw::new(src, dst, src_port, dst_port, tstamp),
                    );
                    info!(ctx, "received a TCP handshake ACK packet",);
                }
            }
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let src_port = unsafe { (*udphdr).src_port() };
            let dst_port = unsafe { (*udphdr).dst_port() };
            let tstamp = unsafe { bpf_ktime_get_boot_ns() };
            submit_udp4_event(
                ctx,
                Udp4EventRaw::new(src, dst, src_port, dst_port, tstamp),
            );
            info!(ctx, "received a UDP packet",);
        }
        _ => (),
    };

    Ok(())
}
