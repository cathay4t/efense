// SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::ring_buf::RingBuf,
    macros::{btf_map, xdp},
    programs::XdpContext,
};
use aya_log_ebpf::{info, warn};
use efence_core::{EfenceErrorCode, UDP4_EVENTS_BATCH_SIZE, Udp4Event};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[inline(always)]
fn ptr_at<T>(
    ctx: &XdpContext,
    offset: usize,
) -> Result<*const T, EfenceErrorCode> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(EfenceErrorCode::PacketTooSmall);
    }

    Ok((start + offset) as *const T)
}

// Is this 4096 size correct?
#[btf_map]
static UDP4_EVENTS: RingBuf<Udp4Event, UDP4_EVENTS_BATCH_SIZE, 0> =
    RingBuf::new();

fn submit_udp4_event(ctx: &XdpContext, event: Udp4Event) {
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

#[xdp]
pub fn efence_ebpf(ctx: XdpContext) -> u32 {
    if let Err(_) = try_efence_ebpf(&ctx) {
        warn!(&ctx, "error processing packet");
    }
    xdp_action::XDP_PASS
}

fn try_efence_ebpf(ctx: &XdpContext) -> Result<(), EfenceErrorCode> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(());
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

    let proto = unsafe { (*ipv4hdr).proto() }
        .map_err(|_| EfenceErrorCode::InvalidProtocol)?;

    match proto {
        IpProto::Tcp => (),
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            // the src_port() already convert the endian to native.
            let src_port = unsafe { (*udphdr).src_port() };
            let dst_port = unsafe { (*udphdr).dst_port() };
            submit_udp4_event(
                ctx,
                Udp4Event::new(src, dst, src_port, dst_port),
            );
            info!(ctx, "received a UDP packet",);
        }
        _ => (),
    };

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
