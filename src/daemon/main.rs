// SPDX-License-Identifier: Apache-2.0

use std::{mem, net::Ipv4Addr};

use anyhow::{Context as _, bail};
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpMode},
};
use clap::Parser;
use efence::Udp4Event;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{io::Interest, signal};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp2s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use
    // the new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load the eBPF program into buffer and initializes the maps and BTF from
    // /sys/kernel/btf/vmlinux
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/efence_ebpf_cli" // this is the CLI tool name
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF
            // program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            )?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let ring_buf = ebpf
        .take_map("UDP4_EVENTS")
        .context("UDP4_EVENTS map not found")?;
    let ring_buf = RingBuf::try_from(ring_buf)
        .context("failed to open UDP4_EVENTS ring buffer")?;
    let mut udp4_events =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, Interest::READABLE)?;
    tokio::task::spawn(async move {
        loop {
            let mut guard = udp4_events.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                match parse_udp4_event(&item) {
                    Ok(event) => println!(
                        "UDP4 src={} dst={} src_port={} dst_port={}",
                        Ipv4Addr::from(event.src),
                        Ipv4Addr::from(event.dst),
                        event.src_port,
                        event.dst_port,
                    ),
                    Err(e) => warn!("failed to parse UDP4 event: {e}"),
                }
            }
            guard.clear_ready();
        }
    });

    let Opt { iface } = opt;
    // You may have multiple eBPF function, there is attach BPF function
    // `efence_ebpf` into kernel.
    let program: &mut Xdp =
        ebpf.program_mut("efence_ebpf").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn parse_udp4_event(bytes: &[u8]) -> anyhow::Result<Udp4Event> {
    if bytes.len() != mem::size_of::<Udp4Event>() {
        bail!(
            "invalid UDP4 event size: got {}, expected {}",
            bytes.len(),
            mem::size_of::<Udp4Event>()
        );
    }

    let src = u32::from_ne_bytes(bytes[0..4].try_into()?);
    let dst = u32::from_ne_bytes(bytes[4..8].try_into()?);
    let src_port = u16::from_ne_bytes(bytes[8..10].try_into()?);
    let dst_port = u16::from_ne_bytes(bytes[10..12].try_into()?);

    Ok(Udp4Event::new(src, dst, src_port, dst_port))
}
