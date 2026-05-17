// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpMode},
};
use efence::{EfenceError, Udp4Event};
use efence_core::Udp4EventRaw;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{io::Interest, signal};

const ARG_IFACE: &str = "IFACE";

pub(crate) struct CommandMonitor;

impl CommandMonitor {
    pub(crate) const CMD: &str = "monitor";

    pub(crate) fn new_cmd() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("Monitor network events")
            .arg(
                clap::Arg::new(ARG_IFACE)
                    .short('i')
                    .long("iface")
                    .required(true)
                    .help("Interface to attach XDP program to"),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<(), EfenceError> {
        // Bump the memlock rlimit. This is needed for older kernels that don't
        // use the new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        // Load the eBPF program into buffer and initializes the maps and BTF
        // from /sys/kernel/btf/vmlinux
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/efence_ebpf_cli" // this is the CLI tool name
        )))?;
        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                // This can happen if you remove all log statements from your
                // eBPF program.
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
            .ok_or_else(|| EfenceError::from("UDP4_EVENTS map not found"))?;
        let ring_buf = RingBuf::try_from(ring_buf)?;
        let mut udp4_events = tokio::io::unix::AsyncFd::with_interest(
            ring_buf,
            Interest::READABLE,
        )?;
        tokio::task::spawn(async move {
            loop {
                let mut guard = udp4_events.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    match parse_udp4_event(&item) {
                        Ok(event) => {
                            if let Ok(s) = serde_yaml::to_string(&[event]) {
                                println!("{s}");
                            }
                        }
                        Err(e) => warn!("failed to parse UDP4 event: {e}"),
                    }
                }
                guard.clear_ready();
            }
        });

        let iface = matches
            .get_one::<String>(ARG_IFACE)
            .expect("clap required iface");
        let program: &mut Xdp =
            ebpf.program_mut("efence_ebpf").unwrap().try_into()?;
        program.load()?;
        program.attach(iface, XdpMode::default())?;

        let ctrl_c = signal::ctrl_c();
        eprintln!("Waiting for Ctrl-C...");
        ctrl_c.await?;
        eprintln!("Exiting...");

        Ok(())
    }
}

fn parse_udp4_event(bytes: &[u8]) -> Result<Udp4Event, EfenceError> {
    if bytes.len() != size_of::<Udp4EventRaw>() {
        return Err(EfenceError::from(format!(
            "invalid UDP4 event size: got {}, expected {}",
            bytes.len(),
            size_of::<Udp4EventRaw>()
        )));
    }

    let raw = Udp4EventRaw::new(
        u32::from_ne_bytes(bytes[0..4].try_into()?),
        u32::from_ne_bytes(bytes[4..8].try_into()?),
        u16::from_ne_bytes(bytes[8..10].try_into()?),
        u16::from_ne_bytes(bytes[10..12].try_into()?),
    );

    Ok(Udp4Event::from(raw))
}
