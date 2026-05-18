// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;

use aya::{
    maps::{MapData, RingBuf},
    programs::{Xdp, XdpMode},
};
use efence::{EfenceError, EfenceEvent, Tcp4Event, Udp4Event};
use efence_core::{Tcp4EventRaw, Udp4EventRaw};
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
        bump_memlock();
        let mut ebpf = load_ebpf_program()?;
        init_ebpf_logger(&mut ebpf);

        let (ev_tx, ev_rx) = tokio::sync::mpsc::unbounded_channel();

        spawn_udp4_task(
            take_ring_buf(&mut ebpf, "UDP4_EVENTS")?,
            ev_tx.clone(),
        );
        spawn_tcp4_task(take_ring_buf(&mut ebpf, "TCP4_EVENTS")?, ev_tx);
        spawn_event_printer(ev_rx);

        let iface = matches
            .get_one::<String>(ARG_IFACE)
            .expect("clap required iface");
        attach_xdp_program(&mut ebpf, iface)?;

        let ctrl_c = signal::ctrl_c();
        eprintln!("Waiting for Ctrl-C...");
        ctrl_c.await?;
        eprintln!("Exiting...");

        Ok(())
    }
}

fn bump_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn load_ebpf_program() -> Result<aya::Ebpf, EfenceError> {
    Ok(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/efence_ebpf_cli"
    )))?)
}

fn init_ebpf_logger(ebpf: &mut aya::Ebpf) {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            )
            .expect("Failed to create AsyncFd for logger");
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
}

fn take_ring_buf(
    ebpf: &mut aya::Ebpf,
    name: &str,
) -> Result<RingBuf<impl Borrow<MapData> + Send + 'static>, EfenceError> {
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| EfenceError::from(format!("{name} map not found")))?;
    Ok(RingBuf::try_from(map)?)
}

fn spawn_udp4_task(
    ring_buf: RingBuf<impl Borrow<MapData> + Send + 'static>,
    tx: tokio::sync::mpsc::UnboundedSender<EfenceEvent>,
) {
    let mut events =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, Interest::READABLE)
            .expect("Failed to create AsyncFd for UDP4 ring buffer");
    tokio::task::spawn(async move {
        loop {
            let mut guard = events.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                match Udp4EventRaw::parse(&item) {
                    Ok(raw) => {
                        let event = Udp4Event::from(raw);
                        let _ = tx.send(EfenceEvent::Udp4Ingress(event));
                    }
                    Err(e) => warn!("failed to parse UDP4 event: {e}"),
                }
            }
            guard.clear_ready();
        }
    });
}

fn spawn_tcp4_task(
    ring_buf: RingBuf<impl Borrow<MapData> + Send + 'static>,
    tx: tokio::sync::mpsc::UnboundedSender<EfenceEvent>,
) {
    let mut events =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, Interest::READABLE)
            .expect("Failed to create AsyncFd for TCP4 ring buffer");
    tokio::task::spawn(async move {
        loop {
            let mut guard = events.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                match Tcp4EventRaw::parse(&item) {
                    Ok(raw) => {
                        let event = Tcp4Event::from(raw);
                        let _ = tx.send(EfenceEvent::Tcp4Ingress(event));
                    }
                    Err(e) => warn!("failed to parse TCP4 event: {e}"),
                }
            }
            guard.clear_ready();
        }
    });
}

fn spawn_event_printer(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<EfenceEvent>,
) {
    tokio::task::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let Ok(s) = serde_yaml::to_string(&[ev]) {
                print!("{s}");
            }
        }
    });
}

fn attach_xdp_program(
    ebpf: &mut aya::Ebpf,
    iface: &str,
) -> Result<(), EfenceError> {
    let program: &mut Xdp = ebpf
        .program_mut("efence_net_ingress_monitor")
        .ok_or_else(|| {
            EfenceError::from("efence_net_ingress_monitor program not found")
        })?
        .try_into()?;
    program.load()?;
    program.attach(iface, XdpMode::default())?;
    Ok(())
}
