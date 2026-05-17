// SPDX-License-Identifier: Apache-2.0

use std::{
    net::Ipv4Addr,
    sync::LazyLock,
    time::{Duration, UNIX_EPOCH},
};

use efence_core::Udp4EventRaw;
use serde::{Deserialize, Serialize};

static BOOT_TO_REALTIME: LazyLock<Duration> = LazyLock::new(|| {
    let mut mono = std::mem::MaybeUninit::<libc::timespec>::uninit();
    let mut real = std::mem::MaybeUninit::<libc::timespec>::uninit();
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, mono.as_mut_ptr());
        libc::clock_gettime(libc::CLOCK_REALTIME, real.as_mut_ptr());
    }
    let mono = unsafe { mono.assume_init() };
    let real = unsafe { real.assume_init() };
    let mono_dur = Duration::new(mono.tv_sec as u64, mono.tv_nsec as u32);
    let real_dur = Duration::new(real.tv_sec as u64, real.tv_nsec as u32);
    real_dur - mono_dur
});

fn serialize_timestamp<S: serde::Serializer>(
    mono_ns: &u64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let wall = UNIX_EPOCH + *BOOT_TO_REALTIME + Duration::from_nanos(*mono_ns);
    let dur = wall.duration_since(UNIX_EPOCH).unwrap();
    let dt = chrono::DateTime::from_timestamp(dur.as_secs() as i64, dur.subsec_nanos())
        .unwrap()
        .with_timezone(&chrono::Local);
    serializer.collect_str(&dt.format("%Y-%m-%dT%H:%M:%S%:z"))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Udp4Event {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: u64,
}

impl Udp4Event {
    pub fn new(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        timestamp: u64,
    ) -> Self {
        Self {
            src,
            dst,
            src_port,
            dst_port,
            timestamp,
        }
    }
}

impl From<Udp4EventRaw> for Udp4Event {
    fn from(raw: Udp4EventRaw) -> Self {
        Self {
            src: Ipv4Addr::from(raw.src),
            dst: Ipv4Addr::from(raw.dst),
            src_port: raw.src_port,
            dst_port: raw.dst_port,
            timestamp: raw.timestamp,
        }
    }
}
