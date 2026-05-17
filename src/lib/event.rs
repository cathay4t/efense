// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::LazyLock,
    time::{Duration, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{Tcp4Event, Udp4Event};

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

pub(crate) fn serialize_timestamp<S: serde::Serializer>(
    mono_ns: &u64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let wall = UNIX_EPOCH + *BOOT_TO_REALTIME + Duration::from_nanos(*mono_ns);
    let dur = wall.duration_since(UNIX_EPOCH).unwrap();
    let dt = chrono::DateTime::from_timestamp(
        dur.as_secs() as i64,
        dur.subsec_nanos(),
    )
    .unwrap()
    .with_timezone(&chrono::Local);
    serializer.collect_str(&dt.format("%Y-%m-%dT%H:%M:%S%:z"))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EfenceEvent {
    #[serde(rename = "udp4_ingress")]
    Udp4Ingress(Udp4Event),
    #[serde(rename = "tcp4_ingress")]
    Tcp4Ingress(Tcp4Event),
}
