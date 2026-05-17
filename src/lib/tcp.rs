// SPDX-License-Identifier: Apache-2.0

use std::{
    net::Ipv4Addr,
    time::{Duration, UNIX_EPOCH},
};

use efence_core::Tcp4EventRaw;
use serde::{Deserialize, Serialize};

use crate::event::{BOOT_TIME, deserialize_timestamp, serialize_timestamp};

/// Represents a TCP event
///
/// To eliminate the noise, only trace TCP ACK packet during TCP handshake,
/// hence each Tcp4Event represents a established TCP connection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Tcp4Event {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    #[serde(
        serialize_with = "serialize_timestamp",
        deserialize_with = "deserialize_timestamp"
    )]
    pub timestamp: Duration,
}

impl Tcp4Event {
    pub fn new(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        timestamp: Duration,
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

impl From<Tcp4EventRaw> for Tcp4Event {
    fn from(raw: Tcp4EventRaw) -> Self {
        Self {
            src: Ipv4Addr::from(raw.src),
            dst: Ipv4Addr::from(raw.dst),
            src_port: raw.src_port,
            dst_port: raw.dst_port,
            timestamp: BOOT_TIME
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .checked_add(Duration::from_nanos(raw.timestamp))
                .unwrap_or_default(),
        }
    }
}
