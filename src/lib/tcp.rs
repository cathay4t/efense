// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use efence_core::Tcp4EventRaw;
use serde::{Deserialize, Serialize};

use crate::event::serialize_timestamp;

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
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: u64,
}

impl Tcp4Event {
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

impl From<Tcp4EventRaw> for Tcp4Event {
    fn from(raw: Tcp4EventRaw) -> Self {
        Self {
            src: Ipv4Addr::from(raw.src),
            dst: Ipv4Addr::from(raw.dst),
            src_port: raw.src_port,
            dst_port: raw.dst_port,
            timestamp: raw.timestamp,
        }
    }
}
