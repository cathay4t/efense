// SPDX-License-Identifier: Apache-2.0

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Udp4Event {
    pub src: u32,
    pub dst: u32,
    pub port: u16,
    pub _pad: u16,
}

impl Udp4Event {
    pub fn new(src: u32, dst: u32, port: u16) -> Self {
        Self {
            src,
            dst,
            port,
            _pad: 0,
        }
    }
}

pub const UDP4_EVENTS_BATCH_SIZE: usize = 32;
