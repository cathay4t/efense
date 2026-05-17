// SPDX-License-Identifier: Apache-2.0

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Udp4Event {
    pub src: u32,
    pub dst: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub _pad: u32,
}

impl Udp4Event {
    pub fn new(src: u32, dst: u32, src_port: u16, dst_port: u16) -> Self {
        Self {
            src,
            dst,
            src_port,
            dst_port,
            _pad: 0,
        }
    }
}

// Ring buffer byte size, passed as max_entries to the kernel.
// Must be a power of 2 and page-aligned (multiple of 4096).
pub const UDP4_EVENTS_RING_BUF_SIZE: usize = 16384;
