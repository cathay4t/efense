// SPDX-License-Identifier: Apache-2.0

#![no_std]

mod error;
mod udp;

pub use self::{
    error::EfenceError,
    udp::{UDP4_EVENTS_BATCH_SIZE, Udp4Event},
};
