// SPDX-License-Identifier: Apache-2.0

#[repr(u8)]
#[derive(Debug, Clone)]
pub enum EfenceError {
    PacketTooSmall,
    InvalidProtocol,
}

impl core::fmt::Display for EfenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EfenceError::PacketTooSmall => "packet too small",
                EfenceError::InvalidProtocol => "invalid protocol",
            }
        )
    }
}
