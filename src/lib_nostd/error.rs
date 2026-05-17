// SPDX-License-Identifier: Apache-2.0

#[repr(u8)]
#[derive(Debug, Clone)]
pub enum EfenceErrorCode {
    PacketTooSmall,
    InvalidProtocol,
}

impl core::fmt::Display for EfenceErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EfenceErrorCode::PacketTooSmall => "packet too small",
                EfenceErrorCode::InvalidProtocol => "invalid protocol",
            }
        )
    }
}
