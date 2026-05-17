// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum ErrorKind {
    Io,
    Ebpf,
    Map,
    Program,
    TryFromSlice,
    Bug,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io => f.write_str("Io"),
            ErrorKind::Ebpf => f.write_str("Ebpf"),
            ErrorKind::Map => f.write_str("Map"),
            ErrorKind::Program => f.write_str("Program"),
            ErrorKind::TryFromSlice => f.write_str("TryFromSlice"),
            ErrorKind::Bug => f.write_str("Bug"),
        }
    }
}

#[derive(Debug)]
pub struct EfenceError {
    pub kind: ErrorKind,
    pub msg: String,
}

impl fmt::Display for EfenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

impl Error for EfenceError {}

impl From<io::Error> for EfenceError {
    fn from(e: io::Error) -> Self {
        EfenceError {
            kind: ErrorKind::Io,
            msg: e.to_string(),
        }
    }
}

impl From<aya::EbpfError> for EfenceError {
    fn from(e: aya::EbpfError) -> Self {
        EfenceError {
            kind: ErrorKind::Ebpf,
            msg: e.to_string(),
        }
    }
}

impl From<aya::maps::MapError> for EfenceError {
    fn from(e: aya::maps::MapError) -> Self {
        EfenceError {
            kind: ErrorKind::Map,
            msg: e.to_string(),
        }
    }
}

impl From<aya::programs::ProgramError> for EfenceError {
    fn from(e: aya::programs::ProgramError) -> Self {
        EfenceError {
            kind: ErrorKind::Program,
            msg: e.to_string(),
        }
    }
}

impl From<std::array::TryFromSliceError> for EfenceError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        EfenceError {
            kind: ErrorKind::TryFromSlice,
            msg: e.to_string(),
        }
    }
}

impl From<String> for EfenceError {
    fn from(e: String) -> Self {
        EfenceError {
            kind: ErrorKind::Bug,
            msg: e,
        }
    }
}

impl From<&str> for EfenceError {
    fn from(e: &str) -> Self {
        EfenceError {
            kind: ErrorKind::Bug,
            msg: e.to_string(),
        }
    }
}
