use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use bytes::{BufMut, BytesMut};
use thiserror::Error;

use super::{Afi, DecodeError, reader::Reader};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrefixError {
    #[error("prefix length {0} out of range")]
    Length(u8),
    #[error("missing '/' in prefix")]
    MissingSlash,
    #[error("invalid address")]
    Address,
    #[error("invalid prefix length")]
    ParseLength,
    #[error("host bits set, did you mean {0}?")]
    HostBitsSet(String),
}

fn split_prefix(s: &str) -> Result<(&str, u8), PrefixError> {
    let (addr, len) = s.split_once('/').ok_or(PrefixError::MissingSlash)?;
    let len = len.parse().map_err(|_| PrefixError::ParseLength)?;
    Ok((addr, len))
}

/// Octets needed to encode a prefix of `len` bits in NLRI format.
fn octet_len(len: u8) -> usize {
    usize::from(len).div_ceil(8)
}

macro_rules! prefix_type {
    ($name:ident, $addr:ty, $int:ty, $bits:literal) => {
        /// An IP prefix with host bits cleared. 17 bytes for IPv6, 5 for IPv4,
        /// so full tables stay compact.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name {
            addr: $addr,
            len: u8,
        }

        impl $name {
            pub const MAX_LEN: u8 = $bits;

            /// Builds a prefix, clearing host bits beyond `len`.
            pub fn new(addr: $addr, len: u8) -> Result<Self, PrefixError> {
                if len > Self::MAX_LEN {
                    return Err(PrefixError::Length(len));
                }
                let mask = <$int>::MAX.checked_shl(u32::from($bits - len)).unwrap_or(0);
                Ok(Self {
                    addr: <$addr>::from(<$int>::from(addr) & mask),
                    len,
                })
            }

            pub fn addr(&self) -> $addr {
                self.addr
            }

            pub fn prefix_len(&self) -> u8 {
                self.len
            }

            /// NLRI encoding (RFC 4271 §4.3): length in bits, then the minimum
            /// number of octets holding them.
            pub(crate) fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
                let len = r.u8()?;
                if len > Self::MAX_LEN {
                    return r.fail();
                }
                let mut octets = [0u8; $bits / 8];
                r.fill(&mut octets[..octet_len(len)])?;
                Self::new(<$addr>::from(octets), len).or_else(|_| r.fail())
            }

            /// Bytes this prefix takes in NLRI encoding.
            pub fn encoded_len(&self) -> usize {
                1 + octet_len(self.len)
            }

            pub(crate) fn encode(&self, buf: &mut BytesMut) {
                buf.put_u8(self.len);
                buf.put_slice(&self.addr.octets()[..octet_len(self.len)]);
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}/{}", self.addr, self.len)
            }
        }

        /// Strict: rejects set host bits, which in a config file is a typo.
        impl FromStr for $name {
            type Err = PrefixError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let (addr, len) = split_prefix(s)?;
                let addr: $addr = addr.parse().map_err(|_| PrefixError::Address)?;
                let prefix = Self::new(addr, len)?;
                if prefix.addr != addr {
                    return Err(PrefixError::HostBitsSet(prefix.to_string()));
                }
                Ok(prefix)
            }
        }
    };
}

prefix_type!(Prefix4, Ipv4Addr, u32, 32);
prefix_type!(Prefix6, Ipv6Addr, u128, 128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Prefix {
    V4(Prefix4),
    V6(Prefix6),
}

impl Prefix {
    pub fn afi(&self) -> Afi {
        match self {
            Prefix::V4(_) => Afi::IPV4,
            Prefix::V6(_) => Afi::IPV6,
        }
    }

    /// Bytes this prefix takes in NLRI encoding.
    pub fn encoded_len(&self) -> usize {
        match self {
            Prefix::V4(p) => p.encoded_len(),
            Prefix::V6(p) => p.encoded_len(),
        }
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        match self {
            Prefix::V4(p) => p.encode(buf),
            Prefix::V6(p) => p.encode(buf),
        }
    }
}

impl From<Prefix4> for Prefix {
    fn from(p: Prefix4) -> Self {
        Prefix::V4(p)
    }
}

impl From<Prefix6> for Prefix {
    fn from(p: Prefix6) -> Self {
        Prefix::V6(p)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Prefix::V4(p) => p.fmt(f),
            Prefix::V6(p) => p.fmt(f),
        }
    }
}

impl FromStr for Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(':') {
            s.parse().map(Prefix::V6)
        } else {
            s.parse().map(Prefix::V4)
        }
    }
}
