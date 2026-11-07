//! Interfaces (`struct ifinfomsg`, 16 bytes) and their addresses
//! (`struct ifaddrmsg`, 8 bytes). Read only: herald never changes them.

use std::{fmt, net::IpAddr};

use super::{
    AF_UNSPEC, Batch, DecodeError, RTM_GETADDR, RTM_GETLINK,
    attr::{attrs, u32_at, value_addr, value_str, value_u32},
};

const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;

const IFLA_IFNAME: u16 = 3;
const IFLA_OPERSTATE: u16 = 16;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_FLAGS: u16 = 8;

pub const IFF_UP: u32 = 1 << 0;
pub const IFF_LOOPBACK: u32 = 1 << 3;
pub const IFF_RUNNING: u32 = 1 << 6;
pub const IFF_LOWER_UP: u32 = 1 << 16;

/// Address flags (IFA_F_*).
pub const IFA_F_DADFAILED: u32 = 0x08;
pub const IFA_F_TENTATIVE: u32 = 0x40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    /// IFF_* flags.
    pub flags: u32,
    /// RFC 2863 operational state (IF_OPER_UP = 6).
    pub operstate: Option<u8>,
}

impl Link {
    /// Administratively up and with carrier: usable for forwarding.
    pub fn is_running(&self) -> bool {
        self.flags & IFF_UP != 0 && self.flags & IFF_LOWER_UP != 0
    }

    pub(crate) fn decode(kind: u16, body: &[u8]) -> Result<Self, DecodeError> {
        if body.len() < IFINFOMSG_LEN {
            return Err(DecodeError::Short(kind));
        }
        let bad = |attr| DecodeError::Attribute { kind, attr };
        let mut link = Link {
            index: u32_at(body, 4),
            name: String::new(),
            flags: u32_at(body, 8),
            operstate: None,
        };
        for attr in attrs(&body[IFINFOMSG_LEN..]) {
            let (attr, value) = attr.map_err(|b| bad(b.0))?;
            match attr {
                IFLA_IFNAME => link.name = value_str(value),
                IFLA_OPERSTATE => link.operstate = Some(*value.first().ok_or(bad(attr))?),
                _ => {}
            }
        }
        Ok(link)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Interface index.
    pub index: u32,
    pub addr: IpAddr,
    pub prefix_len: u8,
    pub scope: u8,
    /// IFA_F_* (IFA_FLAGS when present, it extends the 8-bit field).
    pub flags: u32,
    pub label: Option<String>,
}

impl Address {
    pub(crate) fn decode(kind: u16, body: &[u8]) -> Result<Self, DecodeError> {
        if body.len() < IFADDRMSG_LEN {
            return Err(DecodeError::Short(kind));
        }
        let family = body[0];
        let bad = |attr| DecodeError::Attribute { kind, attr };
        let (mut address, mut local) = (None, None);
        let mut flags = u32::from(body[2]);
        let mut label = None;
        for attr in attrs(&body[IFADDRMSG_LEN..]) {
            let (attr, value) = attr.map_err(|b| bad(b.0))?;
            match attr {
                IFA_ADDRESS => address = Some(value_addr(family, value).ok_or(bad(attr))?),
                IFA_LOCAL => local = Some(value_addr(family, value).ok_or(bad(attr))?),
                IFA_FLAGS => flags = value_u32(value).ok_or(bad(attr))?,
                IFA_LABEL => label = Some(value_str(value)),
                _ => {}
            }
        }
        // On point-to-point links IFA_ADDRESS is the far end; ours is IFA_LOCAL.
        let addr = local.or(address).ok_or(DecodeError::Missing {
            kind,
            attr: IFA_ADDRESS,
        })?;
        Ok(Address {
            index: u32_at(body, 4),
            addr,
            prefix_len: body[1],
            scope: body[3],
            flags,
            label,
        })
    }
}

impl Batch {
    /// All interfaces.
    pub fn dump_links(&mut self) -> u32 {
        let seq = self.begin(RTM_GETLINK, 0, true);
        self.put(&[AF_UNSPEC; IFINFOMSG_LEN]);
        self.end();
        seq
    }

    /// All addresses of `family` (AF_UNSPEC: both).
    pub fn dump_addresses(&mut self, family: u8) -> u32 {
        let seq = self.begin(RTM_GETADDR, 0, true);
        self.put(&[family, 0, 0, 0, 0, 0, 0, 0]);
        self.end();
        seq
    }
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = if self.is_running() {
            "up"
        } else if self.flags & IFF_UP != 0 {
            "no-carrier"
        } else {
            "down"
        };
        write!(f, "{}: {} {state}", self.index, self.name)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{} dev {}", self.addr, self.prefix_len, self.index)?;
        if self.flags & IFA_F_TENTATIVE != 0 {
            write!(f, " tentative")?;
        }
        if self.flags & IFA_F_DADFAILED != 0 {
            write!(f, " dadfailed")?;
        }
        Ok(())
    }
}
