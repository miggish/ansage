//! Nexthop objects (kernel >= 5.3): `struct nhmsg` (8 bytes) + NHA_*.
//!
//! Routes point at a nexthop object by id (RTA_NH_ID). Changing the object
//! moves every route that uses it in one message.

use std::{fmt, net::IpAddr};

use super::{
    AF_UNSPEC, Batch, DecodeError, NLM_F_CREATE, NLM_F_REPLACE, RTM_DELNEXTHOP, RTM_GETNEXTHOP,
    RTM_NEWNEXTHOP, RTNH_F_DEAD, RTNH_F_LINKDOWN, RTNH_F_ONLINK,
    attr::{attrs, family_of, u32_at, value_addr, value_u32},
    protocol_name,
};

const NHMSG_LEN: usize = 8;

const NHA_ID: u16 = 1;
const NHA_GROUP: u16 = 2;
const NHA_BLACKHOLE: u16 = 4;
const NHA_OIF: u16 = 5;
const NHA_GATEWAY: u16 = 6;

/// `struct nexthop_grp`: id u32, weight u8, weight_high u8, reserved u16.
const GROUP_ENTRY_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nexthop {
    pub id: u32,
    /// AF_INET / AF_INET6 (family of the gateway), AF_UNSPEC for groups and
    /// blackholes.
    pub family: u8,
    pub protocol: u8,
    /// RTNH_F_ONLINK may be set; the kernel reports RTNH_F_DEAD / LINKDOWN.
    pub flags: u32,
    /// Device (required with a gateway).
    pub oif: Option<u32>,
    pub gateway: Option<IpAddr>,
    pub blackhole: bool,
    /// Members of a nexthop group (ECMP, later).
    pub group: Vec<GroupMember>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMember {
    pub id: u32,
    /// 1..=65536.
    pub weight: u32,
}

impl Nexthop {
    /// Via `gateway` on device `oif`.
    pub fn gateway(id: u32, gateway: IpAddr, oif: u32, protocol: u8) -> Self {
        Self {
            id,
            family: family_of(&gateway),
            protocol,
            flags: 0,
            oif: Some(oif),
            gateway: Some(gateway),
            blackhole: false,
            group: Vec::new(),
        }
    }

    /// Down: the device is down or has no carrier.
    pub fn is_dead(&self) -> bool {
        self.flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN) != 0
    }

    pub(crate) fn decode(kind: u16, body: &[u8]) -> Result<Self, DecodeError> {
        if body.len() < NHMSG_LEN {
            return Err(DecodeError::Short(kind));
        }
        let family = body[0];
        let bad = |attr| DecodeError::Attribute { kind, attr };
        let mut id = None;
        let mut nh = Nexthop {
            id: 0,
            family,
            protocol: body[2],
            flags: u32_at(body, 4),
            oif: None,
            gateway: None,
            blackhole: false,
            group: Vec::new(),
        };
        for attr in attrs(&body[NHMSG_LEN..]) {
            let (attr, value) = attr.map_err(|b| bad(b.0))?;
            match attr {
                NHA_ID => id = Some(value_u32(value).ok_or(bad(attr))?),
                NHA_OIF => nh.oif = Some(value_u32(value).ok_or(bad(attr))?),
                NHA_GATEWAY => nh.gateway = Some(value_addr(family, value).ok_or(bad(attr))?),
                NHA_BLACKHOLE => nh.blackhole = true,
                NHA_GROUP => {
                    if value.len() % GROUP_ENTRY_LEN != 0 {
                        return Err(bad(attr));
                    }
                    nh.group = value
                        .as_chunks::<GROUP_ENTRY_LEN>()
                        .0
                        .iter()
                        .map(|e| GroupMember {
                            id: u32_at(e, 0),
                            weight: (u32::from(e[5]) << 8 | u32::from(e[4])) + 1,
                        })
                        .collect();
                }
                _ => {}
            }
        }
        nh.id = id.ok_or(DecodeError::Missing { kind, attr: NHA_ID })?;
        Ok(nh)
    }

    fn encode(&self, batch: &mut Batch) {
        // nh_scope and resvd must be 0 in requests.
        batch.put(&[self.family, 0, self.protocol, 0]);
        batch.put(&self.flags.to_ne_bytes());
        batch.attr_u32(NHA_ID, self.id);
        if let Some(oif) = self.oif {
            batch.attr_u32(NHA_OIF, oif);
        }
        if let Some(gateway) = &self.gateway {
            batch.attr_addr(NHA_GATEWAY, gateway);
        }
        if self.blackhole {
            batch.attr(NHA_BLACKHOLE, &[]);
        }
        if !self.group.is_empty() {
            let mut value = Vec::with_capacity(self.group.len() * GROUP_ENTRY_LEN);
            for m in &self.group {
                let w = m.weight.clamp(1, 65536) - 1;
                value.extend_from_slice(&m.id.to_ne_bytes());
                value.extend_from_slice(&[w as u8, (w >> 8) as u8, 0, 0]);
            }
            batch.attr(NHA_GROUP, &value);
        }
    }
}

impl Batch {
    /// Creates nexthop `nh.id`, or replaces it (every route using it follows).
    pub fn add_nexthop(&mut self, nh: &Nexthop) -> u32 {
        let seq = self.begin(RTM_NEWNEXTHOP, NLM_F_CREATE | NLM_F_REPLACE, false);
        nh.encode(self);
        self.end();
        seq
    }

    /// Deletes nexthop `id`; the kernel also deletes the routes using it.
    pub fn delete_nexthop(&mut self, id: u32) -> u32 {
        let seq = self.begin(RTM_DELNEXTHOP, 0, false);
        self.put(&[AF_UNSPEC, 0, 0, 0]);
        self.put(&0u32.to_ne_bytes());
        self.attr_u32(NHA_ID, id);
        self.end();
        seq
    }

    /// Nexthop object `id` (an RTM_NEWNEXTHOP reply, then the ACK; ENOENT
    /// when there is none).
    pub fn get_nexthop(&mut self, id: u32) -> u32 {
        let seq = self.begin(RTM_GETNEXTHOP, 0, false);
        self.put(&[AF_UNSPEC, 0, 0, 0]);
        self.put(&0u32.to_ne_bytes());
        self.attr_u32(NHA_ID, id);
        self.end();
        seq
    }

    /// All nexthop objects.
    pub fn dump_nexthops(&mut self) -> u32 {
        let seq = self.begin(RTM_GETNEXTHOP, 0, true);
        self.put(&[AF_UNSPEC, 0, 0, 0]);
        self.put(&0u32.to_ne_bytes());
        self.end();
        seq
    }
}

/// Like `ip nexthop`: `id 7 via 10.0.0.2 dev 3 proto bgp`.
impl fmt::Display for Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id {}", self.id)?;
        if !self.group.is_empty() {
            write!(f, " group ")?;
            for (i, m) in self.group.iter().enumerate() {
                let sep = if i > 0 { "/" } else { "" };
                write!(f, "{sep}{}", m.id)?;
                if m.weight != 1 {
                    write!(f, ",{}", m.weight)?;
                }
            }
        }
        if let Some(gw) = &self.gateway {
            write!(f, " via {gw}")?;
        }
        if let Some(oif) = self.oif {
            write!(f, " oif {oif}")?;
        }
        if self.blackhole {
            write!(f, " blackhole")?;
        }
        if self.flags & RTNH_F_ONLINK != 0 {
            write!(f, " onlink")?;
        }
        if self.flags & RTNH_F_DEAD != 0 {
            write!(f, " dead")?;
        }
        if self.flags & RTNH_F_LINKDOWN != 0 {
            write!(f, " linkdown")?;
        }
        match protocol_name(self.protocol) {
            Some(name) => write!(f, " proto {name}"),
            None => write!(f, " proto {}", self.protocol),
        }
    }
}
