//! Routes: `struct rtmsg` (12 bytes) + RTA_* attributes.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use super::{
    AF_INET, AF_INET6, Batch, DecodeError, NLM_F_CREATE, NLM_F_REPLACE, RT_SCOPE_HOST,
    RT_SCOPE_LINK, RT_SCOPE_UNIVERSE, RT_TABLE_LOCAL, RT_TABLE_MAIN, RT_TABLE_UNSPEC, RTM_DELROUTE,
    RTM_F_FIB_MATCH, RTM_GETROUTE, RTM_NEWROUTE, RTN_ANYCAST, RTN_BLACKHOLE, RTN_BROADCAST,
    RTN_LOCAL, RTN_MULTICAST, RTN_PROHIBIT, RTN_UNICAST, RTN_UNREACHABLE, RTNH_F_DEAD,
    RTNH_F_LINKDOWN,
    attr::{align, attrs, family_of, u16_at, u32_at, value_addr, value_u32},
    protocol_name,
};
use ansage_bgp::wire::{Prefix, Prefix4, Prefix6};

const RTMSG_LEN: usize = 12;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;
const RTA_NH_ID: u16 = 30;

/// A route as the kernel stores it (the fields ansage reads or sets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub dst: Prefix,
    pub table: u32,
    pub protocol: u8,
    pub scope: u8,
    /// `rtm_type`: RTN_UNICAST, RTN_LOCAL, RTN_BLACKHOLE, ...
    pub kind: u8,
    /// `rtm_flags`: RTNH_F_* in the low byte, RTM_F_* above.
    pub flags: u32,
    /// Metric (RTA_PRIORITY); lower wins.
    pub priority: Option<u32>,
    /// RTA_GATEWAY, or RTA_VIA when its family differs from `dst`'s.
    pub gateway: Option<IpAddr>,
    pub oif: Option<u32>,
    /// Nexthop object the route uses (RTA_NH_ID).
    pub nh_id: Option<u32>,
    pub prefsrc: Option<IpAddr>,
    /// The legs of an ECMP route (RTA_MULTIPATH); empty for a single next hop.
    pub multipath: Vec<RouteHop>,
}

/// One leg of an ECMP route: `struct rtnexthop` (8 bytes) + its attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHop {
    /// `rtnh_flags`: RTNH_F_DEAD, RTNH_F_LINKDOWN, ...
    pub flags: u8,
    /// `rtnh_hops` + 1.
    pub weight: u16,
    pub oif: u32,
    /// RTA_GATEWAY, or RTA_VIA when its family differs from the route's.
    pub gateway: Option<IpAddr>,
}

impl RouteHop {
    /// Down: the device is down or has no carrier.
    pub fn is_dead(&self) -> bool {
        u32::from(self.flags) & (RTNH_F_DEAD | RTNH_F_LINKDOWN) != 0
    }
}

impl Route {
    /// A unicast route through nexthop object `nh_id`: what ansage installs.
    pub fn via_nexthop(dst: Prefix, nh_id: u32, table: u32, protocol: u8, priority: u32) -> Self {
        Self {
            dst,
            table,
            protocol,
            scope: RT_SCOPE_UNIVERSE,
            kind: RTN_UNICAST,
            flags: 0,
            priority: Some(priority),
            gateway: None,
            oif: None,
            nh_id: Some(nh_id),
            prefsrc: None,
            multipath: Vec::new(),
        }
    }

    pub(crate) fn decode(kind: u16, body: &[u8]) -> Result<Self, DecodeError> {
        if body.len() < RTMSG_LEN {
            return Err(DecodeError::Short(kind));
        }
        let family = body[0];
        let dst_len = body[1];
        let bad = |attr| DecodeError::Attribute { kind, attr };
        let mut dst = None;
        let mut route = Route {
            dst: unspecified(family, 0)?,
            table: u32::from(body[4]),
            protocol: body[5],
            scope: body[6],
            kind: body[7],
            flags: u32_at(body, 8),
            priority: None,
            gateway: None,
            oif: None,
            nh_id: None,
            prefsrc: None,
            multipath: Vec::new(),
        };
        for attr in attrs(&body[RTMSG_LEN..]) {
            let (attr, value) = attr.map_err(|b| bad(b.0))?;
            match attr {
                RTA_DST => dst = Some(value_addr(family, value).ok_or(bad(attr))?),
                RTA_TABLE => route.table = value_u32(value).ok_or(bad(attr))?,
                RTA_PRIORITY => route.priority = Some(value_u32(value).ok_or(bad(attr))?),
                RTA_GATEWAY => route.gateway = Some(value_addr(family, value).ok_or(bad(attr))?),
                RTA_VIA => route.gateway = Some(decode_via(value).ok_or(bad(attr))?),
                RTA_OIF => route.oif = Some(value_u32(value).ok_or(bad(attr))?),
                RTA_NH_ID => route.nh_id = Some(value_u32(value).ok_or(bad(attr))?),
                RTA_PREFSRC => route.prefsrc = Some(value_addr(family, value).ok_or(bad(attr))?),
                RTA_MULTIPATH => {
                    route.multipath = decode_multipath(family, value).ok_or(bad(attr))?
                }
                _ => {}
            }
        }
        route.dst = match dst {
            Some(addr) => prefix(addr, dst_len)?,
            // The default route has no RTA_DST.
            None => unspecified(family, dst_len)?,
        };
        Ok(route)
    }

    /// Writes `rtmsg` and the attributes.
    fn encode(&self, batch: &mut Batch) {
        let (family, dst_len, dst) = match self.dst {
            Prefix::V4(p) => (AF_INET, p.prefix_len(), IpAddr::V4(p.addr())),
            Prefix::V6(p) => (AF_INET6, p.prefix_len(), IpAddr::V6(p.addr())),
        };
        // Tables above 255 only fit in RTA_TABLE (iproute2 does the same).
        let table = u8::try_from(self.table).unwrap_or(RT_TABLE_UNSPEC as u8);
        batch.put(&[
            family,
            dst_len,
            0, // src_len
            0, // tos
            table,
            self.protocol,
            self.scope,
            self.kind,
        ]);
        batch.put(&self.flags.to_ne_bytes());
        if dst_len > 0 {
            batch.attr_addr(RTA_DST, &dst);
        }
        batch.attr_u32(RTA_TABLE, self.table);
        if let Some(priority) = self.priority {
            batch.attr_u32(RTA_PRIORITY, priority);
        }
        if let Some(gateway) = &self.gateway {
            if family_of(gateway) == family {
                batch.attr_addr(RTA_GATEWAY, gateway);
            } else {
                batch.attr(RTA_VIA, &encode_via(gateway));
            }
        }
        if let Some(oif) = self.oif {
            batch.attr_u32(RTA_OIF, oif);
        }
        if let Some(nh_id) = self.nh_id {
            batch.attr_u32(RTA_NH_ID, nh_id);
        }
        if let Some(prefsrc) = &self.prefsrc {
            batch.attr_addr(RTA_PREFSRC, prefsrc);
        }
        if !self.multipath.is_empty() {
            batch.attr(RTA_MULTIPATH, &encode_multipath(family, &self.multipath));
        }
    }
}

impl Batch {
    /// Adds `route`, replacing one with the same destination, table and metric.
    pub fn add_route(&mut self, route: &Route) -> u32 {
        let seq = self.begin(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, false);
        route.encode(self);
        self.end();
        seq
    }

    /// Deletes `route`. The kernel matches on destination, table, protocol and
    /// metric; the fields that are `None` match anything.
    pub fn delete_route(&mut self, route: &Route) -> u32 {
        let seq = self.begin(RTM_DELROUTE, 0, false);
        route.encode(self);
        self.end();
        seq
    }

    /// Asks which routing entry the kernel uses for `addr` (policy routing
    /// included). The answer is one RTM_NEWROUTE with the matching FIB entry
    /// (its prefix, protocol, next hop), then the ACK.
    pub fn lookup_route(&mut self, addr: IpAddr) -> u32 {
        self.lookup_route_on(addr, None)
    }

    /// Like [`Batch::lookup_route`], for packets leaving through interface
    /// `oif` (`ip route get ADDR oif DEV fibmatch`): how a link-local
    /// address is looked up.
    pub fn lookup_route_on(&mut self, addr: IpAddr, oif: Option<u32>) -> u32 {
        let seq = self.begin(RTM_GETROUTE, 0, false);
        let (family, len) = match addr {
            IpAddr::V4(_) => (AF_INET, 32),
            IpAddr::V6(_) => (AF_INET6, 128),
        };
        batch_rtmsg(self, family, len, 0, 0, RTM_F_FIB_MATCH);
        self.attr_addr(RTA_DST, &addr);
        if let Some(oif) = oif {
            self.attr_u32(RTA_OIF, oif);
        }
        self.end();
        seq
    }

    /// All routes of `family` (AF_UNSPEC: both). With strict checking (the
    /// socket enables it) the kernel only returns routes of `table` and
    /// `protocol` when those are not 0.
    pub fn dump_routes(&mut self, family: u8, table: u32, protocol: u8) -> u32 {
        let seq = self.begin(RTM_GETROUTE, 0, true);
        let small = u8::try_from(table).unwrap_or(RT_TABLE_UNSPEC as u8);
        batch_rtmsg(self, family, 0, small, protocol, 0);
        if table != RT_TABLE_UNSPEC {
            self.attr_u32(RTA_TABLE, table);
        }
        self.end();
        seq
    }
}

fn batch_rtmsg(batch: &mut Batch, family: u8, dst_len: u8, table: u8, protocol: u8, flags: u32) {
    batch.put(&[family, dst_len, 0, 0, table, protocol, 0, 0]);
    batch.put(&flags.to_ne_bytes());
}

fn prefix(addr: IpAddr, len: u8) -> Result<Prefix, DecodeError> {
    let bad = DecodeError::PrefixLength(len);
    Ok(match addr {
        IpAddr::V4(a) => Prefix::V4(Prefix4::new(a, len).map_err(|_| bad)?),
        IpAddr::V6(a) => Prefix::V6(Prefix6::new(a, len).map_err(|_| bad)?),
    })
}

fn unspecified(family: u8, len: u8) -> Result<Prefix, DecodeError> {
    match family {
        AF_INET => prefix(IpAddr::V4(Ipv4Addr::UNSPECIFIED), len),
        AF_INET6 => prefix(IpAddr::V6(Ipv6Addr::UNSPECIFIED), len),
        other => Err(DecodeError::Family(other)),
    }
}

/// `struct rtvia`: u16 family (host order), then the address.
fn decode_via(value: &[u8]) -> Option<IpAddr> {
    if value.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([value[0], value[1]]);
    value_addr(u8::try_from(family).ok()?, &value[2..])
}

/// RTA_MULTIPATH: `struct rtnexthop` entries (u16 length, u8 flags, u8 hops,
/// i32 ifindex), each followed by its attributes and padded to 4 bytes.
fn decode_multipath(family: u8, mut value: &[u8]) -> Option<Vec<RouteHop>> {
    const RTNH_LEN: usize = 8;
    let mut legs = Vec::new();
    while !value.is_empty() {
        if value.len() < RTNH_LEN {
            return None;
        }
        let len = usize::from(u16_at(value, 0));
        if len < RTNH_LEN || len > value.len() {
            return None;
        }
        let mut leg = RouteHop {
            flags: value[2],
            weight: u16::from(value[3]) + 1,
            oif: u32_at(value, 4),
            gateway: None,
        };
        for attr in attrs(&value[RTNH_LEN..len]) {
            let (attr, v) = attr.ok()?;
            match attr {
                RTA_GATEWAY => leg.gateway = Some(value_addr(family, v)?),
                RTA_VIA => leg.gateway = Some(decode_via(v)?),
                _ => {}
            }
        }
        legs.push(leg);
        value = &value[align(len).min(value.len())..];
    }
    Some(legs)
}

fn encode_multipath(family: u8, legs: &[RouteHop]) -> Vec<u8> {
    let mut out = Vec::new();
    for leg in legs {
        let start = out.len();
        out.extend_from_slice(&[
            0,
            0,
            leg.flags,
            u8::try_from(leg.weight.saturating_sub(1)).unwrap_or(u8::MAX),
        ]);
        out.extend_from_slice(&leg.oif.to_ne_bytes());
        if let Some(gateway) = &leg.gateway {
            let (kind, v) = if family_of(gateway) == family {
                (
                    RTA_GATEWAY,
                    match gateway {
                        IpAddr::V4(a) => a.octets().to_vec(),
                        IpAddr::V6(a) => a.octets().to_vec(),
                    },
                )
            } else {
                (RTA_VIA, encode_via(gateway))
            };
            out.extend_from_slice(&u16::try_from(4 + v.len()).expect("short").to_ne_bytes());
            out.extend_from_slice(&kind.to_ne_bytes());
            out.extend_from_slice(&v);
            out.resize(align(out.len()), 0);
        }
        let len = u16::try_from(out.len() - start).expect("leg below 64 KiB");
        out[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }
    out
}

fn encode_via(addr: &IpAddr) -> Vec<u8> {
    let mut v = u16::from(family_of(addr)).to_ne_bytes().to_vec();
    match addr {
        IpAddr::V4(a) => v.extend_from_slice(&a.octets()),
        IpAddr::V6(a) => v.extend_from_slice(&a.octets()),
    }
    v
}

/// Like `ip route`: `198.51.100.0/24 nhid 7 proto bgp metric 20`.
impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match type_name(self.kind) {
            Some("unicast") => {}
            Some(name) => write!(f, "{name} ")?,
            None => write!(f, "type {} ", self.kind)?,
        }
        write!(f, "{}", self.dst)?;
        if let Some(id) = self.nh_id {
            write!(f, " nhid {id}")?;
        }
        if let Some(gw) = &self.gateway {
            write!(f, " via {gw}")?;
        }
        if let Some(oif) = self.oif {
            write!(f, " oif {oif}")?;
        }
        for leg in &self.multipath {
            write!(f, " nexthop")?;
            if let Some(gw) = &leg.gateway {
                write!(f, " via {gw}")?;
            }
            write!(f, " oif {} weight {}", leg.oif, leg.weight)?;
            if leg.is_dead() {
                write!(f, " dead")?;
            }
        }
        match protocol_name(self.protocol) {
            Some(name) => write!(f, " proto {name}")?,
            None => write!(f, " proto {}", self.protocol)?,
        }
        match self.scope {
            RT_SCOPE_UNIVERSE => {}
            RT_SCOPE_LINK => write!(f, " scope link")?,
            RT_SCOPE_HOST => write!(f, " scope host")?,
            other => write!(f, " scope {other}")?,
        }
        if let Some(src) = &self.prefsrc {
            write!(f, " src {src}")?;
        }
        if let Some(metric) = self.priority {
            write!(f, " metric {metric}")?;
        }
        match self.table {
            RT_TABLE_MAIN => {}
            RT_TABLE_LOCAL => write!(f, " table local")?,
            other => write!(f, " table {other}")?,
        }
        Ok(())
    }
}

fn type_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        RTN_UNICAST => "unicast",
        RTN_LOCAL => "local",
        RTN_BROADCAST => "broadcast",
        RTN_ANYCAST => "anycast",
        RTN_MULTICAST => "multicast",
        RTN_BLACKHOLE => "blackhole",
        RTN_UNREACHABLE => "unreachable",
        RTN_PROHIBIT => "prohibit",
        _ => return None,
    })
}
