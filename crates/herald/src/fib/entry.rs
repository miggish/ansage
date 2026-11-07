//! What the FIB keeps per prefix and per next hop.

use std::net::{IpAddr, Ipv6Addr};

use herald_netlink::Nexthop;

use herald_netlink::RTPROT_BGP;

use super::{NEXTHOP_IDS, status::RouteState};

/// A prefix's nexthop id and state in one u32 (a full table has ~1.35M of
/// them): bits 0-23 the id's offset in [`NEXTHOP_IDS`], 24-25 the state,
/// 31 set when there is a hop.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Entry(u32);

impl Entry {
    const HAS_HOP: u32 = 1 << 31;
    const ID_MASK: u32 = 0x00FF_FFFF;

    /// `hop` None: the RIB wants the prefix gone, but deleting it failed.
    pub(super) fn new(hop: Option<u32>, state: RouteState) -> Self {
        let state = match state {
            RouteState::Installed => 0,
            RouteState::Failed => 1,
            RouteState::Unresolved => 2,
            RouteState::Shadowed => 3,
        } << 24;
        Self(match hop {
            Some(id) => {
                debug_assert!(NEXTHOP_IDS.contains(&id), "{id:#x}");
                Self::HAS_HOP | ((id - NEXTHOP_IDS.start()) & Self::ID_MASK) | state
            }
            None => state,
        })
    }

    pub(super) fn hop(self) -> Option<u32> {
        (self.0 & Self::HAS_HOP != 0).then(|| NEXTHOP_IDS.start() + (self.0 & Self::ID_MASK))
    }

    pub(super) fn state(self) -> RouteState {
        match (self.0 >> 24) & 3 {
            0 => RouteState::Installed,
            1 => RouteState::Failed,
            2 => RouteState::Unresolved,
            _ => RouteState::Shadowed,
        }
    }

    pub(super) fn with_state(self, state: RouteState) -> Self {
        Self::new(self.hop(), state)
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("hop", &self.hop())
            .field("state", &self.state())
            .finish()
    }
}

/// Where the kernel sends packets for a BGP next hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Via {
    /// The BGP next hop itself when it is directly connected, else the
    /// gateway of the kernel route that reaches it.
    pub gateway: IpAddr,
    pub oif: u32,
}

#[derive(Debug)]
pub(super) struct Hop {
    pub(super) gw: Gateway,
    /// None: not reachable.
    pub(super) via: Option<Via>,
    /// The kernel has (or was just asked to create) the nexthop object.
    pub(super) installed: bool,
    /// Prefixes that want this next hop.
    pub(super) refs: u32,
    /// The RIB was told it is unreachable: kept (even without users) until
    /// it can be told that it is back.
    pub(super) reported: bool,
}

impl Hop {
    pub(super) fn usable(&self) -> bool {
        self.via.is_some() && self.installed
    }

    pub(super) fn nexthop(&self, id: u32) -> Option<Nexthop> {
        let via = self.via?;
        Some(Nexthop::gateway(id, via.gateway, via.oif, RTPROT_BGP))
    }
}

/// What the RIB wants a prefix forwarded to: a BGP next hop and, when the
/// neighbor shares a link with us and sent one (RFC 2545), its link-local
/// next hop on the session's interface. The link-local one is used when
/// the address is itself link-local (the neighbor sent only that) or does
/// not resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Gateway {
    pub addr: IpAddr,
    pub link: Option<(Ipv6Addr, u32)>,
}

impl Gateway {
    /// The gateway for BGP next hop `addr` with the neighbor's link-local
    /// next hop `link_local`, on a session over interface `oif` (None: the
    /// neighbor is not on a shared link).
    pub fn new(addr: IpAddr, link_local: Option<Ipv6Addr>, oif: Option<u32>) -> Self {
        let link_local = match addr {
            IpAddr::V6(a) if a.is_unicast_link_local() => Some(a),
            IpAddr::V6(_) => link_local,
            // Not for IPv4 routes (that would be RFC 8950 forwarding).
            IpAddr::V4(_) => None,
        };
        Self {
            addr,
            link: oif.zip(link_local).map(|(oif, ll)| (ll, oif)),
        }
    }
}

impl From<IpAddr> for Gateway {
    fn from(addr: IpAddr) -> Self {
        Self { addr, link: None }
    }
}

impl std::fmt::Display for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.link {
            Some((ll, oif)) if IpAddr::V6(ll) == self.addr => write!(f, "{ll}%{oif}"),
            Some((ll, oif)) => write!(f, "{} (or {ll}%{oif})", self.addr),
            None => write!(f, "{}", self.addr),
        }
    }
}

pub(super) fn is_link_local(addr: IpAddr) -> bool {
    matches!(addr, IpAddr::V6(a) if a.is_unicast_link_local())
}
