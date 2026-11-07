//! Next hop resolution: which kernel route (and interface) reaches a BGP next
//! hop.

use std::net::{IpAddr, Ipv6Addr};

use herald_netlink::RTN_UNICAST;

use herald_netlink::RTPROT_BGP;

use herald_netlink::Route;

use herald_bgp::wire::Prefix;
use tracing::{debug, warn};

use super::{
    Fib, NEXTHOP_IDS,
    entry::{Gateway, Via, is_link_local},
    kernel::Kernel,
};

/// What the kernel's routing entry for a BGP next hop says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Reachable through this gateway and interface.
    Via(Via),
    /// Through another daemon's nexthop object: look at that.
    Nexthop(u32),
    /// One of herald's own routes covers it. The kernel cannot be asked
    /// for the next best entry, so the previous resolution stays; without
    /// one the next hop is unreachable. (Not resolving through our own
    /// routes, like other BGP daemons; keeping the old answer avoids a
    /// flap when a learned prefix covers its own next hop.)
    Ours,
    Unusable(&'static str),
}

/// RFC 4271 §9.1.2.1, the kernel's way: `route` is its FIB entry for `addr`.
pub fn resolution(route: &Route, addr: IpAddr, via_default: bool) -> Resolution {
    if route.nh_id.is_some_and(|id| NEXTHOP_IDS.contains(&id)) {
        return Resolution::Ours;
    }
    if route.protocol == RTPROT_BGP {
        return Resolution::Unusable("route learned by BGP");
    }
    if route.kind != RTN_UNICAST {
        return Resolution::Unusable("not a unicast route");
    }
    let default = match route.dst {
        Prefix::V4(p) => p.prefix_len() == 0,
        Prefix::V6(p) => p.prefix_len() == 0,
    };
    if default && !via_default {
        return Resolution::Unusable("only the default route (resolve_via_default is off)");
    }
    if let Some(id) = route.nh_id {
        return Resolution::Nexthop(id);
    }
    match route.oif {
        Some(oif) => Resolution::Via(Via {
            gateway: route.gateway.unwrap_or(addr),
            oif,
        }),
        // An ECMP route: the first leg that is up (the kernel hashes flows
        // over all of them; one is enough to reach the next hop).
        None => match route.multipath.iter().find(|leg| !leg.is_dead()) {
            Some(leg) => Resolution::Via(Via {
                gateway: leg.gateway.unwrap_or(addr),
                oif: leg.oif,
            }),
            None if route.multipath.is_empty() => Resolution::Unusable("no interface"),
            None => Resolution::Unusable("every ECMP leg is down"),
        },
    }
}

impl<K: Kernel> Fib<K> {
    /// Where the kernel would send packets for `gw`: its address, else its
    /// link-local fallback.
    pub(super) fn resolve(&mut self, gw: Gateway, previous: Option<Via>) -> Option<Via> {
        // A link-local address only means something with its interface.
        if !is_link_local(gw.addr)
            && let Some(via) = self.resolve_addr(gw.addr, previous)
        {
            return Some(via);
        }
        let (ll, oif) = gw.link?;
        self.resolve_link(ll, oif)
    }

    /// A link-local next hop is reachable while the kernel has a route for
    /// it out of its interface (the interface's fe80::/64 route).
    fn resolve_link(&mut self, ll: Ipv6Addr, oif: u32) -> Option<Via> {
        let addr = IpAddr::V6(ll);
        let route = match self.kernel.lookup(addr, Some(oif)) {
            Ok(route) => route?,
            Err(err) => {
                warn!(%addr, oif, %err, "cannot look up the link-local next hop");
                return None;
            }
        };
        match resolution(&route, addr, false) {
            Resolution::Via(via) if via == (Via { gateway: addr, oif }) => Some(via),
            _ => {
                debug!(%addr, oif, %route, "link-local next hop not on its interface");
                None
            }
        }
    }

    /// Where the kernel would send packets for `addr`; `previous` is kept
    /// when that cannot be told (see [`Resolution::Ours`]).
    fn resolve_addr(&mut self, addr: IpAddr, previous: Option<Via>) -> Option<Via> {
        let route = match self.kernel.lookup(addr, None) {
            Ok(Some(route)) => route,
            Ok(None) => {
                debug!(%addr, "no route to the next hop");
                return None;
            }
            Err(err) => {
                warn!(%addr, %err, "cannot look up the next hop");
                return previous;
            }
        };
        match resolution(&route, addr, self.settings.resolve_via_default) {
            Resolution::Via(via) => Some(via),
            Resolution::Nexthop(id) => self.resolve_object(id, addr),
            Resolution::Ours => {
                debug!(%addr, %route, "next hop covered by one of our routes, keeping its resolution");
                previous
            }
            Resolution::Unusable(why) => {
                debug!(%addr, %route, why, "next hop not reachable");
                None
            }
        }
    }

    /// Resolution through another daemon's nexthop object (a group: its
    /// first member that is up).
    fn resolve_object(&mut self, id: u32, addr: IpAddr) -> Option<Via> {
        let mut nh = self.kernel.nexthop(id).ok().flatten()?;
        if !nh.group.is_empty() {
            let members: Vec<u32> = nh.group.iter().map(|m| m.id).collect();
            nh = members
                .into_iter()
                .filter_map(|id| self.kernel.nexthop(id).ok().flatten())
                .find(|m| !m.blackhole && !m.is_dead())?;
        }
        if nh.blackhole || nh.is_dead() {
            return None;
        }
        Some(Via {
            gateway: nh.gateway.unwrap_or(addr),
            oif: nh.oif?,
        })
    }
}
