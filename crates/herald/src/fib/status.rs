//! What `herald show fib` and the metrics report.

use std::{collections::BTreeMap, net::IpAddr};

use herald_bgp::wire::Prefix;
use serde::Serialize;

use super::{
    Fib, FibQuery,
    entry::{Entry, Gateway, Via},
    kernel::Kernel,
};

/// `herald show fib`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FibStatus {
    pub table: u32,
    pub metric: u32,
    pub resolve_via_default: bool,
    pub installed_ipv4: usize,
    pub installed_ipv6: usize,
    pub failed: usize,
    pub unresolved: usize,
    /// Prefixes the kernel has its own (connected, static) route for.
    pub shadowed: usize,
    /// Routes of an earlier run still waiting to be taken over.
    pub adopted: usize,
    pub next_hops: Vec<HopStatus>,
    /// Operations the kernel refused since the start, by errno name.
    pub errors: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HopStatus {
    pub address: IpAddr,
    /// The peer's link-local next hop and the session's interface, used when
    /// `address` is link-local itself or does not resolve.
    pub link_local: Option<IpAddr>,
    pub link_dev: Option<String>,
    /// Kernel nexthop object id.
    pub id: u32,
    /// Gateway and interface; null: unreachable.
    pub via: Option<IpAddr>,
    pub dev: Option<String>,
    pub routes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrefixStatus {
    pub next_hop: IpAddr,
    pub state: RouteState,
}

/// What happened to a prefix the RIB wants in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteState {
    Installed,
    /// The kernel refused the change (or the socket failed): its state for
    /// this prefix is unknown until the next try.
    Failed,
    /// The next hop is not reachable; nothing is in the kernel.
    Unresolved,
    /// The kernel has its own route for exactly this prefix (connected,
    /// `ip route add`, static): that one wins, like an administrative
    /// distance below BGP's.
    Shadowed,
}

/// A next hop as `show fib` lists it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HopInfo {
    pub gw: Gateway,
    /// Nexthop object id.
    pub id: u32,
    /// None: unreachable (or the kernel refused the object).
    pub via: Option<Via>,
    /// Prefixes using it.
    pub routes: u32,
}

/// The interface's name, or its index when it has none (any more).
fn interface_name(index: u32) -> String {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: buf has IF_NAMESIZE bytes, as if_indextoname requires.
    let name = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if name.is_null() {
        return format!("if{index}");
    }
    // SAFETY: on success buf holds a NUL-terminated name.
    unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

impl<K: Kernel> Fib<K> {
    /// The state of `prefix` and its next hop, if the RIB wants it installed.
    pub fn route(&self, prefix: &Prefix) -> Option<(IpAddr, RouteState)> {
        let entry = self.entry(prefix)?;
        Some((self.hops[&entry.hop()?].gw.addr, entry.state()))
    }

    #[cfg(test)]
    /// Prefixes per state, IPv4 and IPv6 together.
    pub fn count(&self, state: RouteState) -> usize {
        let v4 = self.v4.values().filter(|e| e.state() == state).count();
        v4 + self.v6.values().filter(|e| e.state() == state).count()
    }

    /// Next hops in use or watched, by address.
    pub fn next_hops(&self) -> Vec<HopInfo> {
        let mut hops: Vec<HopInfo> = self
            .hops
            .iter()
            .map(|(&id, hop)| HopInfo {
                gw: hop.gw,
                id,
                via: hop.via.filter(|_| hop.installed),
                routes: hop.refs,
            })
            .collect();
        hops.sort_unstable();
        hops
    }

    pub fn status(&self) -> FibStatus {
        let count = |v: &mut [usize; 4], e: &Entry| {
            v[match e.state() {
                RouteState::Installed => 0,
                RouteState::Failed => 1,
                RouteState::Unresolved => 2,
                RouteState::Shadowed => 3,
            }] += 1;
        };
        let (mut v4, mut v6) = ([0; 4], [0; 4]);
        self.v4.values().for_each(|e| count(&mut v4, e));
        self.v6.values().for_each(|e| count(&mut v6, e));
        FibStatus {
            table: self.settings.table,
            metric: self.settings.metric,
            resolve_via_default: self.settings.resolve_via_default,
            installed_ipv4: v4[0],
            installed_ipv6: v6[0],
            failed: v4[1] + v6[1],
            unresolved: v4[2] + v6[2],
            shadowed: v4[3] + v6[3],
            adopted: self.adopted.len(),
            next_hops: self
                .next_hops()
                .into_iter()
                .map(|h| HopStatus {
                    address: h.gw.addr,
                    link_local: h.gw.link.map(|(ll, _)| IpAddr::V6(ll)),
                    link_dev: h.gw.link.map(|(_, oif)| interface_name(oif)),
                    id: h.id,
                    via: h.via.map(|v| v.gateway),
                    dev: h.via.map(|v| interface_name(v.oif)),
                    routes: h.routes,
                })
                .collect(),
            errors: self.errors.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        }
    }

    pub(super) fn answer(&self, query: FibQuery) {
        match query {
            FibQuery::Status(reply) => {
                let _ = reply.send(self.status());
            }
            FibQuery::Prefix { prefix, reply } => {
                let status = self
                    .route(&prefix)
                    .map(|(next_hop, state)| PrefixStatus { next_hop, state });
                let _ = reply.send(status);
            }
        }
    }
}
