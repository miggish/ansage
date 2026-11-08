//! Kernel FIB: puts ansage's best routes into the Linux routing table.
//!
//! The RIB sends the next hop each changed prefix should use
//! ([`FibMsg::Routes`], pulled with
//! [`RibMsg::FibReady`](crate::rib::RibMsg::FibReady)); this module keeps
//! the kernel in line with that. Every BGP next hop becomes one kernel
//! nexthop object (ids in [`NEXTHOP_IDS`], protocol bgp) and routes point at
//! it, so a next hop that moves is one message, not one per route.
//!
//! A BGP next hop is resolved through the kernel's own routing entry for
//! it (connected, or through a gateway: the nexthop object then points at
//! that gateway, see [`resolution`](resolve::resolution)). A thread watching
//! the kernel ([`events`]) makes ansage resolve again after interface, address
//! and route changes. Next hops that become unreachable or reachable again are
//! reported to the RIB ([`RibMsg::NextHops`](crate::rib::RibMsg::NextHops)),
//! which then decides again. What the kernel refuses is retried every
//! [`SWEEP_INTERVAL`].
//!
//! The work runs on its own thread: applying a batch blocks for as long as
//! the kernel needs, which must not hold up a tokio worker.

mod apply;
mod entry;
pub mod events;
mod kernel;
mod resolve;
mod status;
mod thread;

pub use entry::Gateway;
pub use status::{FibStatus, PrefixStatus, RouteState};
pub use thread::{FibHandle, start};

use std::{
    collections::{HashMap, HashSet},
    io,
    ops::RangeInclusive,
    time::Duration,
};

use ansage_netlink::RTN_UNICAST;

use ansage_netlink::RTPROT_BGP;

use ansage_bgp::wire::Prefix;

use ansage_bgp::wire::Prefix4;

use ansage_bgp::wire::Prefix6;
use tokio::sync::oneshot;
use tracing::{info, warn};

use apply::{Plan, Target, route_in};
use entry::{Entry, Hop};

#[cfg(test)]
mod tests;

pub use kernel::{Kernel, Op};

/// Nexthop object ids ansage owns: 186 (the bgp protocol number) << 24,
/// 16M ids. Whatever is in this range belongs to ansage.
pub const NEXTHOP_IDS: RangeInclusive<u32> = 0xBA00_0000..=0xBAFF_FFFF;
/// The last id is only used by the start-up probe.
const PROBE_ID: u32 = *NEXTHOP_IDS.end();

/// Protocols of routes ansage never overrides: connected (kernel),
/// `ip route add` (boot) and static (systemd-networkd and others).
const LOCAL_PROTOCOLS: [u8; 3] = [
    ansage_netlink::RTPROT_KERNEL,
    ansage_netlink::RTPROT_BOOT,
    ansage_netlink::RTPROT_STATIC,
];

/// How often failed and waiting prefixes are tried again.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// After a kernel change, wait this long for more before resolving again.
pub const DEBOUNCE: Duration = Duration::from_millis(100);

/// Where and how routes are installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub table: u32,
    pub metric: u32,
    /// A next hop whose only route is the default route counts as reachable.
    pub resolve_via_default: bool,
}

impl From<&crate::config::Kernel> for Settings {
    fn from(kernel: &crate::config::Kernel) -> Self {
        Self {
            table: kernel.table,
            metric: kernel.metric,
            resolve_via_default: kernel.resolve_via_default,
        }
    }
}

#[derive(Debug)]
pub enum FibMsg {
    /// From the RIB: the next hop each prefix should use now; None takes it
    /// out of the kernel.
    Routes(Vec<(Prefix, Option<Gateway>)>),
    /// New settings (config reload): a new table or metric moves every
    /// route.
    Settings(Settings),
    /// From the event thread: interfaces, addresses or routes changed.
    KernelChanged,
    /// From the RIB: every installing neighbor sent its routes again; what
    /// is left of the earlier run goes.
    Synced,
    /// From the control socket.
    Query(FibQuery),
    /// End the thread; `flush` deletes everything ansage installed first.
    Stop {
        flush: bool,
        done: oneshot::Sender<()>,
    },
}

#[derive(Debug)]
pub enum FibQuery {
    Status(oneshot::Sender<FibStatus>),
    /// The kernel state of one prefix.
    Prefix {
        prefix: Prefix,
        reply: oneshot::Sender<Option<PrefixStatus>>,
    },
}

pub struct Fib<K> {
    kernel: K,
    settings: Settings,
    v4: HashMap<Prefix4, Entry>,
    v6: HashMap<Prefix6, Entry>,
    /// Prefixes that are not Installed, for the sweep.
    retry: HashSet<Prefix>,
    hops: HashMap<u32, Hop>,
    by_addr: HashMap<Gateway, u32>,
    free_ids: Vec<u32>,
    next_id: u32,
    /// Refused operations, by reason (errno name).
    errors: HashMap<String, u64>,
    /// Reachability changes for the RIB, not sent yet.
    reports: Vec<(Gateway, bool)>,
    /// Left by an earlier run (`ansage upgrade`, a crash) and kept until
    /// the neighbors have sent their routes again: nexthop ids, and the
    /// prefixes not taken over yet.
    adopted_ids: HashSet<u32>,
    adopted: HashSet<Prefix>,
    /// Prefixes the table has a connected, boot or static route for.
    local: HashSet<Prefix>,
}

impl<K: Kernel> Fib<K> {
    pub fn new(kernel: K, settings: Settings) -> Self {
        Self {
            kernel,
            settings,
            v4: HashMap::new(),
            v6: HashMap::new(),
            retry: HashSet::new(),
            hops: HashMap::new(),
            by_addr: HashMap::new(),
            free_ids: Vec::new(),
            next_id: *NEXTHOP_IDS.start(),
            errors: HashMap::new(),
            reports: Vec::new(),
            adopted_ids: HashSet::new(),
            adopted: HashSet::new(),
            local: HashSet::new(),
        }
    }

    /// Re-reads the routes ansage must not shadow (connected, boot,
    /// static) and returns the prefixes that came or went.
    fn load_local(&mut self) -> Vec<Prefix> {
        let mut local = HashSet::new();
        for protocol in LOCAL_PROTOCOLS {
            match self.kernel.routes(self.settings.table, protocol) {
                Ok(routes) => local.extend(
                    routes
                        .into_iter()
                        .filter(|r| r.kind == RTN_UNICAST)
                        .map(|r| r.dst),
                ),
                Err(err) => {
                    warn!(%err, "cannot read the kernel's own routes");
                    return Vec::new();
                }
            }
        }
        let changed = local.symmetric_difference(&self.local).copied().collect();
        self.local = local;
        changed
    }

    /// Takes over what an earlier run left in the kernel: its routes keep
    /// forwarding until the RIB sends them again (replaced in place) or
    /// [`Fib::end_adoption`] removes the rest. Returns the number of
    /// nexthop objects and routes found.
    pub fn adopt(&mut self) -> io::Result<(usize, usize)> {
        let ids: HashSet<u32> = self
            .kernel
            .nexthops()?
            .into_iter()
            .map(|nh| nh.id)
            .filter(|id| NEXTHOP_IDS.contains(id))
            .collect();
        let routes: HashSet<Prefix> = self
            .kernel
            .routes(self.settings.table, RTPROT_BGP)?
            .into_iter()
            .filter(|r| r.nh_id.is_some_and(|id| ids.contains(&id)))
            .map(|r| r.dst)
            .collect();
        if let Some(&last) = ids.iter().max() {
            self.next_id = last.saturating_add(1).min(PROBE_ID - 1);
        }
        let found = (ids.len(), routes.len());
        self.adopted_ids = ids;
        self.adopted = routes;
        Ok(found)
    }

    #[cfg(test)]
    /// Adopted routes are waiting to be taken over.
    pub fn adopting(&self) -> bool {
        !self.adopted_ids.is_empty()
    }

    /// Deletes the earlier run's nexthop objects, and with them its routes
    /// that were not taken over. Returns how many routes those were.
    pub fn end_adoption(&mut self) -> usize {
        let ids: Vec<u32> = self.adopted_ids.drain().collect();
        let ops: Vec<Op> = ids.iter().map(|&id| Op::DeleteNexthop(id)).collect();
        for (result, id) in self.kernel.apply(&ops).into_iter().zip(&ids) {
            if let Err(err) = result
                && !err.is_not_found()
            {
                warn!(id, %err, "cannot delete a nexthop object of the earlier run");
            }
        }
        let left = self.adopted.len();
        self.adopted.clear();
        left
    }

    #[cfg(test)]
    pub fn kernel(&mut self) -> &mut K {
        &mut self.kernel
    }

    /// Reachability changes the RIB has not heard of yet.
    pub fn take_reports(&mut self) -> Vec<(Gateway, bool)> {
        std::mem::take(&mut self.reports)
    }

    pub fn settings(&self) -> Settings {
        self.settings
    }

    #[cfg(test)]
    pub fn errors(&self) -> &HashMap<String, u64> {
        &self.errors
    }

    /// Something waits for the next sweep.
    pub fn needs_sweep(&self) -> bool {
        !self.retry.is_empty() || self.hops.values().any(|h| !h.usable())
    }

    fn entry(&self, prefix: &Prefix) -> Option<Entry> {
        match prefix {
            Prefix::V4(p) => self.v4.get(p).copied(),
            Prefix::V6(p) => self.v6.get(p).copied(),
        }
    }

    fn set_entry(&mut self, prefix: Prefix, entry: Option<Entry>) {
        match entry {
            Some(e) if !matches!(e.state(), RouteState::Installed | RouteState::Shadowed) => {
                self.retry.insert(prefix);
            }
            _ => {
                self.retry.remove(&prefix);
            }
        }
        match (prefix, entry) {
            (Prefix::V4(p), Some(e)) => {
                self.v4.insert(p, e);
            }
            (Prefix::V4(p), None) => {
                self.v4.remove(&p);
            }
            (Prefix::V6(p), Some(e)) => {
                self.v6.insert(p, e);
            }
            (Prefix::V6(p), None) => {
                self.v6.remove(&p);
            }
        }
    }

    /// Brings the kernel in line with what the RIB wants for these prefixes.
    pub fn update<G: Copy + Into<Gateway>>(&mut self, routes: &[(Prefix, Option<G>)]) {
        let mut plan = Plan::default();
        for &(prefix, want) in routes {
            // The new next hop first, so one that stays never drops to zero.
            let hop = want.map(|gw| self.acquire(gw.into(), &mut plan));
            let old = self.entry(&prefix);
            if let Some(old_hop) = old.and_then(|e| e.hop()) {
                self.release(old_hop, &mut plan);
            }
            let unchanged = old.is_some_and(|e| e.hop() == hop && e.hop().is_some());
            // An adopted route is in the kernel: replaced or deleted now.
            let old_state = old
                .map(|e| e.state())
                .or_else(|| self.adopted.remove(&prefix).then_some(RouteState::Failed));
            if unchanged && old_state == Some(RouteState::Installed) {
                continue;
            }
            self.plan_route(prefix, old_state, hop, &mut plan);
        }
        self.execute(plan);
    }

    /// Resolves every next hop again and tries again what failed or waits
    /// for its next hop: after kernel changes and every [`SWEEP_INTERVAL`].
    pub fn refresh(&mut self) {
        let mut plan = Plan::default();
        // A connected or static route came or went: its prefix leaves the
        // kernel or goes in.
        for prefix in self.load_local() {
            if let Some(entry) = self.entry(&prefix) {
                self.plan_route(prefix, Some(entry.state()), entry.hop(), &mut plan);
            }
        }
        let mut lost = HashSet::new();
        let ids: Vec<u32> = self.hops.keys().copied().collect();
        for id in ids {
            let (gw, previous) = (self.hops[&id].gw, self.hops[&id].via);
            let via = self.resolve(gw, previous);
            let hop = self.hops.get_mut(&id).expect("listed");
            match via {
                Some(_) if hop.refs == 0 => {
                    // Only watched: the RIB hears it is back, nothing more.
                    self.reports.push((gw, true));
                    self.forget_hop(id);
                }
                Some(via) => {
                    if hop.via != Some(via) || !hop.installed {
                        hop.via = Some(via);
                        hop.installed = true;
                        let nh = hop.nexthop(id).expect("resolved");
                        plan.hops.push((Op::AddNexthop(nh), Target::Hop(id)));
                    }
                    if hop.reported {
                        hop.reported = false;
                        self.reports.push((gw, true));
                    }
                }
                None => {
                    hop.via = None;
                    if hop.installed {
                        // Its routes go with it, in one message.
                        hop.installed = false;
                        plan.hops.push((Op::DeleteNexthop(id), Target::None));
                        lost.insert(id);
                    }
                    if !hop.reported {
                        hop.reported = true;
                        self.reports.push((gw, false));
                    }
                }
            }
        }
        if !lost.is_empty() {
            self.mark_unresolved(&lost);
        }
        let retry: Vec<Prefix> = self.retry.iter().copied().collect();
        for prefix in retry {
            let Some(entry) = self.entry(&prefix) else {
                continue;
            };
            let usable = entry.hop().is_some_and(|id| self.hops[&id].usable());
            if entry.state() == RouteState::Unresolved && !usable {
                continue;
            }
            self.plan_route(prefix, Some(entry.state()), entry.hop(), &mut plan);
        }
        self.execute(plan);
    }

    /// The routes through these hops left the kernel with their nexthop
    /// objects.
    fn mark_unresolved(&mut self, hops: &HashSet<u32>) {
        let gone = |e: &Entry| {
            e.state() == RouteState::Installed && e.hop().is_some_and(|id| hops.contains(&id))
        };
        let v4 = self.v4.iter().filter(|(_, e)| gone(e));
        let v6 = self.v6.iter().filter(|(_, e)| gone(e));
        let prefixes: Vec<(Prefix, Entry)> = v4
            .map(|(p, e)| (Prefix::V4(*p), *e))
            .chain(v6.map(|(p, e)| (Prefix::V6(*p), *e)))
            .collect();
        for (prefix, entry) in prefixes {
            self.set_entry(prefix, Some(entry.with_state(RouteState::Unresolved)));
        }
    }

    /// Moves every route to a new table or metric: the new copy first, so
    /// forwarding never stops, then the old one goes.
    pub fn set_settings(&mut self, settings: Settings) {
        let old = std::mem::replace(&mut self.settings, settings);
        if old.resolve_via_default != settings.resolve_via_default || old.table != settings.table {
            // Also re-reads the kernel's own routes of the new table.
            self.refresh();
        }
        if (old.table, old.metric) == (settings.table, settings.metric) {
            return;
        }
        let mut plan = Plan::default();
        let mut deletes = Vec::new();
        let prefixes: Vec<(Prefix, Entry)> = self
            .v4
            .iter()
            .map(|(p, e)| (Prefix::V4(*p), *e))
            .chain(self.v6.iter().map(|(p, e)| (Prefix::V6(*p), *e)))
            .collect();
        for (prefix, entry) in prefixes {
            if entry.state() == RouteState::Unresolved {
                continue;
            }
            deletes.push((Op::DeleteRoute(route_in(old, prefix, None)), Target::None));
            self.plan_route(prefix, Some(entry.state()), entry.hop(), &mut plan);
        }
        plan.routes.extend(deletes);
        info!(
            table = settings.table,
            metric = settings.metric,
            "moving kernel routes"
        );
        self.execute(plan);
    }

    /// Deletes every nexthop object in ansage's range, and with them every
    /// route ansage installed (also ones of an earlier run). Returns how
    /// many objects there were.
    pub fn purge(&mut self) -> io::Result<usize> {
        let ours: Vec<u32> = self
            .kernel
            .nexthops()?
            .into_iter()
            .map(|nh| nh.id)
            .filter(|id| NEXTHOP_IDS.contains(id))
            .collect();
        let ops: Vec<Op> = ours.iter().map(|&id| Op::DeleteNexthop(id)).collect();
        for (result, id) in self.kernel.apply(&ops).into_iter().zip(&ours) {
            if let Err(err) = result
                && !err.is_not_found()
            {
                warn!(id, %err, "cannot delete nexthop object");
            }
        }
        self.v4.clear();
        self.v6.clear();
        self.retry.clear();
        self.hops.clear();
        self.by_addr.clear();
        self.free_ids.clear();
        self.next_id = *NEXTHOP_IDS.start();
        self.adopted_ids.clear();
        self.adopted.clear();
        Ok(ours.len())
    }
}
