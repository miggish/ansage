//! Routing information base: one task owns all routes.
//!
//! Peer tasks send what they learn ([`RibMsg`]); the RIB keeps every route
//! per prefix with the best one first, and tells each peer what to announce
//! ([`PeerMsg`]). Exports are pulled: a peer gets the next batch only after
//! it reported [`RibMsg::Ready`], so a slow peer never blocks the RIB and its
//! pending changes collapse in a dirty set instead of queueing up.
//!
//! With `[kernel]`, the FIB task is one more consumer of the same kind: it
//! gets the next hop each changed prefix should be installed with
//! ([`crate::fib::FibMsg::Routes`]) and asks for more with
//! [`RibMsg::FibReady`].
//!
//! Graceful Restart helper (RFC 4724 §4.2): when a peer's session ends in a
//! way that keeps its routes ([`Retain`](herald_bgp::session::Retain)), they
//! stay in the tables as stale until the peer sends them again and its
//! End-of-RIB removes the rest, or until the restart time (session still down)
//! or [`STALE_PATH_TIME`] (session back, no End-of-RIB) runs out.

mod export;
mod fib;
mod import;
mod msg;
mod own;
mod peers;
pub mod pool;
mod query;
pub mod table;

pub use export::encode_batch;
pub use msg::{
    ExportBatch, PeerMsg, PeerRibStatus, PeerSettings, PeerUp, Query, RibConfig, RibMsg,
    RibSummary, RouteInfo, RoutePage, Stats,
};
pub use table::{LOCAL, SourceId};

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use herald_bgp::wire::Afi;

use herald_bgp::wire::Prefix;

use herald_bgp::wire::Prefix4;

use herald_bgp::wire::Prefix6;

use herald_bgp::wire::Safi;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::fib::Gateway;
use fib::FibOut;
use pool::{AttrId, AttrPool};
use table::{DecisionProcess, SourceInfo, Table};

/// Prefixes per export batch: bounds the work done per round and the size
/// of one chunk in the peer's write queue.
const EXPORT_BATCH: usize = 20_000;
/// Prefixes per batch to the FIB task.
const FIB_BATCH: usize = 10_000;
/// Messages handled before exports are built, so bursts batch up.
const DRAIN_LIMIT: usize = 256;
/// LOCAL_PREF sent to iBGP peers for our own prefixes.
const DEFAULT_LOCAL_PREF: u32 = 100;
/// How long a peer whose session came back has to send its End-of-RIB
/// before its remaining stale routes are removed (FRR's stalepath-time).
pub const STALE_PATH_TIME: Duration = Duration::from_secs(360);

struct PeerState {
    up: PeerUp,
    settings: PeerSettings,
    /// Routes received from this peer, per family (0: IPv4, 1: IPv6).
    received: [u32; 2],
    limit_warned: [bool; 2],
    /// Max-prefix teardown sent; ignore further updates until Down.
    torn_down: bool,
    out: Outbound,
}

impl PeerState {
    fn negotiated(&self, afi: Afi) -> bool {
        self.up.info.families.contains(&(afi, Safi::UNICAST))
    }

    fn source_info(&self) -> SourceInfo {
        SourceInfo {
            ibgp: self.up.info.negotiated.ibgp,
            bgp_id: self.up.info.bgp_id,
            addr: self.up.addr,
            oif: self.up.oif,
        }
    }
}

#[derive(Default)]
struct Outbound {
    dirty: HashSet<Prefix>,
    /// Adj-RIB-Out: what we last announced, by the source attribute set.
    advertised: HashMap<Prefix, AttrId>,
    /// Families still waiting for their End-of-RIB.
    eor_pending: Vec<Afi>,
    ready: bool,
    /// Families we already warned about missing next hops.
    no_next_hop_warned: Vec<Afi>,
}

/// A peer's routes kept through a Graceful Restart.
struct Stale {
    /// For the decision process while the peer is down.
    info: SourceInfo,
    /// Not sent again since the session was lost.
    prefixes: HashSet<Prefix>,
    /// Removed then if still stale.
    deadline: Instant,
}

pub struct Rib {
    config: RibConfig,
    pool: AttrPool,
    v4: Table<Prefix4>,
    v6: Table<Prefix6>,
    peers: HashMap<SourceId, PeerState>,
    stale: HashMap<SourceId, Stale>,
    /// Since when our own routes carry GRACEFUL_SHUTDOWN; runtime state
    /// only (a restart starts undrained, a reload keeps it).
    drained: Option<Instant>,
    fib: Option<FibOut>,
    /// Next hops the kernel cannot reach, as the FIB task reported them.
    unreachable: HashSet<Gateway>,
    /// Every prefix that was one of our own since the start: never
    /// installed, also after a runtime withdraw (a withdrawn anycast prefix
    /// must not be routed to another site).
    protected: HashSet<Prefix>,
}

fn family_index(afi: Afi) -> usize {
    usize::from(afi == Afi::IPV6)
}

impl Rib {
    pub fn new(config: RibConfig) -> Self {
        let mut rib = Self {
            config,
            pool: AttrPool::default(),
            v4: Table::default(),
            v6: Table::default(),
            peers: HashMap::new(),
            stale: HashMap::new(),
            drained: None,
            fib: None,
            unreachable: HashSet::new(),
            protected: HashSet::new(),
        };
        // Kept in the config for summaries; a handful of prefixes.
        for prefix in rib.config.announce.clone() {
            rib.insert_own(prefix);
        }
        rib
    }

    /// The sender for a peer's messages, while its session is up.
    pub fn sender(&self, peer: SourceId) -> Option<&mpsc::Sender<PeerMsg>> {
        self.peers.get(&peer).map(|p| &p.up.tx)
    }

    /// Applies one message; messages for peers go to `out`.
    pub fn handle(&mut self, msg: RibMsg, out: &mut Vec<(SourceId, PeerMsg)>) {
        match msg {
            RibMsg::Up(up) => self.peer_up(*up, Instant::now()),
            RibMsg::Update { peer, update } => self.update(peer, update, out),
            RibMsg::RouteRefresh { peer, afi, safi } => self.route_refresh(peer, afi, safi),
            RibMsg::Ready { peer } => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.out.ready = true;
                }
            }
            RibMsg::Down { peer, retain } => self.peer_down(peer, retain, Instant::now()),
            RibMsg::Query(query) => self.query(query),
            RibMsg::PeerSettings { peer, settings } => {
                let install = |s: Option<&PeerSettings>| s.is_some_and(|s| s.install);
                let before = install(self.config.peers.get(&peer));
                let after = install(settings.as_ref());
                match settings {
                    Some(settings) => {
                        self.config.peers.insert(peer, settings);
                    }
                    None => {
                        self.config.peers.remove(&peer);
                    }
                }
                if before != after {
                    self.fib_dirty_where(|_, route| route.source == peer);
                }
                if !after && let Some(sync) = self.fib_sync() {
                    sync.waiting.remove(&peer);
                    sync.end_of_rib.remove(&peer);
                }
            }
            RibMsg::MaxPrefixRestart(restart) => self.config.max_prefix_restart = restart,
            RibMsg::Own {
                announce,
                prefixes,
                reply,
            } => {
                let change = self.own(announce, prefixes);
                let _ = reply.send(change);
            }
            RibMsg::Drain { drained, reply } => {
                let change = self.drain(drained, Instant::now());
                let _ = reply.send(change);
            }
            RibMsg::FibReady => {
                if let Some(fib) = &mut self.fib {
                    fib.ready = true;
                }
            }
            RibMsg::NextHops(changes) => self.next_hops(changes),
            RibMsg::InstallFamilies(families) => {
                let old = std::mem::replace(&mut self.config.install_families, families);
                self.fib_dirty_where(|prefix, route| {
                    let i = family_index(prefix.afi());
                    route.source != LOCAL && old[i] != families[i]
                });
            }
        }
    }
}

/// The decision process over the current peers.
fn prefer<'a>(
    pool: &'a AttrPool,
    peers: &'a HashMap<SourceId, PeerState>,
    stale: &'a HashMap<SourceId, Stale>,
    unreachable: &'a HashSet<Gateway>,
) -> DecisionProcess<'a, impl Fn(SourceId) -> SourceInfo + 'a> {
    DecisionProcess {
        pool,
        unreachable,
        info: move |source| match (peers.get(&source), stale.get(&source)) {
            (Some(state), _) => state.source_info(),
            (None, Some(stale)) => stale.info,
            // LOCAL is decided before this is asked; a peer that went down
            // has no routes left, unless they are stale.
            (None, None) => SourceInfo {
                ibgp: false,
                bgp_id: Ipv4Addr::UNSPECIFIED,
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                oif: None,
            },
        },
    }
}

/// Runs the RIB until every sender is gone.
pub async fn run(mut rib: Rib, mut rx: mpsc::Receiver<RibMsg>) {
    let mut out = Vec::new();
    loop {
        let deadline = rib.next_deadline();
        let msg = tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => Some(msg),
                None => break,
            },
            _ = sleep_until(deadline), if deadline.is_some() => None,
        };
        match msg {
            Some(msg) => rib.handle(msg, &mut out),
            None => rib.expire(Instant::now()),
        }
        for _ in 0..DRAIN_LIMIT {
            match rx.try_recv() {
                Ok(msg) => rib.handle(msg, &mut out),
                Err(_) => break,
            }
        }
        rib.flush(&mut out);
        rib.flush_fib();
        for (peer, msg) in out.drain(..) {
            let Some(tx) = rib.sender(peer) else { continue };
            // Exports only go to peers that asked for one, so there is room.
            if let Err(err) = tx.try_send(msg) {
                warn!(peer, %err, "cannot reach peer task");
            }
        }
    }
    info!(stats = ?rib.stats(), "RIB stopped");
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
