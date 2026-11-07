//! Feeding the FIB thread: best routes to install and next hop reachability.

use std::{
    collections::{HashMap, HashSet},
    sync::mpsc as std_mpsc,
};

use crate::config::ImportPolicy;

use herald_bgp::wire::Afi;

use herald_bgp::wire::Prefix;
use tracing::info;

use super::{
    FIB_BATCH, Rib, family_index, prefer,
    table::{LOCAL, Route, SourceId},
};
use crate::fib::{FibMsg, Gateway};

/// The FIB task as a consumer: like a peer's [`Outbound`](super::Outbound),
/// without an Adj-RIB-Out (the FIB task knows what it installed).
pub(super) struct FibOut {
    pub(super) tx: std_mpsc::Sender<FibMsg>,
    pub(super) dirty: HashSet<Prefix>,
    pub(super) ready: bool,
    /// Until the FIB is told [`FibMsg::Synced`]: installing neighbors that
    /// have not sent all their routes yet, and the families each still owes
    /// an End-of-RIB for (once its session is up).
    pub(super) sync: Option<FibSync>,
}

#[derive(Default)]
pub(super) struct FibSync {
    pub(super) waiting: HashSet<SourceId>,
    pub(super) end_of_rib: HashMap<SourceId, Vec<Afi>>,
}

impl FibSync {
    pub(super) fn up(&mut self, peer: SourceId, families: Vec<Afi>) {
        if self.waiting.contains(&peer) {
            self.end_of_rib.insert(peer, families);
            self.done(peer, None);
        }
    }

    /// End-of-RIB for `afi` (None: just check).
    pub(super) fn done(&mut self, peer: SourceId, afi: Option<Afi>) {
        let Some(owed) = self.end_of_rib.get_mut(&peer) else {
            return;
        };
        owed.retain(|f| Some(*f) != afi);
        if owed.is_empty() {
            self.end_of_rib.remove(&peer);
            self.waiting.remove(&peer);
        }
    }
}

impl Rib {
    /// Sends the kernel's share of the routes to the FIB task from now on,
    /// starting with every current best route learned from a peer.
    pub fn attach_fib(&mut self, tx: std_mpsc::Sender<FibMsg>) {
        let waiting = self
            .config
            .peers
            .iter()
            .filter(|(_, s)| s.install && s.import == ImportPolicy::All)
            .map(|(&peer, _)| peer)
            .collect();
        self.fib = Some(FibOut {
            tx,
            dirty: HashSet::new(),
            ready: true,
            sync: Some(FibSync {
                waiting,
                ..FibSync::default()
            }),
        });
        self.fib_dirty_where(|_, route| route.source != LOCAL);
    }

    /// Next hops became unreachable or reachable again: every prefix with a
    /// route through one of them is decided again, and goes to the FIB task
    /// even when its best route stays (it may have to leave the kernel).
    pub(super) fn next_hops(&mut self, changes: Vec<(Gateway, bool)>) {
        let mut changed = HashSet::new();
        for (addr, reachable) in changes {
            let known = if reachable {
                self.unreachable.remove(&addr)
            } else {
                self.unreachable.insert(addr)
            };
            if known {
                changed.insert(addr);
            }
        }
        if changed.is_empty() {
            return;
        }
        info!(next_hops = ?changed, unreachable = self.unreachable.len(), "next hops changed");
        let mut reranked = Vec::new();
        {
            let prefer = prefer(&self.pool, &self.peers, &self.stale, &self.unreachable);
            let pool = &self.pool;
            let affected = |route: &Route| {
                pool.gateway(route.attrs, (prefer.info)(route.source).oif)
                    .is_some_and(|hop| changed.contains(&hop))
            };
            self.v4.rerank(affected, &prefer, |p, change| {
                reranked.push((Prefix::V4(p), change));
            });
            self.v6.rerank(affected, &prefer, |p, change| {
                reranked.push((Prefix::V6(p), change));
            });
        }
        for (prefix, change) in reranked {
            if let Some(fib) = &mut self.fib {
                fib.dirty.insert(prefix);
            }
            if change.best_changed() {
                self.mark_dirty(prefix, change);
            }
        }
    }

    /// Re-evaluates the best routes matching `filter` for the FIB task.
    pub(super) fn fib_dirty_where(&mut self, filter: impl Fn(Prefix, Route) -> bool) {
        let Some(fib) = &mut self.fib else {
            return;
        };
        let v4 = self.v4.iter_best().map(|(p, r)| (Prefix::V4(p), r));
        let v6 = self.v6.iter_best().map(|(p, r)| (Prefix::V6(p), r));
        fib.dirty
            .extend(v4.chain(v6).filter(|&(p, r)| filter(p, r)).map(|(p, _)| p));
    }

    /// The next hop the kernel should use for `prefix`, or None: not
    /// installed. Only the best route counts: a best route from a neighbor
    /// without `install` keeps the prefix out of the kernel.
    pub fn fib_next_hop(&self, prefix: &Prefix) -> Option<Gateway> {
        if !self.config.install_families[family_index(prefix.afi())]
            || self.protected.contains(prefix)
        {
            return None;
        }
        let best = match prefix {
            Prefix::V4(p) => self.v4.best(p),
            Prefix::V6(p) => self.v6.best(p),
        }?;
        if best.source == LOCAL || !self.config.peers.get(&best.source)?.install {
            return None;
        }
        self.pool
            .forwarding_gateway(
                best.attrs,
                prefix.afi() == Afi::IPV6,
                self.source_oif(best.source),
            )
            .filter(|hop| !self.unreachable.contains(hop))
    }

    /// The next batch for the FIB task, if it is ready and there is work.
    fn next_fib_batch(&mut self) -> Option<Vec<(Prefix, Option<Gateway>)>> {
        let fib = self.fib.as_ref()?;
        if !fib.ready || fib.dirty.is_empty() {
            return None;
        }
        let take: Vec<Prefix> = fib.dirty.iter().take(FIB_BATCH).copied().collect();
        let routes: Vec<(Prefix, Option<Gateway>)> =
            take.iter().map(|&p| (p, self.fib_next_hop(&p))).collect();
        let fib = self.fib.as_mut().expect("checked");
        for prefix in &take {
            fib.dirty.remove(prefix);
        }
        // A full table load filled it to a million entries; give that back.
        if fib.dirty.is_empty() && fib.dirty.capacity() > 4 * FIB_BATCH {
            fib.dirty.shrink_to_fit();
        }
        fib.ready = false;
        Some(routes)
    }

    /// Sends the next batch to the FIB task.
    /// Once all is sent and applied, tells it that the neighbors are in
    /// sync.
    pub fn flush_fib(&mut self) {
        let msg = match self.next_fib_batch() {
            Some(routes) => FibMsg::Routes(routes),
            None => {
                let Some(fib) = &mut self.fib else {
                    return;
                };
                let synced = fib.ready
                    && fib.dirty.is_empty()
                    && fib.sync.as_ref().is_some_and(|s| s.waiting.is_empty());
                if !synced {
                    return;
                }
                fib.sync = None;
                info!("installing neighbors sent all their routes");
                FibMsg::Synced
            }
        };
        let fib = self.fib.as_ref().expect("checked");
        if fib.tx.send(msg).is_err() {
            // Only at a restart: the FIB stops first to keep the routes.
            info!("the FIB has stopped: kernel routes are no longer updated");
            self.fib = None;
        }
    }

    pub(super) fn fib_sync(&mut self) -> Option<&mut FibSync> {
        self.fib.as_mut()?.sync.as_mut()
    }

    /// The session interface of a neighbor that is up, or down with stale
    /// routes.
    pub(super) fn source_oif(&self, source: SourceId) -> Option<u32> {
        match (self.peers.get(&source), self.stale.get(&source)) {
            (Some(state), _) => state.up.oif,
            (None, Some(stale)) => stale.info.oif,
            (None, None) => None,
        }
    }
}
