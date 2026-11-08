//! Sessions coming up and going down; stale routes kept for Graceful Restart.

use std::{collections::HashSet, time::Instant};

use ansage_bgp::session::Retain;

use ansage_bgp::wire::Afi;

use ansage_bgp::wire::Prefix;

use ansage_bgp::wire::Safi;
use tracing::{info, warn};

use super::{
    Outbound, PeerState, Rib, STALE_PATH_TIME, Stale, family_index, msg::PeerUp, prefer,
    table::SourceId,
};

impl Rib {
    pub(super) fn peer_up(&mut self, up: PeerUp, now: Instant) {
        let peer = up.peer;
        let settings = self.config.peers.get(&peer).cloned().unwrap_or_default();
        // Stale routes are still in the tables and count until removed.
        let mut received = [0; 2];
        if let Some(stale) = self.stale.get(&peer) {
            for prefix in &stale.prefixes {
                received[family_index(prefix.afi())] += 1;
            }
        }
        let mut state = PeerState {
            up,
            settings,
            received,
            limit_warned: [false; 2],
            torn_down: false,
            out: Outbound {
                ready: true,
                ..Outbound::default()
            },
        };
        for afi in [Afi::IPV4, Afi::IPV6] {
            if state.negotiated(afi) {
                state.out.eor_pending.push(afi);
            }
        }
        // Everything this peer may get is new to it.
        state
            .out
            .dirty
            .extend(self.v4.iter_best().map(|(p, _)| Prefix::V4(p)));
        state
            .out
            .dirty
            .extend(self.v6.iter_best().map(|(p, _)| Prefix::V6(p)));
        if let Some(old) = self.peers.insert(peer, state) {
            warn!(peer, "peer came up twice without going down");
            self.release_outbound(old.out);
        }
        let families = [Afi::IPV4, Afi::IPV6]
            .into_iter()
            .filter(|&afi| self.peers[&peer].negotiated(afi))
            .collect();
        if let Some(sync) = self.fib_sync() {
            sync.up(peer, families);
        }
        self.stale_after_up(peer, now);
    }

    /// RFC 4724 §4.2: the session is back. Stale routes of families the peer
    /// no longer keeps (no Graceful Restart, or the F bit clear) go at once;
    /// the rest wait for its End-of-RIB, at most [`STALE_PATH_TIME`].
    fn stale_after_up(&mut self, peer: SourceId, now: Instant) {
        let Some(stale) = self.stale.get_mut(&peer) else {
            return;
        };
        stale.deadline = now + STALE_PATH_TIME;
        let gr = self.peers[&peer].up.info.graceful_restart.clone();
        for afi in [Afi::IPV4, Afi::IPV6] {
            let kept = gr.as_ref().is_some_and(|gr| {
                gr.families
                    .iter()
                    .any(|f| f.afi == afi && f.safi == Safi::UNICAST && f.forwarding)
            });
            if !kept {
                let removed = self.drop_stale(peer, Some(afi));
                if removed > 0 {
                    info!(
                        peer,
                        ?afi,
                        removed,
                        "stale routes removed: the peer did not keep its forwarding state"
                    );
                }
            }
        }
    }

    /// Removes the stale routes of `peer` (of one family, or all).
    pub(super) fn drop_stale(&mut self, peer: SourceId, afi: Option<Afi>) -> usize {
        let Some(stale) = self.stale.get_mut(&peer) else {
            return 0;
        };
        let gone: Vec<Prefix> = stale
            .prefixes
            .iter()
            .filter(|p| afi.is_none_or(|afi| p.afi() == afi))
            .copied()
            .collect();
        for prefix in &gone {
            self.withdraw(peer, *prefix);
        }
        if self.stale.get(&peer).is_some_and(|s| s.prefixes.is_empty()) {
            self.stale.remove(&peer);
        }
        gone.len()
    }

    /// When the next stale routes run out.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.stale.values().map(|s| s.deadline).min()
    }

    /// Removes stale routes whose time is up.
    pub fn expire(&mut self, now: Instant) {
        let due: Vec<SourceId> = self
            .stale
            .iter()
            .filter(|(_, s)| s.deadline <= now)
            .map(|(&peer, _)| peer)
            .collect();
        for peer in due {
            let removed = self.drop_stale(peer, None);
            self.stale.remove(&peer);
            warn!(peer, removed, stats = ?self.stats(),
                "graceful restart: stale routes timed out and were removed");
        }
    }

    pub(super) fn peer_down(&mut self, peer: SourceId, retain: Option<Retain>, now: Instant) {
        let Some(state) = self.peers.remove(&peer) else {
            return;
        };
        let info = state.source_info();
        self.release_outbound(state.out);
        let Some(retain) = retain else {
            self.stale.remove(&peer);
            let removed = self.remove_routes(peer, [true, true]);
            info!(peer, removed, stats = ?self.stats(), "peer down, routes removed");
            return;
        };
        // Known before removing anything: the decision process needs it for
        // the routes that stay.
        let deadline = now + retain.restart_time;
        let stale = self.stale.entry(peer).or_insert_with(|| Stale {
            info,
            prefixes: HashSet::new(),
            deadline,
        });
        stale.info = info;
        stale.deadline = deadline;
        let keep =
            [Afi::IPV4, Afi::IPV6].map(|afi| retain.families.contains(&(afi, Safi::UNICAST)));
        let removed = self.remove_routes(peer, keep.map(|k| !k));
        // Everything left of the peer is stale now, also what it sent again
        // before this session ended too.
        let prefixes: HashSet<Prefix> = self
            .v4
            .prefixes_of(peer)
            .into_iter()
            .map(Prefix::V4)
            .chain(self.v6.prefixes_of(peer).into_iter().map(Prefix::V6))
            .collect();
        let kept = prefixes.len();
        if kept == 0 {
            self.stale.remove(&peer);
        } else if let Some(stale) = self.stale.get_mut(&peer) {
            stale.prefixes = prefixes;
        }
        info!(peer, kept, removed, restart_time = ?retain.restart_time, stats = ?self.stats(),
            "peer down, routes kept as stale (graceful restart)");
    }

    /// Removes the routes of `peer` from the tables selected by `[v4, v6]`.
    fn remove_routes(&mut self, peer: SourceId, tables: [bool; 2]) -> usize {
        let mut changed = Vec::new();
        let mut released = Vec::new();
        {
            let prefer = prefer(&self.pool, &self.peers, &self.stale, &self.unreachable);
            if tables[0] {
                self.v4.remove_source(peer, &prefer, |p, attrs, change| {
                    released.push(attrs);
                    if change.best_changed() {
                        changed.push((Prefix::V4(p), change));
                    }
                });
            }
            if tables[1] {
                self.v6.remove_source(peer, &prefer, |p, attrs, change| {
                    released.push(attrs);
                    if change.best_changed() {
                        changed.push((Prefix::V6(p), change));
                    }
                });
            }
        }
        let removed = released.len();
        for attrs in released {
            self.pool.release(attrs);
        }
        for (prefix, change) in changed {
            self.mark_dirty(prefix, change);
        }
        removed
    }
}
