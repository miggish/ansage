//! Sessions coming up and going down; stale routes kept for Graceful Restart.

use std::{collections::HashSet, time::Instant};

use ansage_bgp::session::Retain;

use ansage_bgp::wire::Afi;

use ansage_bgp::wire::Prefix;

use ansage_bgp::wire::Safi;
use tracing::{info, warn};

use std::time::Duration;

use ansage_bgp::wire::{Notification, cease_subcode, error_code};
use bytes::Bytes;

use crate::{
    config::NeighborRole,
    policy::{Export, Import},
};

use super::{
    Outbound, PeerState, Rib, STALE_PATH_TIME, Stale, family_index,
    msg::{PeerMsg, PeerSettings, PeerUp},
    prefer,
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
        // Everything this peer may get is new to it. A peer that gets
        // nothing only needs its End-of-RIB (no walk over a full table).
        if state.settings.export != Export::None {
            state
                .out
                .dirty
                .extend(self.v4.iter_best().map(|(p, _)| Prefix::V4(p)));
            state
                .out
                .dirty
                .extend(self.v6.iter_best().map(|(p, _)| Prefix::V6(p)));
        }
        if state.settings.default_route {
            state.out.dirty.extend(super::export::default_routes());
        }
        let provider = state.settings.role == Some(NeighborRole::Provider);
        if let Some(old) = self.peers.insert(peer, state) {
            warn!(peer, "peer came up twice without going down");
            self.release_outbound(old.out);
        }
        if provider {
            self.default_routes_dirty();
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

    /// A reload changed `peer`'s settings: they apply to its running
    /// session without a reset. A new export policy re-checks everything the
    /// peer has or could get; a new import policy drops its routes (now
    /// "none") or asks it to send them again (RFC 2918), so the new filter
    /// sees them all. Without route refresh the session restarts.
    pub(super) fn policy_changed(
        &mut self,
        peer: SourceId,
        settings: &PeerSettings,
        out: &mut Vec<(SourceId, PeerMsg)>,
    ) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        let old = std::mem::replace(&mut state.settings, settings.clone());
        if old.export != settings.export || old.default_route != settings.default_route {
            let advertised: Vec<Prefix> = state.out.advertised.keys().copied().collect();
            state.out.dirty.extend(advertised);
            state
                .out
                .dirty
                .extend(self.v4.iter_best().map(|(p, _)| Prefix::V4(p)));
            state
                .out
                .dirty
                .extend(self.v6.iter_best().map(|(p, _)| Prefix::V6(p)));
            if old.default_route || settings.default_route {
                state.out.dirty.extend(super::export::default_routes());
            }
            info!(peer, "export policy changed, routes re-checked");
        }
        if old.import == settings.import {
            return;
        }
        if settings.import == Import::None {
            self.stale.remove(&peer);
            let removed = self.remove_routes(peer, [true, true]);
            if let Some(state) = self.peers.get_mut(&peer) {
                state.received = [0; 2];
            }
            info!(peer, removed, "import policy is none now, routes removed");
            return;
        }
        let state = &self.peers[&peer];
        if state.up.info.route_refresh {
            let families: Vec<Afi> = [Afi::IPV4, Afi::IPV6]
                .into_iter()
                .filter(|&afi| state.negotiated(afi))
                .collect();
            info!(
                peer,
                "import policy changed, asking the peer for its routes again"
            );
            out.push((peer, PeerMsg::RouteRefresh(families)));
        } else {
            warn!(
                peer,
                "import policy changed and the peer does not support route refresh: \
                 restarting the session"
            );
            let notification = Notification::new(
                error_code::CEASE,
                cease_subcode::OTHER_CONFIGURATION_CHANGE,
                Bytes::new(),
            );
            out.push((
                peer,
                PeerMsg::Teardown {
                    notification,
                    retry_after: Duration::ZERO,
                },
            ));
        }
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
        if state.settings.role == Some(NeighborRole::Provider) {
            self.default_routes_dirty();
        }
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
