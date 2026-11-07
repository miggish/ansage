//! Routes from peers: UPDATEs into the Loc-RIB, with the max-prefix limits.

use std::net::IpAddr;

use crate::config::ImportPolicy;
use bytes::{BufMut, BytesMut};
use herald_bgp::wire::{
    Afi, NextHop, Notification, PathAttr, Prefix, Safi, Update, cease_subcode, error_code,
};
use tracing::{debug, info, warn};

use super::{
    Rib, family_index,
    msg::PeerMsg,
    pool::AttrId,
    prefer,
    table::{Route, SourceId},
};

/// Multicast and reserved space: 224.0.0.0/3 (multicast, class E) and
/// ff00::/8.
fn reserved(prefix: &Prefix) -> bool {
    match prefix {
        Prefix::V4(p) => p.prefix_len() >= 3 && u32::from(p.addr()) >> 29 == 0b111,
        Prefix::V6(p) => p.prefix_len() >= 8 && p.addr().octets()[0] == 0xff,
    }
}

fn as_loop(attrs: &[PathAttr], local_asn: u32) -> bool {
    attrs.iter().any(|a| match a {
        PathAttr::AsPath(path) => path.segments.iter().any(|s| s.asns.contains(&local_asn)),
        _ => false,
    })
}

impl Rib {
    pub(super) fn update(
        &mut self,
        peer: SourceId,
        update: Update,
        out: &mut Vec<(SourceId, PeerMsg)>,
    ) {
        match self.peers.get(&peer) {
            Some(state) if !state.torn_down => {}
            _ => return,
        }
        if let Some((afi, _)) = update.is_end_of_rib() {
            let state = &self.peers[&peer];
            info!(
                peer,
                ?afi,
                received_ipv4 = state.received[0],
                received_ipv6 = state.received[1],
                stats = ?self.stats(),
                "end of RIB from peer"
            );
            if let Some(sync) = self.fib_sync() {
                sync.done(peer, Some(afi));
            }
            let removed = self.drop_stale(peer, Some(afi));
            if removed > 0 {
                info!(
                    peer,
                    ?afi,
                    removed,
                    "graceful restart done: stale routes not sent again removed"
                );
            }
            return;
        }
        if self.peers[&peer].settings.import == ImportPolicy::None {
            return;
        }

        let mut withdrawn: Vec<Prefix> = update.withdrawn.iter().map(|p| Prefix::V4(*p)).collect();
        if let Some(unreach) = &update.mp_unreach {
            withdrawn.extend(&unreach.withdrawn);
        }
        let mut announced: Vec<Prefix> = update.nlri.iter().map(|p| Prefix::V4(*p)).collect();
        let reach = update.mp_reach.as_ref();
        let mut mp_announced: Vec<Prefix> = reach.map(|m| m.nlri.clone()).unwrap_or_default();

        // RFC 4271 §6.3: semantically wrong prefixes (multicast, reserved)
        // are ignored.
        let total = announced.len() + mp_announced.len();
        announced.retain(|p| !reserved(p));
        mp_announced.retain(|p| !reserved(p));
        let ignored = total - announced.len() - mp_announced.len();
        if ignored > 0 {
            debug!(peer, ignored, "ignoring multicast/reserved prefixes");
        }

        // Routes that may not be used replace (withdraw) older routes for
        // the same prefixes. The peer task already logged RFC 7606 errors.
        let local = self.peers[&peer].up.local_addr;
        let ineligible = if update.treat_as_withdraw.is_some() {
            Some("malformed UPDATE (RFC 7606)")
        } else if as_loop(&update.attrs, self.config.local_asn) {
            // RFC 4271 §9.1.2: our own AS in the path.
            Some("AS loop")
        } else {
            None
        };
        // RFC 4271 §6.3: a next hop that is our own address is unusable. Ours
        // are the session address and every next hop we announce on this
        // session, in either family.
        let up = &self.peers[&peer].up;
        let ours = |addr: IpAddr| {
            let addr = addr.to_canonical();
            addr == local.to_canonical()
                || up.next_hop_ipv4.map(IpAddr::V4) == Some(addr)
                || up.next_hop_ipv6.map(IpAddr::V6) == Some(addr)
                || up.next_hop_ipv6_link_local.map(IpAddr::V6) == Some(addr)
        };
        let own_v4_next_hop = update
            .attrs
            .iter()
            .any(|a| matches!(a, PathAttr::NextHop(nh) if ours(IpAddr::V4(*nh))));
        let own_v6_next_hop = reach.is_some_and(|m| match m.next_hop {
            NextHop::V6 { global, link_local } => {
                ours(IpAddr::V6(global)) || link_local.is_some_and(|ll| ours(IpAddr::V6(ll)))
            }
            NextHop::V4(addr) => ours(IpAddr::V4(addr)),
        });
        let v4_reason = ineligible.or(own_v4_next_hop.then_some("next hop is our address"));
        let v6_reason = ineligible.or(own_v6_next_hop.then_some("next hop is our address"));

        // RFC 4271 §4.3: withdrawals first, so a prefix listed as withdrawn
        // and announced in the same UPDATE ends up announced.
        for prefix in withdrawn {
            self.withdraw(peer, prefix);
        }
        for (prefixes, reason, next_hop) in [
            (announced, v4_reason, None),
            (mp_announced, v6_reason, reach.map(|m| &m.next_hop)),
        ] {
            if prefixes.is_empty() {
                continue;
            }
            match reason {
                Some(reason) => {
                    debug!(peer, routes = prefixes.len(), reason, "routes not eligible");
                    for prefix in prefixes {
                        self.withdraw(peer, prefix);
                    }
                }
                None => {
                    let attrs = self.pool.intern(&update.attrs, next_hop);
                    self.announce(peer, attrs, &prefixes);
                }
            }
        }
        self.check_limits(peer, out);
    }

    /// Inserts `prefixes` from `peer` with the interned set `attrs`
    /// (consumes the reference `intern` took).
    pub(super) fn announce(&mut self, peer: SourceId, attrs: AttrId, prefixes: &[Prefix]) {
        let mut stale = self.stale.get_mut(&peer);
        for &prefix in prefixes {
            if let Some(stale) = stale.as_mut() {
                stale.prefixes.remove(&prefix);
            }
        }
        for &prefix in prefixes {
            self.pool.retain(attrs);
            let new = self.insert(
                prefix,
                Route {
                    source: peer,
                    attrs,
                },
            );
            if new && let Some(state) = self.peers.get_mut(&peer) {
                state.received[family_index(prefix.afi())] += 1;
            }
        }
        self.pool.release(attrs);
    }

    /// Returns whether the source had no route for the prefix before.
    pub(super) fn insert(&mut self, prefix: Prefix, route: Route) -> bool {
        let (replaced, change) = {
            let prefer = prefer(&self.pool, &self.peers, &self.stale, &self.unreachable);
            match prefix {
                Prefix::V4(p) => self.v4.upsert(p, route, &prefer),
                Prefix::V6(p) => self.v6.upsert(p, route, &prefer),
            }
        };
        if let Some(old) = replaced {
            self.pool.release(old);
        }
        if change.best_changed() {
            self.mark_dirty(prefix, change);
        }
        replaced.is_none()
    }

    pub(super) fn withdraw(&mut self, peer: SourceId, prefix: Prefix) {
        if let Some(stale) = self.stale.get_mut(&peer) {
            stale.prefixes.remove(&prefix);
        }
        let removed = {
            let prefer = prefer(&self.pool, &self.peers, &self.stale, &self.unreachable);
            match prefix {
                Prefix::V4(p) => self.v4.remove(&p, peer, &prefer),
                Prefix::V6(p) => self.v6.remove(&p, peer, &prefer),
            }
        };
        let Some((attrs, change)) = removed else {
            return;
        };
        self.pool.release(attrs);
        if let Some(state) = self.peers.get_mut(&peer) {
            state.received[family_index(prefix.afi())] -= 1;
        }
        if change.best_changed() {
            self.mark_dirty(prefix, change);
        }
    }

    fn check_limits(&mut self, peer: SourceId, out: &mut Vec<(SourceId, PeerMsg)>) {
        let retry_after = self.config.max_prefix_restart;
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        let limits = [
            (Afi::IPV4, state.settings.max_prefixes_ipv4),
            (Afi::IPV6, state.settings.max_prefixes_ipv6),
        ];
        for (afi, limit) in limits {
            let Some(limit) = limit else { continue };
            let i = family_index(afi);
            let count = state.received[i];
            if count > limit {
                warn!(
                    peer,
                    ?afi,
                    count,
                    limit,
                    "maximum number of prefixes exceeded, closing session"
                );
                // RFC 4486 §4: AFI, SAFI and the upper bound.
                let mut data = BytesMut::with_capacity(7);
                data.put_u16(afi.0);
                data.put_u8(Safi::UNICAST.0);
                data.put_u32(limit);
                let notification = Notification::new(
                    error_code::CEASE,
                    cease_subcode::MAX_PREFIXES_REACHED,
                    data.freeze(),
                );
                state.torn_down = true;
                out.push((
                    peer,
                    PeerMsg::Teardown {
                        notification,
                        retry_after,
                    },
                ));
                return;
            }
            if !state.limit_warned[i] && u64::from(count) * 10 >= u64::from(limit) * 9 {
                state.limit_warned[i] = true;
                warn!(peer, ?afi, count, limit, "90% of the prefix limit reached");
            }
        }
    }
}
