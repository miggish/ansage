//! Answers for the control socket: summaries, routes, lookups.

use std::net::IpAddr;

use herald_bgp::wire::Afi;

use herald_bgp::wire::Prefix;

use herald_bgp::wire::Prefix4;

use herald_bgp::wire::Prefix6;

use super::{
    Rib, Stale,
    msg::{PeerRibStatus, Query, RibSummary, RouteInfo, RoutePage, Stats},
    table::Route,
};

impl Rib {
    pub fn stats(&self) -> Stats {
        Stats {
            prefixes_ipv4: self.v4.len(),
            prefixes_ipv6: self.v6.len(),
            attr_sets: self.pool.len(),
        }
    }

    #[cfg(test)]
    /// The best route of `prefix`: where it came from and its attributes.
    pub fn best_route(
        &self,
        prefix: &Prefix,
    ) -> Option<(super::SourceId, Vec<herald_bgp::wire::PathAttr>)> {
        let best = match prefix {
            Prefix::V4(p) => self.v4.best(p),
            Prefix::V6(p) => self.v6.best(p),
        }?;
        Some((best.source, self.pool.attrs(best.attrs)))
    }

    #[cfg(test)]
    /// Number of routes (all candidates) for `prefix`.
    pub fn route_count(&self, prefix: &Prefix) -> usize {
        match prefix {
            Prefix::V4(p) => self.v4.routes(p).len(),
            Prefix::V6(p) => self.v6.routes(p).len(),
        }
    }

    /// Answers a query; a requester that gave up is ignored.
    pub(super) fn query(&self, query: Query) {
        match query {
            Query::Summary(reply) => {
                let _ = reply.send(self.summary());
            }
            Query::Prefix { prefix, reply } => {
                let _ = reply.send(self.candidates(prefix));
            }
            Query::Longest { addr, reply } => {
                let routes = self
                    .longest_match(addr)
                    .map(|p| self.candidates(p))
                    .unwrap_or_default();
                let _ = reply.send(routes);
            }
            Query::Routes { afi, limit, reply } => {
                let mut best: Vec<(Prefix, Route)> = match afi {
                    Afi::IPV4 => self
                        .v4
                        .iter_best()
                        .take(limit)
                        .map(|(p, r)| (Prefix::V4(p), r))
                        .collect(),
                    Afi::IPV6 => self
                        .v6
                        .iter_best()
                        .take(limit)
                        .map(|(p, r)| (Prefix::V6(p), r))
                        .collect(),
                    _ => Vec::new(),
                };
                best.sort_unstable_by_key(|(p, _)| *p);
                let total = match afi {
                    Afi::IPV4 => self.v4.len(),
                    Afi::IPV6 => self.v6.len(),
                    _ => 0,
                };
                let routes = best
                    .into_iter()
                    .map(|(prefix, route)| self.route_info(prefix, route, true))
                    .collect();
                let _ = reply.send(RoutePage { total, routes });
            }
        }
    }

    /// All routes of `prefix`, the best first.
    pub(super) fn candidates(&self, prefix: Prefix) -> Vec<RouteInfo> {
        let routes = match prefix {
            Prefix::V4(p) => self.v4.routes(&p),
            Prefix::V6(p) => self.v6.routes(&p),
        };
        routes
            .iter()
            .enumerate()
            .map(|(i, route)| self.route_info(prefix, *route, i == 0))
            .collect()
    }

    /// The longest prefix in the RIB that contains `addr`: one lookup per
    /// prefix length, fine for a control command (no trie, Q8).
    pub fn longest_match(&self, addr: IpAddr) -> Option<Prefix> {
        match addr.to_canonical() {
            IpAddr::V4(a) => (0..=32).rev().find_map(|len| {
                let p = Prefix4::new(a, len).ok()?;
                self.v4.best(&p).map(|_| Prefix::V4(p))
            }),
            IpAddr::V6(a) => (0..=128).rev().find_map(|len| {
                let p = Prefix6::new(a, len).ok()?;
                self.v6.best(&p).map(|_| Prefix::V6(p))
            }),
        }
    }

    pub fn summary(&self) -> RibSummary {
        let stale = |peer| {
            self.stale
                .get(&peer)
                .map_or(0, |s: &Stale| s.prefixes.len())
        };
        let mut peers: Vec<PeerRibStatus> = self
            .peers
            .iter()
            .map(|(&peer, state)| {
                let advertised_ipv6 = state
                    .out
                    .advertised
                    .keys()
                    .filter(|p| p.afi() == Afi::IPV6)
                    .count();
                PeerRibStatus {
                    peer,
                    received_ipv4: state.received[0],
                    received_ipv6: state.received[1],
                    advertised_ipv4: state.out.advertised.len() - advertised_ipv6,
                    advertised_ipv6,
                    pending: state.out.dirty.len(),
                    initial_sync_done: state.out.eor_pending.is_empty(),
                    torn_down: state.torn_down,
                    stale: stale(peer),
                }
            })
            .collect();
        // Peers that are down but still have stale routes.
        for (&peer, s) in &self.stale {
            if self.peers.contains_key(&peer) {
                continue;
            }
            let ipv6 = s.prefixes.iter().filter(|p| p.afi() == Afi::IPV6).count();
            peers.push(PeerRibStatus {
                peer,
                received_ipv4: (s.prefixes.len() - ipv6) as u32,
                received_ipv6: ipv6 as u32,
                advertised_ipv4: 0,
                advertised_ipv6: 0,
                pending: 0,
                initial_sync_done: false,
                torn_down: false,
                stale: s.prefixes.len(),
            });
        }
        peers.sort_unstable_by_key(|p| p.peer);
        RibSummary {
            stats: self.stats(),
            own: self.config.announce.clone(),
            peers,
            drained: self.drained,
        }
    }

    fn route_info(&self, prefix: Prefix, route: Route, best: bool) -> RouteInfo {
        RouteInfo {
            prefix,
            source: route.source,
            best,
            attrs: self.pool.attrs(route.attrs),
            mp_next_hop: self.pool.mp_next_hop(route.attrs).copied(),
            unreachable: self
                .pool
                .gateway(route.attrs, self.source_oif(route.source))
                .is_some_and(|hop| self.unreachable.contains(&hop)),
        }
    }
}
