//! `ansage test`: what ansage does with one route, step by step: import,
//! best path, kernel, and the export to every neighbor. The same checks,
//! filters and decisions as for real routes; nothing changes.

use std::{collections::BTreeMap, net::IpAddr};

use ansage_bgp::wire::{AsPath, LargeCommunity, NextHop, Origin, PathAttr, Prefix};

use super::{
    Rib,
    export::SessionView,
    family_index,
    import::reserved,
    msg::{PeerSettings, RouteInfo},
    prefer,
    table::{LOCAL, Prefer, Route, SourceId},
};
use crate::{
    config::NeighborRole,
    policy::{self, Import, RouteView},
};

/// What to test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestQuery {
    /// A route as if the neighbor at `from` sent it.
    Route(TestRoute),
    /// The route the RIB has for exactly this prefix.
    Prefix(Prefix),
    /// The route of the longest prefix containing this address.
    Address(IpAddr),
}

/// A route a neighbor could send. Unset: the AS path is the neighbor's AS
/// (empty over iBGP), the next hop the neighbor's address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestRoute {
    pub from: Option<IpAddr>,
    pub prefix: Option<Prefix>,
    pub as_path: Option<Vec<u32>>,
    pub communities: Vec<u32>,
    pub large_communities: Vec<LargeCommunity>,
    pub med: Option<u32>,
    pub next_hop: Option<IpAddr>,
    pub otc: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    pub prefix: Prefix,
    /// The tested route as the neighbor sends it.
    pub tested: Option<RouteInfo>,
    pub import: Option<ImportTrace>,
    /// Every route of the prefix (with the tested one in place), best first.
    pub candidates: Vec<RouteInfo>,
    /// The tested route would be the best one.
    pub tested_is_best: Option<bool>,
    pub kernel: KernelTrace,
    /// One per configured neighbor, by ID.
    pub exports: Vec<ExportTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportTrace {
    pub accepted: bool,
    pub reason: &'static str,
    pub filter: Option<String>,
    /// Index of the filter rule that decided.
    pub rule: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelTrace {
    pub installed: bool,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportTrace {
    pub peer: SourceId,
    pub address: Option<IpAddr>,
    pub role: Option<NeighborRole>,
    /// Session up; otherwise both families and next hops are assumed.
    pub up: bool,
    pub sent: bool,
    pub reason: &'static str,
    pub filter: Option<String>,
    pub rule: Option<usize>,
    /// What goes out (without NEXT_HOP).
    pub attrs: Vec<PathAttr>,
}

impl Rib {
    /// Answers `ansage test`. Only the attribute pool changes, and only for
    /// the time of the call.
    pub fn trace(&mut self, query: TestQuery) -> Result<Trace, String> {
        match query {
            TestQuery::Route(route) => self.trace_route(route),
            TestQuery::Prefix(prefix) => Ok(self.trace_existing(prefix)),
            TestQuery::Address(addr) => {
                let prefix = self
                    .longest_match(addr)
                    .ok_or_else(|| format!("no route contains {addr}"))?;
                Ok(self.trace_existing(prefix))
            }
        }
    }

    fn trace_existing(&self, prefix: Prefix) -> Trace {
        let best = self.best(prefix);
        let kernel = match best {
            None => KernelTrace::no("no route"),
            Some(_) if self.fib_next_hop(&prefix).is_some() => KernelTrace {
                installed: true,
                reason: "installed",
            },
            Some(route) => self.kernel_reason(prefix, route),
        };
        Trace {
            prefix,
            tested: None,
            import: None,
            candidates: self.candidates(prefix),
            tested_is_best: None,
            kernel,
            exports: self.trace_exports(prefix, best),
        }
    }

    fn trace_route(&mut self, test: TestRoute) -> Result<Trace, String> {
        let from = test
            .from
            .ok_or("a test route needs the neighbor it comes from")?;
        let prefix = test.prefix.ok_or("a test route needs a prefix")?;
        let (peer, settings) = self
            .config
            .peers
            .iter()
            .find(|(_, s)| s.address == Some(from))
            .map(|(&id, s)| (id, s.clone()))
            .ok_or_else(|| format!("{from} is not a configured neighbor"))?;
        let (attrs, mp_next_hop) = self.test_attrs(&settings, prefix, &test)?;
        let tested = RouteInfo {
            prefix,
            source: peer,
            best: false,
            attrs: attrs.clone(),
            mp_next_hop,
            unreachable: false,
        };
        let mut trace = Trace {
            prefix,
            tested: Some(tested),
            import: None,
            candidates: self.candidates(prefix),
            tested_is_best: Some(false),
            kernel: KernelTrace::no("not imported"),
            exports: Vec::new(),
        };
        let filter = match &settings.import {
            Import::Filter(f) => Some(f.clone()),
            _ => None,
        };
        let rejected = |reason, rule| ImportTrace {
            accepted: false,
            reason,
            filter: filter.as_ref().map(|f| f.name.clone()),
            rule,
        };
        if reserved(&prefix) {
            trace.import = Some(rejected("multicast or reserved prefix", None));
            return Ok(trace);
        }
        if settings.import == Import::None {
            trace.import = Some(rejected("import none", None));
            return Ok(trace);
        }
        let stored = match self.eligible(peer, &attrs, false, mp_next_hop.as_ref()) {
            Ok(stored) => stored.into_owned(),
            Err(reason) => {
                trace.import = Some(rejected(reason, None));
                return Ok(trace);
            }
        };
        let (stored, import) = match &filter {
            None => (
                stored,
                ImportTrace {
                    accepted: true,
                    reason: "import all",
                    filter: None,
                    rule: None,
                },
            ),
            Some(filter) => {
                let view = RouteView {
                    prefix,
                    source: self.policy_source(peer),
                    attrs: &stored,
                    local_asn: self.config.local_asn,
                };
                let verdict = filter.verdict(&view);
                let Some(rule) = verdict.rule.filter(|_| verdict.accept) else {
                    let reason = if verdict.rule.is_some() {
                        "rejected by the import filter"
                    } else {
                        "no rule of the import filter matches"
                    };
                    trace.import = Some(rejected(reason, verdict.rule));
                    return Ok(trace);
                };
                let mut changed = stored;
                policy::apply(&filter.rules[rule], &mut changed, self.config.local_asn);
                let import = ImportTrace {
                    accepted: true,
                    reason: "accepted by the import filter",
                    filter: Some(filter.name.clone()),
                    rule: Some(rule),
                };
                (changed, import)
            }
        };
        trace.import = Some(import);

        // Best path with the tested route in place of what the neighbor has
        // now; the pool reference is dropped again below.
        let id = self.pool.intern(&stored, mp_next_hop.as_ref());
        let tested = Route {
            source: peer,
            attrs: id,
        };
        let mut routes: Vec<Route> = self
            .routes(prefix)
            .iter()
            .filter(|r| r.source != peer)
            .copied()
            .collect();
        routes.push(tested);
        let best = prefer(&self.pool, &self.peers, &self.stale, &self.unreachable).best(&routes);
        let best_route = routes.remove(best);
        trace.candidates = std::iter::once(self.route_info(prefix, best_route, true))
            .chain(routes.iter().map(|r| self.route_info(prefix, *r, false)))
            .collect();
        trace.tested_is_best = Some(best_route == tested);
        trace.kernel = if best_route == tested {
            self.kernel_reason(prefix, tested)
        } else {
            KernelTrace::no("not the best route")
        };
        trace.exports = self.trace_exports(prefix, Some(best_route));
        self.pool.release(id);
        Ok(trace)
    }

    /// The tested route's attributes and MP next hop, with the defaults.
    fn test_attrs(
        &self,
        settings: &PeerSettings,
        prefix: Prefix,
        test: &TestRoute,
    ) -> Result<(Vec<PathAttr>, Option<NextHop>), String> {
        let ibgp = settings.asn == self.config.local_asn;
        let path = test
            .as_path
            .clone()
            .unwrap_or_else(|| if ibgp { Vec::new() } else { vec![settings.asn] });
        let mut attrs = vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence(path)),
        ];
        let next_hop = test.next_hop.or(settings.address).ok_or("no next hop")?;
        let mp_next_hop = match (prefix, next_hop) {
            (Prefix::V4(_), IpAddr::V4(addr)) => {
                attrs.push(PathAttr::NextHop(addr));
                None
            }
            // RFC 8950 for IPv4 routes.
            (_, IpAddr::V6(global)) => Some(NextHop::V6 {
                global,
                link_local: None,
            }),
            (Prefix::V6(_), IpAddr::V4(_)) => {
                return Err("an IPv6 route needs an IPv6 next hop (--next-hop)".into());
            }
        };
        if let Some(med) = test.med {
            attrs.push(PathAttr::MultiExitDisc(med));
        }
        if !test.communities.is_empty() {
            attrs.push(PathAttr::Communities(test.communities.clone()));
        }
        if !test.large_communities.is_empty() {
            let mut list = test.large_communities.clone();
            list.sort_unstable();
            list.dedup();
            attrs.push(PathAttr::LargeCommunities(list));
        }
        if let Some(asn) = test.otc {
            attrs.push(PathAttr::OnlyToCustomer(asn));
        }
        attrs.sort_by_key(PathAttr::type_code);
        Ok((attrs, mp_next_hop))
    }

    fn best(&self, prefix: Prefix) -> Option<Route> {
        match prefix {
            Prefix::V4(p) => self.v4.best(&p),
            Prefix::V6(p) => self.v6.best(&p),
        }
    }

    fn routes(&self, prefix: Prefix) -> &[Route] {
        match prefix {
            Prefix::V4(p) => self.v4.routes(&p),
            Prefix::V6(p) => self.v6.routes(&p),
        }
    }

    /// Why the best route `route` of `prefix` would (not) be installed; the
    /// next hop's reachability is not checked.
    fn kernel_reason(&self, prefix: Prefix, route: Route) -> KernelTrace {
        if route.source == LOCAL {
            KernelTrace::no("our own prefix")
        } else if !self.config.install_families[family_index(prefix.afi())] {
            KernelTrace::no("no [kernel] for this family")
        } else if self.protected.contains(&prefix) {
            KernelTrace::no("one of our own prefixes")
        } else if !self
            .config
            .peers
            .get(&route.source)
            .is_some_and(|s| s.install)
        {
            KernelTrace::no("install = false for this neighbor")
        } else {
            KernelTrace {
                installed: true,
                reason: "would be installed (if the next hop is reachable)",
            }
        }
    }

    fn trace_exports(&self, prefix: Prefix, best: Option<Route>) -> Vec<ExportTrace> {
        let peers: BTreeMap<SourceId, &PeerSettings> =
            self.config.peers.iter().map(|(&id, s)| (id, s)).collect();
        peers
            .into_iter()
            .map(|(peer, settings)| {
                let (session, settings, up) = match self.peers.get(&peer) {
                    Some(state) => (SessionView::of(state), &state.settings, true),
                    None => (
                        SessionView {
                            ibgp: settings.asn == self.config.local_asn,
                            families: [true; 2],
                            next_hops: [true; 2],
                        },
                        settings,
                        false,
                    ),
                };
                let decision = self.decide(peer, settings, session, prefix, best);
                ExportTrace {
                    peer,
                    address: settings.address,
                    role: settings.role,
                    up,
                    sent: decision.attrs.is_some(),
                    reason: decision.reason,
                    filter: match &settings.export {
                        policy::Export::Filter(f) => Some(f.name.clone()),
                        _ => None,
                    },
                    rule: decision.rule,
                    attrs: decision.attrs.unwrap_or_default(),
                }
            })
            .collect()
    }
}

impl KernelTrace {
    fn no(reason: &'static str) -> Self {
        Self {
            installed: false,
            reason,
        }
    }
}
