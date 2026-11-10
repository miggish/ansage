//! Routes pe        for prefix in self.prefixes_of(source) { prefix, best
//! first.

use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet, hash_map::Entry},
    hash::Hash,
    net::{IpAddr, Ipv4Addr},
};

use super::pool::{AttrId, AttrPool};
use crate::fib::Gateway;

/// Where a route came from: [`LOCAL`] for our own prefixes, otherwise a peer.
pub type SourceId = u16;
pub const LOCAL: SourceId = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub source: SourceId,
    pub attrs: AttrId,
}

/// Almost every prefix has a single route, so that one is stored inline.
/// `Box<Vec>` instead of `Vec` keeps this at 16 bytes (a thin pointer)
/// rather than 32: it is stored once per prefix, a million times.
#[derive(Debug)]
#[allow(clippy::box_collection)]
enum Routes {
    One(Route),
    Many(Box<Vec<Route>>),
}

impl Routes {
    fn as_slice(&self) -> &[Route] {
        match self {
            Routes::One(route) => std::slice::from_ref(route),
            Routes::Many(routes) => routes,
        }
    }

    fn best(&self) -> Route {
        self.as_slice()[0]
    }
}

/// The best route of a prefix before and after a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub before: Option<Route>,
    pub after: Option<Route>,
}

impl Change {
    pub fn best_changed(&self) -> bool {
        self.before != self.after
    }
}

/// Picks the preferred route.
pub trait Prefer {
    /// Index of the best of `routes` (never empty).
    fn best(&self, routes: &[Route]) -> usize;
}

pub struct Table<P> {
    map: HashMap<P, Routes>,
}

impl<P> Default for Table<P> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<P: Copy + Eq + Hash> Table<P> {
    pub fn best(&self, prefix: &P) -> Option<Route> {
        self.map.get(prefix).map(Routes::best)
    }

    pub fn routes(&self, prefix: &P) -> &[Route] {
        self.map.get(prefix).map_or(&[], Routes::as_slice)
    }

    /// Number of prefixes.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Prefixes with their best route.
    pub fn iter_best(&self) -> impl Iterator<Item = (P, Route)> + '_ {
        self.map.iter().map(|(p, routes)| (*p, routes.best()))
    }

    /// Inserts the route of `route.source`, replacing that source's previous
    /// route. Returns the replaced attribute set (to release) and the change.
    pub fn upsert(
        &mut self,
        prefix: P,
        route: Route,
        prefer: &impl Prefer,
    ) -> (Option<AttrId>, Change) {
        match self.map.entry(prefix) {
            Entry::Vacant(entry) => {
                entry.insert(Routes::One(route));
                let change = Change {
                    before: None,
                    after: Some(route),
                };
                (None, change)
            }
            Entry::Occupied(mut entry) => {
                let routes = entry.get_mut();
                let before = routes.best();
                let replaced = match routes {
                    Routes::One(old) if old.source == route.source => {
                        Some(std::mem::replace(old, route).attrs)
                    }
                    Routes::One(old) => {
                        *routes = Routes::Many(Box::new(vec![*old, route]));
                        None
                    }
                    Routes::Many(list) => {
                        match list.iter_mut().find(|r| r.source == route.source) {
                            Some(old) => Some(std::mem::replace(old, route).attrs),
                            None => {
                                list.push(route);
                                None
                            }
                        }
                    }
                };
                select_best(routes, prefer);
                let change = Change {
                    before: Some(before),
                    after: Some(routes.best()),
                };
                (replaced, change)
            }
        }
    }

    /// Removes the route of `source`. Returns its attribute set (to release)
    /// and the change; `None` if the source had no route for the prefix.
    pub fn remove(
        &mut self,
        prefix: &P,
        source: SourceId,
        prefer: &impl Prefer,
    ) -> Option<(AttrId, Change)> {
        let Entry::Occupied(mut entry) = self.map.entry(*prefix) else {
            return None;
        };
        let before = entry.get().best();
        let removed = match entry.get_mut() {
            Routes::One(route) if route.source == source => {
                let attrs = route.attrs;
                entry.remove();
                return Some((
                    attrs,
                    Change {
                        before: Some(before),
                        after: None,
                    },
                ));
            }
            Routes::One(_) => return None,
            Routes::Many(list) => {
                let index = list.iter().position(|r| r.source == source)?;
                list.swap_remove(index).attrs
            }
        };
        let routes = entry.get_mut();
        if let Routes::Many(list) = routes
            && list.len() == 1
        {
            *routes = Routes::One(list[0]);
        }
        select_best(routes, prefer);
        Some((
            removed,
            Change {
                before: Some(before),
                after: Some(routes.best()),
            },
        ))
    }

    /// Prefixes `source` has a route for.
    pub fn prefixes_of(&self, source: SourceId) -> Vec<P> {
        self.map
            .iter()
            .filter(|(_, routes)| routes.as_slice().iter().any(|r| r.source == source))
            .map(|(p, _)| *p)
            .collect()
    }

    /// Runs the decision process again for every prefix with a route that
    /// `affected` selects, and reports each such prefix with its best route
    /// before and after (equal when it did not change).
    pub fn rerank(
        &mut self,
        affected: impl Fn(&Route) -> bool,
        prefer: &impl Prefer,
        mut report: impl FnMut(P, Change),
    ) {
        for (prefix, routes) in &mut self.map {
            if !routes.as_slice().iter().any(&affected) {
                continue;
            }
            let before = routes.best();
            select_best(routes, prefer);
            report(
                *prefix,
                Change {
                    before: Some(before),
                    after: Some(routes.best()),
                },
            );
        }
    }

    /// Removes every route of `source`, calling `removed` for each.
    pub fn remove_source(
        &mut self,
        source: SourceId,
        prefer: &impl Prefer,
        mut removed: impl FnMut(P, AttrId, Change),
    ) {
        for prefix in self.prefixes_of(source) {
            if let Some((attrs, change)) = self.remove(&prefix, source, prefer) {
                removed(prefix, attrs, change);
            }
        }
    }
}

/// Moves the preferred route to the front.
fn select_best(routes: &mut Routes, prefer: &impl Prefer) {
    if let Routes::Many(list) = routes {
        let best = prefer.best(list);
        list.swap(0, best);
    }
}

/// Per-peer facts used in best path selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceInfo {
    pub ibgp: bool,
    pub bgp_id: Ipv4Addr,
    pub addr: IpAddr,
    /// Interface of the session when the neighbor is on a shared link.
    pub oif: Option<u32>,
}

/// RFC 4271 §9.1.2 decision process, without IGP cost (ansage has no IGP).
pub struct DecisionProcess<'a, F> {
    pub pool: &'a AttrPool,
    pub info: F,
    /// Next hops the kernel cannot reach (only known with `[kernel]`).
    pub unreachable: &'a HashSet<Gateway>,
}

/// LOCAL_PREF of routes without one.
const DEFAULT_LOCAL_PREF: u32 = 100;

impl<'a, F: Fn(SourceId) -> SourceInfo> Prefer for DecisionProcess<'a, F> {
    /// Eliminates candidates step by step in the order of RFC 4271 §9.1.2.
    /// A pairwise comparison cannot do this: MED only compares routes from
    /// the same neighbor AS, which makes it non-transitive (§9.1.2.2 c).
    fn best(&self, routes: &[Route]) -> usize {
        if routes.len() == 1 {
            return 0;
        }
        let summary = |i: usize| self.pool.summary(routes[i].attrs);
        let info = |i: usize| (self.info)(routes[i].source);
        let mut alive: Vec<usize> = (0..routes.len()).collect();

        // Our own prefixes beat anything learned.
        keep_min(&mut alive, |i| routes[i].source != LOCAL);
        // §9.1.2.1: a route whose next hop cannot be reached is not usable.
        // Ranked last rather than dropped: such a best route is never
        // installed, and learned routes are never exported.
        if !self.unreachable.is_empty() {
            keep_min(&mut alive, |i| {
                self.pool
                    .gateway(routes[i].attrs, info(i).oif)
                    .is_some_and(|hop| self.unreachable.contains(&hop))
            });
        }
        // §9.1.1: degree of preference. LOCAL_PREF from an eBGP neighbor is
        // dropped on receipt (RFC 7606 §7.5), so on an eBGP route it was set
        // by our import filter. RFC 8326 §4: GRACEFUL_SHUTDOWN means
        // LOCAL_PREF 0, also on eBGP, so traffic moves off a neighbor that is
        // about to go away.
        keep_min(&mut alive, |i| {
            let local_pref = if summary(i).graceful_shutdown {
                0
            } else {
                summary(i).local_pref.unwrap_or(DEFAULT_LOCAL_PREF)
            };
            Reverse(local_pref)
        });
        // §9.1.2.2 a) shortest AS path, b) lowest ORIGIN.
        keep_min(&mut alive, |i| summary(i).as_path_len);
        keep_min(&mut alive, |i| summary(i).origin as u8);
        // c) drop a route if another route from the same neighbor AS has a
        // lower MED; a missing MED is the lowest value.
        let med = |i: usize| summary(i).med.unwrap_or(0);
        let candidates = alive.clone();
        alive.retain(|&i| {
            !candidates
                .iter()
                .any(|&j| summary(j).neighbor_as == summary(i).neighbor_as && med(j) < med(i))
        });
        // d) eBGP over iBGP, e) (IGP cost: ansage has none), f) lowest BGP
        // identifier, g) lowest peer address; last, the source for determinism.
        keep_min(&mut alive, |i| info(i).ibgp);
        keep_min(&mut alive, |i| info(i).bgp_id);
        keep_min(&mut alive, |i| info(i).addr);
        keep_min(&mut alive, |i| routes[i].source);
        alive[0]
    }
}

/// Keeps the candidates with the smallest key.
fn keep_min<K: Ord>(alive: &mut Vec<usize>, key: impl Fn(usize) -> K) {
    if let Some(min) = alive.iter().map(|&i| key(i)).min() {
        alive.retain(|&i| key(i) == min);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ansage_bgp::wire::{AsPath, Origin, PathAttr};

    struct Pool {
        pool: AttrPool,
    }

    impl Pool {
        fn new() -> Self {
            Self {
                pool: AttrPool::default(),
            }
        }

        fn set(&mut self, path: &[u32], local_pref: Option<u32>, med: Option<u32>) -> AttrId {
            let mut attrs = vec![
                PathAttr::Origin(Origin::Igp),
                PathAttr::AsPath(AsPath::sequence(path.to_vec())),
            ];
            attrs.extend(med.map(PathAttr::MultiExitDisc));
            attrs.extend(local_pref.map(PathAttr::LocalPref));
            self.pool.intern(&attrs, None)
        }
    }

    fn info(source: SourceId) -> SourceInfo {
        SourceInfo {
            // Sources 10 and above are iBGP in these tests.
            ibgp: source >= 10,
            bgp_id: Ipv4Addr::new(203, 0, 113, source as u8),
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, source as u8)),
            oif: None,
        }
    }

    fn route(source: SourceId, attrs: AttrId) -> Route {
        Route { source, attrs }
    }

    fn pick(prefer: &impl Prefer, routes: &[Route]) -> Route {
        routes[prefer.best(routes)]
    }

    #[test]
    fn shorter_path_wins_and_removal_falls_back() {
        let mut p = Pool::new();
        let long = p.set(&[64501, 3356, 1299], None, None);
        let short = p.set(&[64502, 1299], None, None);
        let prefer = DecisionProcess {
            unreachable: &HashSet::new(),
            pool: &p.pool,
            info,
        };
        let mut table = Table::default();

        let (_, change) = table.upsert(1u32, route(1, long), &prefer);
        assert_eq!(change.after, Some(route(1, long)));
        let (_, change) = table.upsert(1, route(2, short), &prefer);
        assert!(change.best_changed());
        assert_eq!(table.best(&1), Some(route(2, short)));

        let (attrs, change) = table.remove(&1, 2, &prefer).unwrap();
        assert_eq!(attrs, short);
        assert_eq!(change.after, Some(route(1, long)));
        let (_, change) = table.remove(&1, 1, &prefer).unwrap();
        assert_eq!(change.after, None);
        assert!(table.is_empty());
    }

    #[test]
    fn local_routes_win() {
        let mut p = Pool::new();
        let own = p.set(&[], None, None);
        let learned = p.set(&[64501], None, None);
        let prefer = DecisionProcess {
            unreachable: &HashSet::new(),
            pool: &p.pool,
            info,
        };
        let mut table = Table::default();
        table.upsert(1u32, route(1, learned), &prefer);
        table.upsert(1, route(LOCAL, own), &prefer);
        assert_eq!(table.best(&1).unwrap().source, LOCAL);
    }

    #[test]
    fn local_pref_beats_path_length() {
        let mut p = Pool::new();
        let high_lp_long = p.set(&[64501, 1, 2], Some(200), None);
        let short = p.set(&[64502], None, None);
        let low_lp_short = p.set(&[64503], Some(50), None);
        let long = p.set(&[64504, 1, 2], None, None);
        let prefer = DecisionProcess {
            unreachable: &HashSet::new(),
            pool: &p.pool,
            info,
        };
        // From iBGP source 10, or set by an import filter on eBGP source 1.
        for source in [10, 1] {
            let (a, b) = (route(source, high_lp_long), route(2, short));
            assert_eq!(pick(&prefer, &[a, b]), a);
        }
        // Below the default of 100, a shorter path loses.
        let (a, b) = (route(3, low_lp_short), route(4, long));
        assert_eq!(pick(&prefer, &[a, b]), b);
    }

    #[test]
    fn med_only_within_the_same_neighbor_as() {
        let mut p = Pool::new();
        let low_med = p.set(&[64501, 1], None, Some(10));
        let high_med = p.set(&[64501, 2], None, Some(50));
        let other_as = p.set(&[64502, 3], None, Some(90));
        let prefer = DecisionProcess {
            unreachable: &HashSet::new(),
            pool: &p.pool,
            info,
        };
        let (a, b) = (route(2, low_med), route(1, high_med));
        assert_eq!(pick(&prefer, &[a, b]), a);
        // Different neighbor AS: MED ignored, lower BGP ID (source 1) wins.
        let (a, b) = (route(1, other_as), route(2, low_med));
        assert_eq!(pick(&prefer, &[a, b]), a);
    }

    #[test]
    fn med_elimination_does_not_depend_on_order() {
        // RFC 4271 §9.1.2.2: R1 loses to R3 on MED (same neighbor AS 100),
        // then R2 wins over R3 on the lower BGP identifier.
        let mut p = Pool::new();
        let r1 = p.set(&[100, 9], None, Some(50));
        let r2 = p.set(&[200, 9], None, Some(0));
        let r3 = p.set(&[100, 8], None, Some(10));
        let prefer = DecisionProcess {
            unreachable: &HashSet::new(),
            pool: &p.pool,
            info,
        };
        let routes = [route(1, r1), route(2, r2), route(3, r3)];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let list: Vec<Route> = order.iter().map(|&i| routes[i]).collect();
            assert_eq!(pick(&prefer, &list), routes[1], "order {order:?}");
        }
    }

    #[test]
    fn replacing_and_removing_a_source() {
        let mut p = Pool::new();
        let a = p.set(&[64501], None, None);
        let b = p.set(&[64501, 1], None, None);
        let prefer = DecisionProcess {
            unreachable: &HashSet::new(),
            pool: &p.pool,
            info,
        };
        let mut table = Table::default();
        table.upsert(1u32, route(1, b), &prefer);
        let (replaced, _) = table.upsert(1, route(1, a), &prefer);
        assert_eq!(replaced, Some(b));
        assert_eq!(table.routes(&1).len(), 1);

        table.upsert(2, route(1, a), &prefer);
        table.upsert(2, route(2, b), &prefer);
        let mut removed = Vec::new();
        table.remove_source(1, &prefer, |prefix, attrs, change| {
            removed.push((prefix, attrs, change.after))
        });
        removed.sort_by_key(|r| r.0);
        assert_eq!(removed, [(1, a, None), (2, a, Some(route(2, b)))]);
    }

    #[test]
    fn unreachable_next_hop_ranks_last_and_rerank_follows() {
        let mut p = Pool::new();
        let via = |p: &mut Pool, path: &[u32], hop: [u8; 4]| {
            let attrs = vec![
                PathAttr::Origin(Origin::Igp),
                PathAttr::AsPath(AsPath::sequence(path.to_vec())),
                PathAttr::NextHop(Ipv4Addr::from(hop)),
            ];
            p.pool.intern(&attrs, None)
        };
        let short = via(&mut p, &[64501], [10, 0, 0, 1]);
        let long = via(&mut p, &[64502, 1, 2], [10, 0, 0, 2]);
        let mut unreachable = HashSet::new();
        let mut table = Table::default();
        {
            let prefer = DecisionProcess {
                unreachable: &unreachable,
                pool: &p.pool,
                info,
            };
            table.upsert(1u32, route(1, short), &prefer);
            table.upsert(1, route(2, long), &prefer);
            table.upsert(2, route(2, long), &prefer);
            assert_eq!(table.best(&1), Some(route(1, short)));
        }
        unreachable.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)).into());
        let prefer = DecisionProcess {
            unreachable: &unreachable,
            pool: &p.pool,
            info,
        };
        let mut reports = Vec::new();
        table.rerank(
            |r| r.attrs == short,
            &prefer,
            |prefix, change| reports.push((prefix, change.best_changed())),
        );
        assert_eq!(reports, [(1, true)], "prefix 2 has no route via 10.0.0.1");
        assert_eq!(table.best(&1), Some(route(2, long)));
    }

    #[test]
    fn graceful_shutdown_loses_against_a_longer_path() {
        let mut p = Pool::new();
        let gshut = |p: &mut Pool, path: &[u32], community: bool| {
            let mut attrs = vec![
                PathAttr::Origin(Origin::Igp),
                PathAttr::AsPath(AsPath::sequence(path.to_vec())),
            ];
            if community {
                attrs.push(PathAttr::Communities(vec![
                    ansage_bgp::wire::GRACEFUL_SHUTDOWN,
                ]));
            }
            p.pool.intern(&attrs, None)
        };
        let draining = gshut(&mut p, &[64501], true);
        let long = gshut(&mut p, &[64502, 1, 2], false);
        let prefer = DecisionProcess {
            unreachable: &HashSet::new(),
            pool: &p.pool,
            info,
        };
        let routes = [route(1, draining), route(2, long)];
        assert_eq!(pick(&prefer, &routes), route(2, long));
        // Only route: still used.
        assert_eq!(pick(&prefer, &routes[..1]), route(1, draining));
    }
}
