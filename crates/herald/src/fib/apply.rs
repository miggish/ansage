//! Turning wanted routes into kernel operations: nexthop objects, routes,
//! results.

use herald_netlink::RTPROT_BGP;

use herald_netlink::Route;

use herald_bgp::wire::Prefix;
use tracing::warn;

use super::{
    Fib, NEXTHOP_IDS, PROBE_ID, SWEEP_INTERVAL, Settings,
    entry::{Entry, Gateway, Hop},
    kernel::{Kernel, Op},
    status::RouteState,
};

/// What an operation was for, to apply its result.
#[derive(Debug, Clone, Copy)]
pub(super) enum Target {
    Hop(u32),
    Route(Prefix),
    /// Nothing to update (a nexthop delete, the old copy of a moved route).
    None,
}

#[derive(Default)]
pub(super) struct Plan {
    /// Nexthop objects to create: before the routes that use them.
    pub(super) hops: Vec<(Op, Target)>,
    pub(super) routes: Vec<(Op, Target)>,
    /// Hops whose last user may be gone: deleted after the routes.
    released: Vec<u32>,
}

/// The route herald installs for `prefix` (through nexthop `nh_id`), or
/// with `None` the match for deleting it whatever its next hop.
pub(super) fn route_in(settings: Settings, prefix: Prefix, nh_id: Option<u32>) -> Route {
    let mut route = Route::via_nexthop(prefix, 0, settings.table, RTPROT_BGP, settings.metric);
    route.nh_id = nh_id;
    route
}

impl<K: Kernel> Fib<K> {
    /// The hop for `gw`, created (and resolved) if new; takes a reference.
    pub(super) fn acquire(&mut self, gw: Gateway, plan: &mut Plan) -> u32 {
        if let Some(&id) = self.by_addr.get(&gw) {
            self.hops.get_mut(&id).expect("indexed").refs += 1;
            return id;
        }
        let id = self.alloc_id();
        let via = self.resolve(gw, None);
        let hop = Hop {
            gw,
            via,
            installed: via.is_some(),
            refs: 1,
            reported: via.is_none(),
        };
        match hop.nexthop(id) {
            Some(nh) => plan.hops.push((Op::AddNexthop(nh), Target::Hop(id))),
            None => self.reports.push((gw, false)),
        }
        self.hops.insert(id, hop);
        self.by_addr.insert(gw, id);
        id
    }

    /// A free id: not used by a hop nor by the earlier run.
    fn alloc_id(&mut self) -> u32 {
        if let Some(id) = self.free_ids.pop() {
            return id;
        }
        loop {
            let id = self.next_id;
            self.next_id = if id + 1 >= PROBE_ID {
                *NEXTHOP_IDS.start()
            } else {
                id + 1
            };
            if !self.hops.contains_key(&id) && !self.adopted_ids.contains(&id) {
                return id;
            }
        }
    }

    pub(super) fn release(&mut self, id: u32, plan: &mut Plan) {
        let hop = self.hops.get_mut(&id).expect("referenced hop exists");
        hop.refs -= 1;
        if hop.refs == 0 {
            plan.released.push(id);
        }
    }

    pub(super) fn forget_hop(&mut self, id: u32) {
        if let Some(hop) = self.hops.remove(&id) {
            self.by_addr.remove(&hop.gw);
            self.free_ids.push(id);
        }
    }

    /// Adds the operation that makes the kernel match `hop` for `prefix`
    /// (whose kernel state is `old`) and records the expected outcome.
    pub(super) fn plan_route(
        &mut self,
        prefix: Prefix,
        old: Option<RouteState>,
        hop: Option<u32>,
        plan: &mut Plan,
    ) {
        let shadowed = self.local.contains(&prefix);
        let usable = hop.filter(|id| !shadowed && self.hops[id].usable());
        let target = Target::Route(prefix);
        if let Some(id) = usable {
            let route = route_in(self.settings, prefix, Some(id));
            plan.routes.push((Op::AddRoute(route), target));
            self.set_entry(prefix, Some(Entry::new(hop, RouteState::Installed)));
            return;
        }
        // Nothing usable: whatever the kernel has for it must go.
        let in_kernel = matches!(old, Some(RouteState::Installed | RouteState::Failed));
        if in_kernel {
            let route = route_in(self.settings, prefix, None);
            plan.routes.push((Op::DeleteRoute(route), target));
        }
        let entry = match (hop, in_kernel) {
            (None, false) => None,
            // Until the delete is confirmed.
            (_, true) => Some(Entry::new(hop, RouteState::Failed)),
            (Some(_), false) => Some(Entry::new(
                hop,
                if shadowed {
                    RouteState::Shadowed
                } else {
                    RouteState::Unresolved
                },
            )),
        };
        self.set_entry(prefix, entry);
    }

    pub(super) fn execute(&mut self, mut plan: Plan) {
        // Hops nobody uses any more; a hop released and acquired again in
        // the same batch is still in use.
        let mut deletes = Vec::new();
        for id in std::mem::take(&mut plan.released) {
            let Some(hop) = self.hops.get(&id) else {
                continue;
            };
            // An unreachable one stays watched for the RIB.
            if hop.refs > 0 || hop.reported {
                continue;
            }
            if hop.installed {
                deletes.push((Op::DeleteNexthop(id), Target::None));
            }
            self.forget_hop(id);
        }
        let all: Vec<(Op, Target)> = plan
            .hops
            .into_iter()
            .chain(plan.routes)
            .chain(deletes)
            .collect();
        if all.is_empty() {
            return;
        }
        let ops: Vec<Op> = all.iter().map(|(op, _)| op.clone()).collect();
        let results = self.kernel.apply(&ops);
        let mut failed = 0;
        let mut first = None;
        for ((op, target), result) in all.iter().zip(results) {
            let deleting = matches!(op, Op::DeleteRoute(_) | Op::DeleteNexthop(_));
            let result = match result {
                Err(err) if deleting && err.is_not_found() => Ok(()),
                other => other,
            };
            if let Err(err) = &result {
                failed += 1;
                *self.errors.entry(err.reason()).or_default() += 1;
                if first.is_none() {
                    first = Some((op.clone(), err.clone()));
                }
            }
            self.apply_result(op, *target, result.is_ok());
        }
        if let Some((op, err)) = first {
            warn!(failed, of = ops.len(), first = ?op, %err,
                "the kernel refused changes; retrying every {} s", SWEEP_INTERVAL.as_secs());
        }
    }

    fn apply_result(&mut self, op: &Op, target: Target, ok: bool) {
        match target {
            Target::None => {}
            Target::Hop(id) => {
                if !ok && let Some(hop) = self.hops.get_mut(&id) {
                    hop.installed = false;
                }
            }
            Target::Route(prefix) => {
                let Some(entry) = self.entry(&prefix) else {
                    return;
                };
                let state = match (op, ok) {
                    (_, false) => RouteState::Failed,
                    (Op::AddRoute(_), true) => RouteState::Installed,
                    (_, true) if entry.hop().is_none() => {
                        self.set_entry(prefix, None);
                        return;
                    }
                    (_, true) if self.local.contains(&prefix) => RouteState::Shadowed,
                    (_, true) => RouteState::Unresolved,
                };
                self.set_entry(prefix, Some(entry.with_state(state)));
            }
        }
    }
}
