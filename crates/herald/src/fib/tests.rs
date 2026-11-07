use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
};

use herald_netlink::KernelError;

use herald_netlink::Nexthop;

use herald_netlink::RT_TABLE_MAIN;

use herald_netlink::RTPROT_KERNEL;

use herald_netlink::Route;

use super::{
    entry::Via,
    kernel::{Netlink, OpError},
    resolve::{Resolution, resolution},
    status::HopInfo,
    thread::probe,
    *,
};

/// A kernel in memory: its own routes for lookups, nexthop objects and
/// herald's routes, with the same rules as the real one for what herald
/// does.
#[derive(Default)]
struct Fake {
    /// Routes that are not herald's (connected, static, other daemons').
    table: Vec<Route>,
    nexthops: BTreeMap<u32, Nexthop>,
    /// herald's routes: (prefix, table, metric) -> nexthop id.
    routes: BTreeMap<(Prefix, u32, u32), u32>,
    /// Route adds for these prefixes fail with EINVAL.
    refuse: HashSet<Prefix>,
    /// Every apply() call.
    calls: Vec<Vec<Op>>,
    foreign_nexthop: Option<u32>,
}

fn kernel_error(errno: i32, message: &str) -> OpError {
    OpError::Kernel(KernelError {
        errno,
        message: Some(message.into()),
        offset: None,
    })
}

/// A connected route: `dst dev oif proto kernel scope link`.
fn connected(dst: &str, oif: u32) -> Route {
    Route {
        oif: Some(oif),
        scope: herald_netlink::RT_SCOPE_LINK,
        nh_id: None,
        ..Route::via_nexthop(p(dst), 0, RT_TABLE_MAIN, RTPROT_KERNEL, 0)
    }
}

/// A static route: `dst via gateway dev oif`.
fn static_via(dst: &str, gateway: &str, oif: u32) -> Route {
    Route {
        gateway: Some(a(gateway)),
        protocol: herald_netlink::RTPROT_STATIC,
        ..connected(dst, oif)
    }
}

fn prefix_len(prefix: &Prefix) -> u8 {
    match prefix {
        Prefix::V4(p) => p.prefix_len(),
        Prefix::V6(p) => p.prefix_len(),
    }
}

fn contains(prefix: &Prefix, addr: IpAddr) -> bool {
    match (prefix, addr) {
        (Prefix::V4(p), IpAddr::V4(a)) => Prefix4::new(a, p.prefix_len()).unwrap() == *p,
        (Prefix::V6(p), IpAddr::V6(a)) => Prefix6::new(a, p.prefix_len()).unwrap() == *p,
        _ => false,
    }
}

impl Fake {
    fn apply_one(&mut self, op: &Op) -> Result<(), OpError> {
        match op {
            Op::AddNexthop(nh) => {
                self.nexthops.insert(nh.id, nh.clone());
            }
            Op::DeleteNexthop(id) => {
                self.nexthops
                    .remove(id)
                    .ok_or_else(|| kernel_error(libc::ENOENT, "Nexthop id does not exist"))?;
                self.routes.retain(|_, nh| nh != id);
            }
            Op::AddRoute(route) => {
                let id = route.nh_id.expect("herald routes use nexthop objects");
                if !self.nexthops.contains_key(&id) {
                    return Err(kernel_error(libc::EINVAL, "Nexthop id does not exist"));
                }
                if self.refuse.contains(&route.dst) {
                    return Err(kernel_error(libc::EINVAL, "refused"));
                }
                let key = (route.dst, route.table, route.priority.unwrap());
                self.routes.insert(key, id);
            }
            Op::DeleteRoute(route) => {
                let key = (route.dst, route.table, route.priority.unwrap());
                self.routes
                    .remove(&key)
                    .ok_or_else(|| kernel_error(libc::ESRCH, "No such process"))?;
            }
        }
        Ok(())
    }

    /// Routes in table main, metric 20: prefix -> next hop address.
    fn installed(&self) -> Vec<(Prefix, IpAddr)> {
        self.routes
            .iter()
            .filter(|((_, table, metric), _)| *table == RT_TABLE_MAIN && *metric == 20)
            .map(|((p, _, _), id)| (*p, self.nexthops[id].gateway.unwrap()))
            .collect()
    }
}

impl Kernel for Fake {
    fn apply(&mut self, ops: &[Op]) -> Vec<Result<(), OpError>> {
        self.calls.push(ops.to_vec());
        ops.iter().map(|op| self.apply_one(op)).collect()
    }

    /// Longest match over the kernel's routes and herald's (table main);
    /// with `oif` only routes out of that interface.
    fn lookup(&mut self, addr: IpAddr, oif: Option<u32>) -> io::Result<Option<Route>> {
        let ours = self
            .routes
            .iter()
            .filter(|((_, table, _), _)| *table == RT_TABLE_MAIN)
            .map(|(&(dst, table, metric), &id)| {
                Route::via_nexthop(dst, id, table, RTPROT_BGP, metric)
            });
        let best = self
            .table
            .iter()
            .cloned()
            .chain(ours)
            .filter(|r| contains(&r.dst, addr))
            .filter(|r| oif.is_none() || r.oif == oif)
            .max_by_key(|r| prefix_len(&r.dst));
        Ok(best)
    }

    fn nexthop(&mut self, id: u32) -> io::Result<Option<Nexthop>> {
        Ok(self.nexthops.get(&id).cloned())
    }

    fn routes(&mut self, table: u32, protocol: u8) -> io::Result<Vec<Route>> {
        if protocol != RTPROT_BGP {
            return Ok(self
                .table
                .iter()
                .filter(|r| r.table == table && r.protocol == protocol)
                .cloned()
                .collect());
        }
        Ok(self
            .routes
            .iter()
            .filter(|((_, t, _), _)| *t == table)
            .map(|(&(dst, t, metric), &id)| Route::via_nexthop(dst, id, t, RTPROT_BGP, metric))
            .collect())
    }

    fn nexthops(&mut self) -> io::Result<Vec<Nexthop>> {
        let mut all: Vec<Nexthop> = self.nexthops.values().cloned().collect();
        if let Some(id) = self.foreign_nexthop {
            all.push(Nexthop::gateway(id, "10.0.0.9".parse().unwrap(), 1, 11));
        }
        Ok(all)
    }
}

const SETTINGS: Settings = Settings {
    table: RT_TABLE_MAIN,
    metric: 20,
    resolve_via_default: false,
};

fn p(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn a(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// eth0 (index 2) has 10.0.0.0/24 and 2001:db8:ff::/64.
fn fib() -> Fib<Fake> {
    let kernel = Fake {
        table: vec![
            connected("10.0.0.0/24", 2),
            connected("2001:db8:ff::/64", 2),
        ],
        ..Fake::default()
    };
    Fib::new(kernel, SETTINGS)
}

#[test]
fn routes_share_one_nexthop_object_per_next_hop() {
    let mut fib = fib();
    fib.update(&[
        (p("198.51.100.0/24"), Some(a("10.0.0.2"))),
        (p("203.0.113.0/24"), Some(a("10.0.0.2"))),
        (p("2001:db8:2::/48"), Some(a("2001:db8:ff::2"))),
    ]);
    let k = fib.kernel();
    assert_eq!(k.nexthops.len(), 2);
    let nh = &k.nexthops[&0xBA00_0000];
    assert_eq!(
        (nh.gateway, nh.oif, nh.protocol),
        (Some(a("10.0.0.2")), Some(2), RTPROT_BGP)
    );
    assert_eq!(
        k.installed(),
        [
            (p("198.51.100.0/24"), a("10.0.0.2")),
            (p("203.0.113.0/24"), a("10.0.0.2")),
            (p("2001:db8:2::/48"), a("2001:db8:ff::2")),
        ]
    );
    // One apply: nexthops first, then the routes using them.
    assert_eq!(k.calls.len(), 1);
    assert!(matches!(k.calls[0][0], Op::AddNexthop(_)));
    assert_eq!(fib.count(RouteState::Installed), 3);
    assert!(!fib.needs_sweep());

    // The same again changes nothing.
    fib.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.2")))]);
    assert_eq!(fib.kernel().calls.len(), 1);
}

#[test]
fn a_new_next_hop_moves_the_route_and_the_unused_one_goes() {
    let mut fib = fib();
    fib.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.2")))]);
    fib.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.3")))]);
    let k = fib.kernel();
    assert_eq!(k.installed(), [(p("198.51.100.0/24"), a("10.0.0.3"))]);
    assert_eq!(k.nexthops.len(), 1, "10.0.0.2 is not used any more");
    let ops = k.calls.last().unwrap();
    assert!(matches!(ops[0], Op::AddNexthop(_)));
    assert!(
        matches!(ops[1], Op::AddRoute(_)),
        "replace, no delete first"
    );
    assert!(matches!(ops[2], Op::DeleteNexthop(0xBA00_0000)));
    let via = Via {
        gateway: a("10.0.0.3"),
        oif: 2,
    };
    assert_eq!(
        fib.next_hops(),
        [HopInfo {
            gw: a("10.0.0.3").into(),
            id: 0xBA00_0001,
            via: Some(via),
            routes: 1
        }]
    );

    // Withdrawn: route and nexthop go, the id is used again.
    fib.update(&[(p("198.51.100.0/24"), None::<IpAddr>)]);
    assert!(fib.kernel().routes.is_empty());
    assert!(fib.kernel().nexthops.is_empty());
    assert_eq!(fib.route(&p("198.51.100.0/24")), None);
    fib.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.4")))]);
    assert!(fib.kernel().nexthops.contains_key(&0xBA00_0001));
}

#[test]
fn unreachable_next_hop_waits_for_the_sweep() {
    let mut fib = fib();
    fib.update(&[(p("198.51.100.0/24"), Some(a("192.0.2.1")))]);
    assert!(fib.kernel().calls.is_empty(), "nothing to tell the kernel");
    assert_eq!(
        fib.route(&p("198.51.100.0/24")),
        Some((a("192.0.2.1"), RouteState::Unresolved))
    );
    assert!(fib.needs_sweep());
    assert_eq!(fib.next_hops()[0].via, None);
    assert_eq!(addrs(fib.take_reports()), [(a("192.0.2.1"), false)]);

    fib.refresh();
    assert!(fib.kernel().routes.is_empty(), "still unreachable");

    fib.kernel().table.push(connected("192.0.2.0/24", 3));
    fib.refresh();
    assert_eq!(addrs(fib.take_reports()), [(a("192.0.2.1"), true)]);
    assert_eq!(
        fib.kernel().installed(),
        [(p("198.51.100.0/24"), a("192.0.2.1"))]
    );
    assert_eq!(fib.count(RouteState::Installed), 1);
    assert!(!fib.needs_sweep());
}

#[test]
fn moving_to_an_unreachable_next_hop_deletes_the_route() {
    let mut fib = fib();
    fib.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.2")))]);
    fib.update(&[(p("198.51.100.0/24"), Some(a("192.0.2.1")))]);
    assert!(fib.kernel().routes.is_empty());
    assert!(fib.kernel().nexthops.is_empty());
    assert_eq!(fib.count(RouteState::Unresolved), 1);
}

#[test]
fn refused_routes_are_counted_and_retried() {
    let mut fib = fib();
    fib.kernel().refuse.insert(p("203.0.113.0/24"));
    fib.update(&[
        (p("198.51.100.0/24"), Some(a("10.0.0.2"))),
        (p("203.0.113.0/24"), Some(a("10.0.0.2"))),
    ]);
    assert_eq!(fib.count(RouteState::Installed), 1);
    assert_eq!(fib.count(RouteState::Failed), 1);
    assert_eq!(fib.errors()["EINVAL"], 1);
    assert!(fib.needs_sweep());

    fib.refresh();
    assert_eq!(fib.errors()["EINVAL"], 2, "tried again, refused again");
    fib.kernel().refuse.clear();
    fib.refresh();
    assert_eq!(fib.count(RouteState::Installed), 2);
    assert!(!fib.needs_sweep());
    // The sweep only touched the failed prefix.
    assert_eq!(fib.kernel().calls.last().unwrap().len(), 1);
}

#[test]
fn a_failed_delete_is_retried() {
    let mut fib = fib();
    fib.update(&[
        (p("198.51.100.0/24"), Some(a("10.0.0.2"))),
        (p("203.0.113.0/24"), Some(a("10.0.0.2"))),
    ]);
    // Someone deleted and re-added the route under a metric we do not
    // know; our delete finds nothing, which counts as done.
    fib.kernel().routes.clear();
    fib.update(&[(p("198.51.100.0/24"), None::<IpAddr>)]);
    assert_eq!(fib.route(&p("198.51.100.0/24")), None);
    assert!(fib.errors().is_empty());
}

#[test]
fn new_settings_move_every_route() {
    let mut fib = fib();
    fib.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.2")))]);
    fib.set_settings(Settings {
        table: 100,
        metric: 30,
        ..SETTINGS
    });
    let k = fib.kernel();
    assert_eq!(
        k.routes.keys().copied().collect::<Vec<_>>(),
        [(p("198.51.100.0/24"), 100, 30)]
    );
    let ops = k.calls.last().unwrap();
    assert!(matches!(ops[0], Op::AddRoute(_)), "new copy first");
    assert!(matches!(ops[1], Op::DeleteRoute(_)));
}

#[test]
fn purge_deletes_only_herald_nexthops() {
    let mut fib = fib();
    fib.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.2")))]);
    fib.kernel().foreign_nexthop = Some(7);
    assert_eq!(fib.purge().unwrap(), 1);
    let k = fib.kernel();
    assert!(k.routes.is_empty() && k.nexthops.is_empty());
    let deleted: Vec<&Op> = k.calls.last().unwrap().iter().collect();
    assert_eq!(deleted, [&Op::DeleteNexthop(0xBA00_0000)]);
    assert_eq!(fib.route(&p("198.51.100.0/24")), None);
}

/// A kernel that refuses everything with one errno.
struct Refusing(i32);

impl Kernel for Refusing {
    fn apply(&mut self, ops: &[Op]) -> Vec<Result<(), OpError>> {
        ops.iter()
            .map(|_| Err(kernel_error(self.0, "no")))
            .collect()
    }

    fn lookup(&mut self, _: IpAddr, _: Option<u32>) -> io::Result<Option<Route>> {
        Ok(None)
    }

    fn nexthops(&mut self) -> io::Result<Vec<Nexthop>> {
        Ok(Vec::new())
    }

    fn nexthop(&mut self, _: u32) -> io::Result<Option<Nexthop>> {
        Ok(None)
    }

    fn routes(&mut self, _: u32, _: u8) -> io::Result<Vec<Route>> {
        Ok(Vec::new())
    }
}

#[test]
fn probe_explains_what_is_missing() {
    let err = probe(&mut Refusing(libc::EPERM)).unwrap_err();
    assert!(err.contains("CAP_NET_ADMIN"), "{err}");
    let err = probe(&mut Refusing(libc::EOPNOTSUPP)).unwrap_err();
    assert!(err.contains("5.3"), "{err}");
    let mut fake = Fake::default();
    probe(&mut fake).unwrap();
    assert!(fake.nexthops.is_empty(), "the probe cleans up");
}

#[test]
fn adopted_routes_keep_forwarding_until_taken_over() {
    // The earlier run installed three routes through two next hops.
    let mut old = fib();
    old.update(&[
        (p("198.51.100.0/24"), Some(a("10.0.0.2"))),
        (p("203.0.113.0/24"), Some(a("10.0.0.2"))),
        (p("192.0.2.0/24"), Some(a("10.0.0.3"))),
    ]);
    let kernel = std::mem::take(old.kernel());
    let mut fib = Fib::new(kernel, SETTINGS);
    assert_eq!(fib.adopt().unwrap(), (2, 3));
    assert!(fib.adopting());

    // Taken over: replaced in place, through a new id.
    fib.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.2")))]);
    let k = fib.kernel();
    assert_eq!(k.routes.len(), 3, "nothing deleted yet");
    let id = k.routes[&(p("198.51.100.0/24"), RT_TABLE_MAIN, 20)];
    assert_eq!(id, 0xBA00_0002, "not one of the earlier run's ids");
    // The RIB has no route for this one any more: deleted at once.
    fib.update(&[(p("192.0.2.0/24"), None::<IpAddr>)]);
    assert!(
        !fib.kernel()
            .routes
            .contains_key(&(p("192.0.2.0/24"), RT_TABLE_MAIN, 20))
    );

    // The rest goes with the earlier run's nexthop objects.
    assert_eq!(fib.end_adoption(), 1, "203.0.113.0/24 was not sent again");
    assert!(!fib.adopting());
    let k = fib.kernel();
    assert_eq!(k.installed(), [(p("198.51.100.0/24"), a("10.0.0.2"))]);
    assert_eq!(
        k.nexthops.keys().copied().collect::<Vec<_>>(),
        [0xBA00_0002]
    );
}

#[test]
fn connected_and_static_routes_are_not_shadowed() {
    let mut fib = fib();
    fib.refresh(); // reads the kernel's own routes
    fib.update(&[
        // srv-c learns its own core subnet from a router.
        (p("2001:db8:ff::/64"), Some(a("2001:db8:ff::3"))),
        (p("198.51.100.0/24"), Some(a("10.0.0.2"))),
    ]);
    assert_eq!(fib.count(RouteState::Shadowed), 1);
    assert_eq!(
        fib.kernel().installed(),
        [(p("198.51.100.0/24"), a("10.0.0.2"))]
    );
    assert!(!fib.needs_sweep(), "nothing to retry");

    // An admin adds a static route for the other prefix: herald steps back.
    fib.kernel()
        .table
        .push(static_via("198.51.100.0/24", "10.0.0.9", 2));
    fib.refresh();
    assert!(fib.kernel().installed().is_empty());
    assert_eq!(fib.count(RouteState::Shadowed), 2);
    // ... and takes over again when it goes.
    fib.kernel().table.pop();
    fib.refresh();
    assert_eq!(
        fib.kernel().installed(),
        [(p("198.51.100.0/24"), a("10.0.0.2"))]
    );
}

#[test]
fn resolution_rules() {
    let hop = a("10.0.0.2");
    let direct = Via {
        gateway: hop,
        oif: 2,
    };
    let on_link = connected("10.0.0.0/24", 2);
    assert_eq!(resolution(&on_link, hop, false), Resolution::Via(direct));
    let static_route = static_via("10.0.0.0/16", "192.0.2.1", 3);
    assert_eq!(
        resolution(&static_route, hop, false),
        Resolution::Via(Via {
            gateway: a("192.0.2.1"),
            oif: 3
        })
    );
    let ours = Route::via_nexthop(p("10.0.0.0/25"), 0xBA00_0001, RT_TABLE_MAIN, RTPROT_BGP, 20);
    assert_eq!(resolution(&ours, hop, false), Resolution::Ours);
    let other_bgp = Route {
        protocol: RTPROT_BGP,
        ..on_link.clone()
    };
    assert!(matches!(
        resolution(&other_bgp, hop, false),
        Resolution::Unusable(_)
    ));
    let local = Route {
        kind: herald_netlink::RTN_LOCAL,
        ..on_link.clone()
    };
    assert!(matches!(
        resolution(&local, hop, false),
        Resolution::Unusable(_)
    ));
    let default = static_via("0.0.0.0/0", "192.0.2.1", 3);
    assert!(matches!(
        resolution(&default, hop, false),
        Resolution::Unusable(_)
    ));
    assert!(matches!(
        resolution(&default, hop, true),
        Resolution::Via(_)
    ));
    let object = Route {
        nh_id: Some(7),
        oif: None,
        ..on_link
    };
    assert_eq!(resolution(&object, hop, false), Resolution::Nexthop(7));
}

#[test]
fn next_hops_behind_a_gateway_are_flattened() {
    let mut fib = fib();
    fib.kernel()
        .table
        .push(static_via("172.16.0.0/16", "10.0.0.254", 2));
    fib.update(&[(p("198.51.100.0/24"), Some(a("172.16.5.5")))]);
    let nh = &fib.kernel().nexthops[&0xBA00_0000];
    assert_eq!((nh.gateway, nh.oif), (Some(a("10.0.0.254")), Some(2)));
    assert_eq!(fib.count(RouteState::Installed), 1);

    // The gateway moves: the object is replaced, the route stays.
    fib.kernel().table[2] = static_via("172.16.0.0/16", "10.0.0.253", 2);
    let routes_before = fib.kernel().routes.clone();
    fib.refresh();
    let k = fib.kernel();
    assert_eq!(k.nexthops[&0xBA00_0000].gateway, Some(a("10.0.0.253")));
    assert_eq!(k.routes, routes_before);
    assert_eq!(k.calls.last().unwrap().len(), 1, "one message");
    assert!(addrs(fib.take_reports()).is_empty(), "reachable all along");
}

#[test]
fn a_next_hop_that_becomes_unreachable_takes_its_routes_out() {
    let mut fib = fib();
    fib.kernel()
        .table
        .push(static_via("172.16.0.0/16", "10.0.0.254", 2));
    fib.update(&[
        (p("198.51.100.0/24"), Some(a("172.16.5.5"))),
        (p("203.0.113.0/24"), Some(a("172.16.5.5"))),
    ]);
    fib.kernel().table.pop();
    fib.refresh();
    let k = fib.kernel();
    assert!(k.nexthops.is_empty() && k.routes.is_empty());
    assert_eq!(k.calls.last().unwrap(), &[Op::DeleteNexthop(0xBA00_0000)]);
    assert_eq!(fib.count(RouteState::Unresolved), 2);
    assert_eq!(addrs(fib.take_reports()), [(a("172.16.5.5"), false)]);

    // The RIB answers: no route for these prefixes now. The next hop has
    // no users left but stays watched.
    fib.update(&[
        (p("198.51.100.0/24"), None),
        (p("203.0.113.0/24"), None::<IpAddr>),
    ]);
    assert_eq!(fib.count(RouteState::Unresolved), 0);
    assert_eq!(fib.next_hops()[0].routes, 0);
    fib.refresh();
    assert!(addrs(fib.take_reports()).is_empty(), "still unreachable");

    // Back: the RIB hears it; the hop is forgotten until it is used again.
    fib.kernel()
        .table
        .push(static_via("172.16.0.0/16", "10.0.0.254", 2));
    fib.refresh();
    assert_eq!(addrs(fib.take_reports()), [(a("172.16.5.5"), true)]);
    assert!(fib.next_hops().is_empty());
    assert!(!fib.needs_sweep());
}

#[test]
fn default_route_resolves_only_when_allowed() {
    let mut fib = fib();
    fib.kernel()
        .table
        .push(static_via("0.0.0.0/0", "10.0.0.1", 2));
    fib.update(&[(p("198.51.100.0/24"), Some(a("169.254.169.254")))]);
    assert_eq!(fib.count(RouteState::Unresolved), 1);
    fib.set_settings(Settings {
        resolve_via_default: true,
        ..SETTINGS
    });
    assert_eq!(fib.count(RouteState::Installed), 1);
    assert_eq!(
        fib.kernel().nexthops[&0xBA00_0000].gateway,
        Some(a("10.0.0.1"))
    );
    assert_eq!(
        addrs(fib.take_reports()),
        [(a("169.254.169.254"), false), (a("169.254.169.254"), true)]
    );
}

#[test]
fn next_hops_through_another_daemons_nexthop_object() {
    let mut fib = fib();
    let k = fib.kernel();
    // An IGP daemon: group 50 of nexthop 51 via 10.0.0.9.
    k.nexthops
        .insert(51, Nexthop::gateway(51, a("10.0.0.9"), 2, 11));
    k.nexthops.insert(
        50,
        Nexthop {
            group: vec![herald_netlink::GroupMember { id: 51, weight: 1 }],
            gateway: None,
            oif: None,
            family: herald_netlink::AF_UNSPEC,
            ..Nexthop::gateway(50, a("10.0.0.9"), 2, 11)
        },
    );
    k.table.push(Route {
        nh_id: Some(50),
        oif: None,
        protocol: 11,
        ..connected("172.16.0.0/16", 2)
    });
    fib.update(&[(p("198.51.100.0/24"), Some(a("172.16.5.5")))]);
    let nh = &fib.kernel().nexthops[&0xBA00_0000];
    assert_eq!((nh.gateway, nh.oif), (Some(a("10.0.0.9")), Some(2)));
}

#[test]
fn a_learned_route_covering_its_next_hop_does_not_flap() {
    let mut fib = fib();
    // 10.0.0.0/25 is learned with a next hop inside it.
    fib.update(&[(p("10.0.0.0/25"), Some(a("10.0.0.2")))]);
    assert_eq!(fib.count(RouteState::Installed), 1);
    // Now the kernel's best entry for 10.0.0.2 is our own route.
    fib.refresh();
    assert_eq!(fib.count(RouteState::Installed), 1);
    assert!(addrs(fib.take_reports()).is_empty());
    assert_eq!(fib.kernel().calls.len(), 1, "nothing changed");
}

// --- against the real kernel ---

const NETNS_ENV: &str = "HERALD_FIB_NETNS";

/// Runs [`in_namespace`] in a new user + network namespace, like the
/// netlink kernel test. Skips when unprivileged user namespaces are not
/// allowed.
#[test]
fn kernel_in_namespace() {
    if std::env::var_os(NETNS_ENV).is_some() {
        in_namespace();
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let out = match std::process::Command::new("unshare")
        .arg("-rn")
        .arg(exe)
        .args(["fib::tests::kernel_in_namespace", "--exact", "--nocapture"])
        .env(NETNS_ENV, "1")
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            eprintln!("kernel_in_namespace skipped: cannot run unshare: {e}");
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && stderr.starts_with("unshare:") {
        eprintln!("kernel_in_namespace skipped: {stderr}");
        return;
    }
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "{stdout}");
}

fn sh(script: &str) -> String {
    let out = std::process::Command::new("sh")
        .args(["-ec", script])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{script}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn in_namespace() {
    if std::process::Command::new("ip").arg("-V").output().is_err() {
        println!("skipped: no ip command");
        return;
    }
    sh("ip link set lo up
        ip link add d0 type dummy
        ip link set d0 up
        ip addr add 10.0.0.1/24 dev d0
        ip -6 addr add 2001:db8:ff::1/64 dev d0 nodad");
    let mut kernel = Netlink::open().unwrap();
    probe(&mut kernel).unwrap();
    assert_eq!(sh("ip nexthop show"), "", "the probe cleans up");
    let mut fib = Fib::new(kernel, SETTINGS);

    fib.update(&[
        (p("198.51.100.0/24"), Some(a("10.0.0.2"))),
        (p("2001:db8:2::/48"), Some(a("2001:db8:ff::2"))),
        (p("192.0.2.0/24"), Some(a("172.16.0.1"))),
    ]);
    assert_eq!(
        sh("ip route show proto bgp"),
        "198.51.100.0/24 nhid 3120562176 via 10.0.0.2 dev d0 metric 20 \n"
    );
    let v6 = sh("ip -6 route show proto bgp");
    assert!(
        v6.starts_with("2001:db8:2::/48 nhid 3120562177 via 2001:db8:ff::2 dev d0 metric 20"),
        "{v6}"
    );
    assert_eq!(fib.count(RouteState::Unresolved), 1);

    // The unreachable next hop becomes reachable.
    sh("ip addr add 172.16.0.2/24 dev d0");
    fib.refresh();
    assert!(sh("ip route show proto bgp").contains("192.0.2.0/24 nhid"));
    assert!(!fib.needs_sweep());

    // A full datagram's worth and more: 3000 routes in one update.
    let many: Vec<(Prefix, Option<IpAddr>)> = (0..3000u32)
        .map(|i| {
            let addr = std::net::Ipv4Addr::from(0x6400_0000 + (i << 8));
            (
                Prefix::V4(Prefix4::new(addr, 24).unwrap()),
                Some(a("10.0.0.3")),
            )
        })
        .collect();
    fib.update(&many);
    assert!(fib.errors().is_empty(), "{:?}", fib.errors());
    let count = sh("ip route show proto bgp | wc -l");
    assert_eq!(count.trim(), "3002");

    // Next hop moves; a withdrawn prefix goes.
    fib.update(&[
        (p("198.51.100.0/24"), Some(a("10.0.0.3"))),
        (p("192.0.2.0/24"), None),
    ]);
    let routes = sh("ip route show proto bgp");
    assert!(
        routes.contains("198.51.100.0/24 nhid 3120562179 via 10.0.0.3"),
        "{routes}"
    );
    assert!(!routes.contains("192.0.2.0/24"), "{routes}");
    assert!(
        !sh("ip nexthop show").contains("10.0.0.2"),
        "unused nexthop deleted"
    );

    // Another table and metric.
    fib.set_settings(Settings {
        table: 100,
        metric: 30,
        ..SETTINGS
    });
    assert_eq!(sh("ip route show proto bgp | wc -l").trim(), "0");
    let moved = sh("ip route show table 100 proto bgp | wc -l");
    assert_eq!(moved.trim(), "3001");
    assert!(fib.errors().is_empty(), "{:?}", fib.errors());

    // A restart: a new FIB adopts the routes, takes over one, and drops
    // the rest at the end.
    let mut next = Fib::new(Netlink::open().unwrap(), fib.settings());
    let (nexthops, routes) = next.adopt().unwrap();
    assert_eq!(
        (nexthops, routes),
        (2, 3002),
        "3000 + 198.51.100.0/24 + one IPv6"
    );
    next.update(&[(p("198.51.100.0/24"), Some(a("10.0.0.3")))]);
    let taken = sh("ip route show table 100 proto bgp 198.51.100.0/24");
    assert!(taken.contains("nhid 3120562180"), "{taken}");
    assert_eq!(next.end_adoption(), 3001);
    let left = sh("ip route show table 100 proto bgp");
    assert_eq!(left.lines().count(), 1, "{left}");
    drop(next);

    // The connected IPv6 subnet (metric 256) is not taken over.
    fib.refresh();
    fib.update(&[(p("2001:db8:ff::/64"), Some(a("2001:db8:ff::2")))]);
    assert_eq!(
        sh("ip -6 route show table 100 proto bgp 2001:db8:ff::/64"),
        ""
    );
    assert_eq!(
        fib.count(RouteState::Shadowed),
        0,
        "table 100 has no connected routes"
    );
    fib.update(&[(p("2001:db8:ff::/64"), None::<IpAddr>)]);

    // Purge leaves nothing behind.
    fib.purge().unwrap();
    assert_eq!(sh("ip route show table all proto bgp"), "");
    assert_eq!(sh("ip nexthop show"), "");

    link_local_in_kernel(&mut fib);
    recursive_and_events(fib);
}

/// Link-local next hops: one per interface, and as the fallback of a
/// global next hop that does not resolve.
fn link_local_in_kernel(fib: &mut Fib<Netlink>) {
    fib.set_settings(SETTINGS);
    let errors_before = fib.errors().clone();
    sh("ip link add d1 type dummy
        ip link set d1 up
        ip -6 addr add fe80::a/64 dev d1 nodad
        ip link add d2 type dummy
        ip link set d2 up
        ip -6 addr add fe80::b/64 dev d2 nodad");
    let index = |dev: &str| {
        let name = std::ffi::CString::new(dev).unwrap();
        // SAFETY: a NUL-terminated name.
        unsafe { libc::if_nametoindex(name.as_ptr()) }
    };
    let (d1, d2) = (index("d1"), index("d2"));
    let on1 = Gateway::new(a("fe80::1"), None, Some(d1));
    let on2 = Gateway::new(a("fe80::1"), None, Some(d2));
    let fallback = Gateway::new(a("2001:db8:77::1"), Some(v6("fe80::77")), Some(d1));
    fib.update(&[
        (p("2001:db8:a::/48"), Some(on1)),
        (p("2001:db8:b::/48"), Some(on2)),
        (p("2001:db8:c::/48"), Some(fallback)),
    ]);
    assert_eq!(*fib.errors(), errors_before);
    let routes = sh("ip -6 route show proto bgp");
    for (prefix, via) in [
        ("2001:db8:a::/48", "via fe80::1 dev d1"),
        ("2001:db8:b::/48", "via fe80::1 dev d2"),
        ("2001:db8:c::/48", "via fe80::77 dev d1"),
    ] {
        let line = routes.lines().find(|l| l.starts_with(prefix));
        assert!(
            line.is_some_and(|l| l.contains(via)),
            "{prefix} {via}: {routes}"
        );
    }

    // d2 goes down: its fe80::/64 route goes, so does fe80::1 on d2.
    addrs(fib.take_reports());
    sh("ip link set d2 down");
    fib.refresh();
    assert_eq!(fib.take_reports(), [(on2, false)]);
    let routes = sh("ip -6 route show proto bgp");
    assert!(!routes.contains("2001:db8:b::/48"), "{routes}");
    assert!(routes.contains("2001:db8:a::/48"), "{routes}");

    fib.update(&[
        (p("2001:db8:a::/48"), None::<Gateway>),
        (p("2001:db8:b::/48"), None),
        (p("2001:db8:c::/48"), None),
    ]);
    assert_eq!(sh("ip -6 route show proto bgp"), "");
    sh("ip link del d1
        ip link del d2");
    fib.refresh();
    addrs(fib.take_reports());
}

/// A next hop behind a static route, another daemon's nexthop object,
/// and the event thread noticing kernel changes.
fn recursive_and_events(mut fib: Fib<Netlink>) {
    fib.set_settings(SETTINGS);
    addrs(fib.take_reports());
    let (tx, rx) = std_mpsc::channel();
    let pending = Arc::new(AtomicBool::new(false));
    events::spawn(tx, pending.clone()).unwrap();
    let changed = |what: &str| {
        let got = rx.recv_timeout(Duration::from_secs(2));
        assert!(matches!(got, Ok(FibMsg::KernelChanged)), "{what}: {got:?}");
        pending.store(false, Ordering::Relaxed);
        while rx.try_recv().is_ok() {}
    };

    sh("ip route add 172.16.0.0/16 via 10.0.0.254");
    changed("static route added");
    fib.update(&[(p("198.51.100.0/24"), Some(a("172.16.5.5")))]);
    let nh = sh("ip nexthop show");
    assert!(nh.contains("via 10.0.0.254 dev d0"), "{nh}");
    // Our own changes are not reported.
    std::thread::sleep(Duration::from_millis(200));
    assert!(rx.try_recv().is_err(), "herald's own route reported");

    // The static route moves to another gateway: the object follows.
    sh("ip route replace 172.16.0.0/16 via 10.0.0.253");
    changed("static route replaced");
    fib.refresh();
    let routes = sh("ip route show proto bgp");
    assert!(routes.contains("198.51.100.0/24 nhid"), "{routes}");
    assert!(sh("ip nexthop show").contains("via 10.0.0.253"));
    assert!(addrs(fib.take_reports()).is_empty());

    // The static route goes: unreachable, the route leaves the kernel.
    sh("ip route del 172.16.0.0/16");
    changed("static route deleted");
    fib.refresh();
    assert_eq!(sh("ip route show proto bgp"), "");
    assert_eq!(addrs(fib.take_reports()), [(a("172.16.5.5"), false)]);
    fib.update(&[(p("198.51.100.0/24"), None::<IpAddr>)]);

    // An IGP daemon's route through its own nexthop object.
    sh("ip nexthop add id 77 via 10.0.0.252 dev d0 proto 11
        ip route add 172.16.0.0/16 nhid 77 proto 11");
    changed("nexthop object route added");
    fib.refresh();
    assert_eq!(addrs(fib.take_reports()), [(a("172.16.5.5"), true)]);
    fib.update(&[(p("198.51.100.0/24"), Some(a("172.16.5.5")))]);
    assert!(sh("ip nexthop show").contains("via 10.0.0.252 dev d0 scope link proto bgp"));

    // Link down: the kernel drops the connected and static routes.
    sh("ip link set d0 down");
    changed("link down");
    fib.refresh();
    assert_eq!(addrs(fib.take_reports()), [(a("172.16.5.5"), false)]);
    assert_eq!(sh("ip route show proto bgp"), "");
}

#[test]
fn next_hops_through_an_ecmp_kernel_route() {
    use herald_netlink::{RTNH_F_LINKDOWN, RouteHop};
    let mut fib = fib();
    let leg = |gateway: &str, oif, flags| RouteHop {
        flags,
        weight: 1,
        oif,
        gateway: Some(a(gateway)),
    };
    // `ip route add 172.16.0.0/16 nexthop via 10.0.0.8 dev 2 nexthop via 10.1.0.8
    // dev 3`, the first leg without carrier.
    fib.kernel().table.push(Route {
        oif: None,
        multipath: vec![
            leg("10.0.0.8", 2, RTNH_F_LINKDOWN as u8),
            leg("10.1.0.8", 3, 0),
        ],
        ..static_via("172.16.0.0/16", "10.0.0.8", 2)
    });
    fib.update(&[(p("198.51.100.0/24"), Some(a("172.16.5.5")))]);
    let nh = &fib.kernel().nexthops[&0xBA00_0000];
    assert_eq!((nh.gateway, nh.oif), (Some(a("10.1.0.8")), Some(3)));
    assert_eq!(
        fib.route(&p("198.51.100.0/24")).unwrap().1,
        RouteState::Installed
    );

    // Every leg down: unreachable.
    fib.kernel().table.last_mut().unwrap().multipath[1].flags = RTNH_F_LINKDOWN as u8;
    fib.refresh();
    assert_eq!(
        fib.route(&p("198.51.100.0/24")).unwrap().1,
        RouteState::Unresolved
    );
    assert_eq!(addrs(fib.take_reports()), [(a("172.16.5.5"), false)]);
}

#[test]
fn a_nexthop_group_resolves_through_its_first_live_member() {
    let mut fib = fib();
    let k = fib.kernel();
    k.nexthops.insert(
        51,
        Nexthop {
            flags: herald_netlink::RTNH_F_LINKDOWN,
            ..Nexthop::gateway(51, a("10.0.0.9"), 2, 11)
        },
    );
    k.nexthops
        .insert(52, Nexthop::gateway(52, a("10.1.0.9"), 3, 11));
    k.nexthops.insert(
        50,
        Nexthop {
            group: vec![
                herald_netlink::GroupMember { id: 51, weight: 1 },
                herald_netlink::GroupMember { id: 52, weight: 1 },
            ],
            gateway: None,
            oif: None,
            family: herald_netlink::AF_UNSPEC,
            ..Nexthop::gateway(50, a("10.0.0.9"), 2, 11)
        },
    );
    k.table.push(Route {
        nh_id: Some(50),
        oif: None,
        protocol: 11,
        ..connected("172.16.0.0/16", 2)
    });
    fib.update(&[(p("198.51.100.0/24"), Some(a("172.16.5.5")))]);
    let nh = &fib.kernel().nexthops[&0xBA00_0000];
    assert_eq!((nh.gateway, nh.oif), (Some(a("10.1.0.9")), Some(3)));
}

#[test]
fn entries_pack_into_four_bytes() {
    assert_eq!(std::mem::size_of::<Entry>(), 4);
    let states = [
        RouteState::Installed,
        RouteState::Failed,
        RouteState::Unresolved,
        RouteState::Shadowed,
    ];
    for hop in [
        None,
        Some(*NEXTHOP_IDS.start()),
        Some(0xBA12_3456),
        Some(*NEXTHOP_IDS.end()),
    ] {
        for state in states {
            let e = Entry::new(hop, state);
            assert_eq!((e.hop(), e.state()), (hop, state));
            for other in states {
                assert_eq!(e.with_state(other), Entry::new(hop, other));
            }
        }
    }
}

/// Reports by address (none of these tests has a link-local fallback).
fn addrs(reports: Vec<(Gateway, bool)>) -> Vec<(IpAddr, bool)> {
    reports.into_iter().map(|(g, up)| (g.addr, up)).collect()
}

fn v6(s: &str) -> std::net::Ipv6Addr {
    s.parse().unwrap()
}

#[test]
fn link_local_next_hops_go_out_of_the_sessions_interface() {
    let mut fib = fib();
    fib.kernel().table.push(connected("fe80::/64", 3));
    fib.kernel().table.push(connected("fe80::/64", 4));
    // Two neighbors on different links, both fe80::1, only link-local.
    let on3 = Gateway::new(a("fe80::1"), None, Some(3));
    let on4 = Gateway::new(a("fe80::1"), None, Some(4));
    assert_eq!(on3.link, Some((v6("fe80::1"), 3)));
    assert_eq!(
        Gateway::new(a("10.0.0.9"), Some(v6("fe80::9")), Some(3)).link,
        None,
        "no link-local fallback for IPv4 routes"
    );
    fib.update(&[
        (p("2001:db8:100::/48"), Some(on3)),
        (p("2001:db8:200::/48"), Some(on4)),
    ]);
    let objects: Vec<(Option<IpAddr>, Option<u32>)> = fib
        .kernel()
        .nexthops
        .values()
        .map(|nh| (nh.gateway, nh.oif))
        .collect();
    assert_eq!(
        objects,
        [(Some(a("fe80::1")), Some(3)), (Some(a("fe80::1")), Some(4))]
    );
    assert_eq!(fib.count(RouteState::Installed), 2);

    // The interface loses its fe80::/64 route (down): unreachable, and only
    // that one is reported.
    fib.kernel().table.retain(|r| r.oif != Some(4));
    fib.refresh();
    assert_eq!(fib.take_reports(), [(on4, false)]);
    assert_eq!(
        fib.route(&p("2001:db8:200::/48")).unwrap().1,
        RouteState::Unresolved
    );
    assert_eq!(
        fib.route(&p("2001:db8:100::/48")).unwrap().1,
        RouteState::Installed
    );
}

#[test]
fn a_link_local_next_hop_without_its_interface_is_unreachable() {
    let mut fib = fib();
    fib.kernel().table.push(connected("fe80::/64", 3));
    // A multihop neighbor (or one the interface is not known for).
    fib.update(&[(p("2001:db8:100::/48"), Some(a("fe80::1")))]);
    assert_eq!(
        fib.route(&p("2001:db8:100::/48")).unwrap().1,
        RouteState::Unresolved
    );
    assert!(fib.kernel().nexthops.is_empty());
}

#[test]
fn the_link_local_next_hop_stands_in_for_an_unreachable_global_one() {
    let mut fib = fib();
    fib.kernel().table.push(connected("fe80::/64", 3));
    // The global next hop is on no connected subnet.
    let gw = Gateway::new(a("2001:db8:77::1"), Some(v6("fe80::77")), Some(3));
    fib.update(&[(p("2001:db8:100::/48"), Some(gw))]);
    let nh = &fib.kernel().nexthops[&0xBA00_0000];
    assert_eq!((nh.gateway, nh.oif), (Some(a("fe80::77")), Some(3)));
    assert_eq!(fib.take_reports(), []);

    // Its subnet appears: the global one is used again.
    fib.kernel().table.push(connected("2001:db8:77::/64", 2));
    fib.refresh();
    let nh = &fib.kernel().nexthops[&0xBA00_0000];
    assert_eq!((nh.gateway, nh.oif), (Some(a("2001:db8:77::1")), Some(2)));
    assert_eq!(
        fib.route(&p("2001:db8:100::/48")).unwrap().1,
        RouteState::Installed
    );
}

#[test]
fn settings_from_config() {
    let config: crate::config::Config = toml::from_str(
        "asn = 64500\nrouter_id = \"203.0.113.1\"\n[kernel]\ntable = 100\nmetric = 32\n",
    )
    .unwrap();
    let settings = Settings::from(config.kernel.as_ref().unwrap());
    assert_eq!((settings.table, settings.metric), (100, 32));
    assert!(!settings.resolve_via_default);
}
