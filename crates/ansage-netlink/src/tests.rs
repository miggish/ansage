//! Byte vectors are written out by hand from the uapi struct layouts (like
//! wire/tests.rs), so encoder and decoder are checked against the kernel's
//! format, not against each other. They are little-endian (netlink uses host
//! byte order). `kernel_in_namespace` checks the same code against the real
//! kernel in a throwaway network namespace.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
};

use super::{socket::Socket, *};
use ansage_bgp::wire::Prefix;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn prefix(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}

/// All messages of `buf`, framing must be fine.
fn messages(buf: &[u8]) -> Vec<Received> {
    parse(buf).map(|m| m.expect("framing")).collect()
}

fn one(buf: &[u8]) -> Body {
    let mut all = messages(buf);
    assert_eq!(all.len(), 1);
    all.remove(0).body.expect("body decodes")
}

#[cfg(target_endian = "little")]
mod vectors {
    use super::*;

    #[test]
    fn add_route_via_nexthop() {
        let mut batch = Batch::new(1);
        let route = Route::via_nexthop(prefix("198.51.100.0/24"), 7, RT_TABLE_MAIN, RTPROT_BGP, 20);
        assert_eq!(batch.add_route(&route), 1);
        let expected = hex("
            3c000000 1800 0505 01000000 00000000
            02 18 00 00 fe ba 00 01 00000000
            0800 0100 c6336400
            0800 0f00 fe000000
            0800 0600 14000000
            0800 1e00 07000000");
        assert_eq!(batch.bytes(), expected);
        assert_eq!(
            route.to_string(),
            "198.51.100.0/24 nhid 7 proto bgp metric 20"
        );
    }

    #[test]
    fn add_nexthop_with_gateway() {
        let mut batch = Batch::new(2);
        batch.add_nexthop(&Nexthop::gateway(7, v4("10.0.0.2"), 3, RTPROT_BGP));
        let expected = hex("
            30000000 6800 0505 02000000 00000000
            02 00 ba 00 00000000
            0800 0100 07000000
            0800 0500 03000000
            0800 0600 0a000002");
        assert_eq!(batch.bytes(), expected);
    }

    #[test]
    fn delete_nexthop() {
        let mut batch = Batch::new(3);
        batch.delete_nexthop(7);
        let expected = hex("
            20000000 6900 0500 03000000 00000000
            00 00 00 00 00000000
            0800 0100 07000000");
        assert_eq!(batch.bytes(), expected);
    }

    #[test]
    fn lookup_asks_for_the_fib_entry() {
        let mut batch = Batch::new(5);
        batch.lookup_route(v6("2001:db8::1"));
        let expected = hex("
            30000000 1a00 0500 05000000 00000000
            0a 80 00 00 00 00 00 00 00200000
            1400 0100 20010db8 00000000 00000000 00000001");
        assert_eq!(batch.bytes(), expected);
    }

    #[test]
    fn dump_filtered_by_table_and_protocol() {
        let mut batch = Batch::new(6);
        batch.dump_routes(AF_INET, RT_TABLE_MAIN, RTPROT_BGP);
        let expected = hex("
            24000000 1a00 0103 06000000 00000000
            02 00 00 00 fe ba 00 00 00000000
            0800 0f00 fe000000");
        assert_eq!(batch.bytes(), expected);
        assert!(batch.requests()[0].dump);
    }

    #[test]
    fn route_from_a_dump_then_done() {
        // RTM_NEWROUTE with NLM_F_MULTI, as the kernel sends it: unknown
        // attributes (RTA_PREF) are skipped.
        let buf = hex("
            6c000000 1800 0200 09000000 d2040000
            0a 30 00 00 fe ba 00 01 00000000
            0800 0f00 fe000000
            1400 0100 20010db8 01000000 00000000 00000000
            0800 0600 14000000
            0800 1e00 07000000
            1400 0500 fe800000 00000000 00000000 00000001
            0800 0400 03000000
            0500 1400 00 000000
            14000000 0300 0200 09000000 d2040000 00000000");
        let all = messages(&buf);
        assert_eq!(all.len(), 2);
        assert_eq!(
            all[0].header,
            Header {
                kind: RTM_NEWROUTE,
                flags: NLM_F_MULTI,
                seq: 9,
                port: 1234,
            }
        );
        let Ok(Body::Route(route)) = &all[0].body else {
            panic!("{:?}", all[0].body);
        };
        assert_eq!(
            *route,
            Route {
                dst: prefix("2001:db8:100::/48"),
                table: RT_TABLE_MAIN,
                protocol: RTPROT_BGP,
                scope: RT_SCOPE_UNIVERSE,
                kind: RTN_UNICAST,
                flags: 0,
                priority: Some(20),
                gateway: Some(v6("fe80::1")),
                oif: Some(3),
                nh_id: Some(7),
                prefsrc: None,
                multipath: Vec::new(),
            }
        );
        assert_eq!(all[1].body, Ok(Body::Done));
        assert!(all[1].body.as_ref().unwrap().is_final());
    }

    #[test]
    fn default_route_has_no_dst() {
        let buf = hex("
            34000000 1800 0200 00000000 00000000
            02 00 00 00 fe 03 00 01 00000000
            0800 0f00 fe000000
            0800 0500 0a000001
            0800 0400 02000000");
        let Body::Route(route) = one(&buf) else {
            panic!()
        };
        assert_eq!(route.dst, prefix("0.0.0.0/0"));
        assert_eq!(route.gateway, Some(v4("10.0.0.1")));
        assert_eq!(route.to_string(), "0.0.0.0/0 via 10.0.0.1 oif 2 proto boot");
    }

    #[test]
    fn ipv4_route_via_ipv6_gateway_uses_rta_via() {
        let mut route =
            Route::via_nexthop(prefix("192.0.2.0/24"), 1, RT_TABLE_MAIN, RTPROT_BGP, 20);
        route.nh_id = None;
        route.gateway = Some(v6("fe80::1"));
        route.oif = Some(3);
        let mut batch = Batch::new(1);
        batch.add_route(&route);
        let via = hex("1600 1200 0a00 fe800000 00000000 00000000 00000001 0000");
        assert!(batch.bytes().windows(via.len()).any(|w| w == via));
        let mut kernel = batch.bytes().to_vec();
        kernel[6] = 0; // flags as in a reply
        assert_eq!(one(&kernel), Body::Route(route));
    }

    #[test]
    fn route_in_table_above_255() {
        let route = Route::via_nexthop(prefix("192.0.2.0/24"), 1, 1000, RTPROT_BGP, 20);
        let mut batch = Batch::new(1);
        batch.add_route(&route);
        let bytes = batch.bytes();
        assert_eq!(bytes[HEADER_LEN + 4], 0, "rtm_table is RT_TABLE_UNSPEC");
        assert_eq!(one(bytes), Body::Route(route));
    }

    #[test]
    fn error_with_extended_ack() {
        let mut buf = hex("
            4c000000 0200 0003 03000000 00000000
            eaffffff
            3c000000 1800 0505 03000000 00000000
            1e00 0100");
        buf.extend_from_slice(b"Nexthop id does not exist\0\0\0");
        buf.extend(hex("0800 0200 34000000"));
        let all = messages(&buf);
        assert_eq!(all[0].header.seq, 3);
        let err = KernelError {
            errno: 22,
            message: Some("Nexthop id does not exist".into()),
            offset: Some(52),
        };
        assert_eq!(all[0].body, Ok(Body::Error(err.clone())));
        assert!(
            err.to_string()
                .starts_with("Nexthop id does not exist (Invalid argument")
        );
    }

    #[test]
    fn error_echoing_the_request() {
        // Without NETLINK_CAP_ACK the request follows in full (24 bytes
        // here), the extended ACK after it.
        let buf = hex("
            40000000 0200 0002 04000000 00000000
            efffffff
            18000000 6800 0505 04000000 00000000 02 00 ba 00 00000000
            0900 0100 65786973 74 000000
            0800 0200 18000000");
        assert_eq!(
            one(&buf),
            Body::Error(KernelError {
                errno: 17,
                message: Some("exist".into()),
                offset: Some(24),
            })
        );
    }

    #[test]
    fn ack_and_failed_dump() {
        let ack = hex("24000000 0200 0001 07000000 00000000 00000000
                       3c000000 1800 0505 07000000 00000000");
        assert_eq!(one(&ack), Body::Ack);
        let done = hex("14000000 0300 0200 08000000 00000000 fcffffff");
        assert_eq!(
            one(&done),
            Body::Error(KernelError {
                errno: 4,
                message: None,
                offset: None,
            })
        );
    }

    #[test]
    fn nexthop_group_and_dead_gateway() {
        let group = hex("
            3c000000 6800 0200 00000000 00000000
            00 00 ba 00 00000000
            0800 0100 0a000000
            1400 0200 07000000 00 00 0000 08000000 02 00 0000
            0600 0300 0000 0000");
        let Body::Nexthop(nh) = one(&group) else {
            panic!()
        };
        assert_eq!(nh.id, 10);
        assert_eq!(
            nh.group,
            [
                GroupMember { id: 7, weight: 1 },
                GroupMember { id: 8, weight: 3 },
            ]
        );
        assert_eq!(nh.to_string(), "id 10 group 7/8,3 proto bgp");

        let dead = hex("
            34000000 6800 0200 00000000 00000000
            0a fd ba 00 11000000
            0800 0100 0b000000
            1400 0600 20010db8 00000000 00000000 00000002");
        let Body::Nexthop(nh) = one(&dead) else {
            panic!()
        };
        assert!(nh.is_dead());
        assert_eq!(nh.gateway, Some(v6("2001:db8::2")));

        let no_id = hex("18000000 6800 0200 00000000 00000000 02 00 ba 00 00000000");
        assert_eq!(
            messages(&no_id)[0].body,
            Err(DecodeError::Missing {
                kind: RTM_NEWNEXTHOP,
                attr: 1,
            })
        );
    }

    #[test]
    fn link() {
        let buf = hex("
            34000000 1000 0200 00000000 00000000
            00 00 0100 03000000 43100100 00000000
            0900 0300 65746830 00 000000
            0500 1000 06 000000");
        assert_eq!(
            one(&buf),
            Body::Link(Link {
                index: 3,
                name: "eth0".into(),
                flags: IFF_UP | IFF_RUNNING | IFF_LOWER_UP | 0x1002,
                operstate: Some(6),
            })
        );
    }

    #[test]
    fn address_prefers_ifa_local() {
        let buf = hex("
            3c000000 1400 0200 00000000 00000000
            02 1e 80 00 03000000
            0800 0100 c0000202
            0800 0200 c0000201
            0900 0300 65746830 00 000000
            0800 0800 80020000");
        assert_eq!(
            one(&buf),
            Body::Address(Address {
                index: 3,
                addr: v4("192.0.2.1"),
                prefix_len: 30,
                scope: 0,
                flags: 0x280,
                label: Some("eth0".into()),
            })
        );
    }

    #[test]
    fn bad_body_does_not_stop_the_dump() {
        // Family 7 (AF_BRIDGE route), then an attribute running past the end,
        // then DONE.
        let buf = hex("
            1c000000 1800 0200 01000000 00000000 07 00 00 00 fe 00 00 01 00000000
            24000000 1800 0200 01000000 00000000 02 18 00 00 fe ba 00 01 00000000
                     4000 0100 c6336400
            14000000 0300 0200 01000000 00000000 00000000");
        let all = messages(&buf);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].body, Err(DecodeError::Family(7)));
        assert_eq!(
            all[1].body,
            Err(DecodeError::Attribute {
                kind: RTM_NEWROUTE,
                attr: 1,
            })
        );
        assert_eq!(all[2].body, Ok(Body::Done));
    }
}

#[test]
fn framing_errors_end_the_iteration() {
    let short: Vec<_> = parse(&[0; 10]).collect();
    assert_eq!(short, [Err(DecodeError::Truncated)]);
    let mut tiny = vec![0; 16];
    tiny[..4].copy_from_slice(&8u32.to_ne_bytes());
    assert_eq!(
        parse(&tiny).collect::<Vec<_>>(),
        [Err(DecodeError::BadLength(8))]
    );
    let mut long = vec![0; 16];
    long[..4].copy_from_slice(&17u32.to_ne_bytes());
    assert_eq!(
        parse(&long).collect::<Vec<_>>(),
        [Err(DecodeError::BadLength(17))]
    );
}

/// Found by fuzzing: an error field of i32::MIN must not overflow on negation.
#[test]
fn error_field_minimum() {
    let mut buf = vec![0; 36];
    buf[..4].copy_from_slice(&36u32.to_ne_bytes());
    buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    buf[6..8].copy_from_slice(&NLM_F_CAPPED.to_ne_bytes());
    buf[16..20].copy_from_slice(&i32::MIN.to_ne_bytes());
    assert!(matches!(one(&buf), Body::Error(_)));
}

#[test]
fn batch_numbers_requests() {
    let mut batch = Batch::new(u32::MAX);
    let a = batch.add_route(&Route::via_nexthop(
        prefix("192.0.2.0/24"),
        1,
        254,
        RTPROT_BGP,
        20,
    ));
    let b = batch.delete_nexthop(1);
    let c = batch.dump_links();
    assert_eq!((a, b, c), (u32::MAX, 0, 1));
    let kinds: Vec<_> = batch.requests().iter().map(|r| (r.kind, r.dump)).collect();
    assert_eq!(
        kinds,
        [
            (RTM_NEWROUTE, false),
            (RTM_DELNEXTHOP, false),
            (RTM_GETLINK, true)
        ]
    );
    // Three requests back to back, each aligned.
    let seqs: Vec<_> = parse(batch.bytes())
        .map(|m| m.unwrap().header.seq)
        .collect();
    assert_eq!(seqs, [u32::MAX, 0, 1]);
    batch.clear();
    assert!(batch.is_empty());
    assert_eq!(batch.next_seq(), 2);
}

/// Encoded requests decode to what went in (the kernel's replies have the
/// same layout).
#[test]
fn round_trips() {
    let routes = [
        Route::via_nexthop(
            prefix("2001:db8:100::/48"),
            9,
            RT_TABLE_MAIN,
            RTPROT_BGP,
            20,
        ),
        Route {
            dst: prefix("0.0.0.0/0"),
            table: RT_TABLE_LOCAL,
            protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK,
            kind: RTN_BLACKHOLE,
            flags: RTNH_F_ONLINK,
            priority: None,
            gateway: Some(v4("10.0.0.1")),
            oif: Some(2),
            nh_id: None,
            prefsrc: Some(v4("10.0.0.2")),
            multipath: Vec::new(),
        },
        Route {
            gateway: None,
            oif: None,
            nh_id: None,
            multipath: vec![
                RouteHop {
                    flags: 0,
                    weight: 1,
                    oif: 3,
                    gateway: Some(v4("10.0.0.1")),
                },
                RouteHop {
                    flags: RTNH_F_LINKDOWN as u8,
                    weight: 256,
                    oif: 4,
                    gateway: Some(v6("fe80::2")),
                },
                RouteHop {
                    flags: 0,
                    weight: 2,
                    oif: 5,
                    gateway: None,
                },
            ],
            ..Route::via_nexthop(prefix("172.16.0.0/16"), 0, RT_TABLE_MAIN, RTPROT_STATIC, 0)
        },
    ];
    for route in routes {
        let mut batch = Batch::new(1);
        batch.add_route(&route);
        assert_eq!(one(batch.bytes()), Body::Route(route));
    }
    let nexthops = [
        Nexthop::gateway(1, v6("fe80::1"), 4, RTPROT_BGP),
        Nexthop {
            id: 2,
            family: AF_UNSPEC,
            protocol: RTPROT_BGP,
            flags: 0,
            oif: None,
            gateway: None,
            blackhole: false,
            group: vec![
                GroupMember { id: 1, weight: 1 },
                GroupMember {
                    id: 3,
                    weight: 65536,
                },
            ],
        },
    ];
    for nh in nexthops {
        let mut batch = Batch::new(1);
        batch.add_nexthop(&nh);
        assert_eq!(one(batch.bytes()), Body::Nexthop(nh));
    }
}

// --- against the real kernel ---

const NETNS_ENV: &str = "ANSAGE_NETLINK_NETNS";

/// Runs [`in_namespace`] in a new user + network namespace (`unshare -rn`:
/// CAP_NET_ADMIN there without being root here), by running this test
/// binary again. Skips when unprivileged user namespaces are not allowed.
#[test]
fn kernel_in_namespace() {
    if std::env::var_os(NETNS_ENV).is_some() {
        in_namespace();
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let out = match Command::new("unshare")
        .arg("-rn")
        .arg(exe)
        .args(["tests::kernel_in_namespace", "--exact", "--nocapture"])
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
    let out = Command::new("sh").args(["-ec", script]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{script}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

struct Kernel {
    socket: Socket,
    seq: u32,
}

impl Kernel {
    /// Runs the requests `f` writes, returns the decoded replies (final
    /// ACK/DONE left out).
    fn run(&mut self, f: impl FnOnce(&mut Batch)) -> Vec<Body> {
        let mut batch = Batch::new(self.seq);
        f(&mut batch);
        self.seq = batch.next_seq();
        let replies = self.socket.run(&batch).unwrap();
        replies
            .into_iter()
            .map(|r| r.body.expect("reply decodes"))
            .filter(|b| !matches!(b, Body::Ack | Body::Done))
            .collect()
    }

    fn ok(&mut self, f: impl FnOnce(&mut Batch)) {
        let errors = self.run(f);
        assert!(errors.is_empty(), "{errors:?}");
    }

    fn routes(&mut self, family: u8) -> Vec<Route> {
        let replies = self.run(|b| {
            b.dump_routes(family, RT_TABLE_MAIN, RTPROT_BGP);
        });
        replies
            .into_iter()
            .map(|b| match b {
                Body::Route(r) => r,
                other => panic!("{other:?}"),
            })
            .collect()
    }

    fn lookup(&mut self, addr: IpAddr) -> Route {
        match self
            .run(|b| {
                b.lookup_route(addr);
            })
            .as_slice()
        {
            [Body::Route(r)] => r.clone(),
            other => panic!("{other:?}"),
        }
    }
}

fn in_namespace() {
    if Command::new("ip").arg("-V").output().is_err() {
        println!("skipped: no ip command");
        return;
    }
    sh("ip link set lo up
        ip link add d0 type dummy
        ip link set d0 up
        ip addr add 10.0.0.1/24 dev d0
        ip -6 addr add 2001:db8:ff::1/64 dev d0 nodad
        ip route add 203.0.113.0/24 via 10.0.0.3
        ip link add d1 type dummy
        ip link set d1 up
        ip addr add 10.1.0.1/24 dev d1
        ip route add 172.16.0.0/16 nexthop via 10.0.0.4 dev d0 nexthop via 10.1.0.4 dev d1 weight 3");
    let mut k = Kernel {
        socket: Socket::open().unwrap(),
        seq: 1,
    };

    // Interfaces and addresses.
    let links: Vec<Link> = k
        .run(|b| {
            b.dump_links();
        })
        .into_iter()
        .filter_map(|b| match b {
            Body::Link(l) => Some(l),
            _ => None,
        })
        .collect();
    let d0 = links
        .iter()
        .find(|l| l.name == "d0")
        .expect("d0 listed")
        .clone();
    assert!(d0.is_running(), "{d0:?}");
    let addrs: Vec<Address> = k
        .run(|b| {
            b.dump_addresses(AF_UNSPEC);
        })
        .into_iter()
        .filter_map(|b| match b {
            Body::Address(a) => Some(a),
            _ => None,
        })
        .collect();
    for (addr, len) in [(v4("10.0.0.1"), 24), (v6("2001:db8:ff::1"), 64)] {
        assert!(
            addrs
                .iter()
                .any(|a| a.addr == addr && a.prefix_len == len && a.index == d0.index),
            "{addr} missing in {addrs:?}"
        );
    }

    // Nexthops and routes, all in one batch.
    let nh4 = Nexthop::gateway(100, v4("10.0.0.2"), d0.index, RTPROT_BGP);
    let nh6 = Nexthop::gateway(101, v6("2001:db8:ff::2"), d0.index, RTPROT_BGP);
    let r4 = Route::via_nexthop(
        prefix("198.51.100.0/24"),
        100,
        RT_TABLE_MAIN,
        RTPROT_BGP,
        20,
    );
    let r6 = Route::via_nexthop(
        prefix("2001:db8:100::/48"),
        101,
        RT_TABLE_MAIN,
        RTPROT_BGP,
        20,
    );
    k.ok(|b| {
        b.add_nexthop(&nh4);
        b.add_nexthop(&nh6);
        b.add_route(&r4);
        b.add_route(&r6);
    });
    // iproute2's view of the same table.
    let ip = sh("ip route show proto bgp; ip -6 route show proto bgp");
    assert!(
        ip.contains("198.51.100.0/24 nhid 100 via 10.0.0.2 dev d0"),
        "{ip}"
    );
    assert!(
        ip.contains("2001:db8:100::/48 nhid 101 via 2001:db8:ff::2 dev d0"),
        "{ip}"
    );

    // The dump is filtered in the kernel: 203.0.113.0/24 (proto boot) is not
    // there.
    let routes = k.routes(AF_INET);
    assert_eq!(routes.len(), 1, "{routes:?}");
    assert_eq!(routes[0].dst, r4.dst);
    assert_eq!(routes[0].nh_id, Some(100));
    assert_eq!(routes[0].priority, Some(20));
    let routes = k.routes(AF_INET6);
    assert_eq!(routes.len(), 1, "{routes:?}");
    assert_eq!(routes[0].dst, r6.dst);

    // Lookups return the FIB entry that matches.
    let hit = k.lookup(v4("198.51.100.7"));
    assert_eq!(
        (hit.dst, hit.protocol, hit.nh_id),
        (r4.dst, RTPROT_BGP, Some(100))
    );
    let connected = k.lookup(v4("10.0.0.2"));
    assert_eq!(connected.dst, prefix("10.0.0.0/24"));
    assert_eq!(connected.protocol, RTPROT_KERNEL);
    assert_eq!(connected.scope, RT_SCOPE_LINK);
    assert_eq!(connected.oif, Some(d0.index));
    let other = k.lookup(v4("203.0.113.9"));
    assert_eq!(
        (other.protocol, other.gateway),
        (RTPROT_BOOT, Some(v4("10.0.0.3")))
    );
    // An ECMP route without nexthop objects: RTA_MULTIPATH legs.
    let ecmp = k.lookup(v4("172.16.1.1"));
    assert_eq!(
        (ecmp.oif, ecmp.gateway, ecmp.nh_id),
        (None, None, None),
        "{ecmp}"
    );
    let legs: Vec<(Option<IpAddr>, u16)> = ecmp
        .multipath
        .iter()
        .map(|l| (l.gateway, l.weight))
        .collect();
    assert_eq!(
        legs,
        [(Some(v4("10.0.0.4")), 1), (Some(v4("10.1.0.4")), 3)],
        "{ecmp}"
    );
    assert_eq!(ecmp.multipath[0].oif, d0.index);
    sh("ip link set d1 down");
    let ecmp = k.lookup(v4("172.16.1.1"));
    assert!(!ecmp.multipath[0].is_dead(), "{ecmp}");
    assert!(ecmp.multipath[1].is_dead(), "{ecmp}");

    // Moving the nexthop moves the route with it.
    k.ok(|b| {
        b.add_nexthop(&Nexthop::gateway(100, v4("10.0.0.3"), d0.index, RTPROT_BGP));
    });
    let ip = sh("ip route show 198.51.100.0/24");
    assert!(ip.contains("nhid 100 via 10.0.0.3 dev d0"), "{ip}");
    let nexthops: Vec<Nexthop> = k
        .run(|b| {
            b.dump_nexthops();
        })
        .into_iter()
        .filter_map(|b| match b {
            Body::Nexthop(n) => Some(n),
            _ => None,
        })
        .collect();
    let moved = nexthops.iter().find(|n| n.id == 100).expect("nexthop 100");
    assert_eq!(moved.gateway, Some(v4("10.0.0.3")));
    assert_eq!(moved.protocol, RTPROT_BGP);

    // A refused request comes back with the kernel's reason.
    let bad = Route::via_nexthop(prefix("192.0.2.0/24"), 999, RT_TABLE_MAIN, RTPROT_BGP, 20);
    let replies = k.run(|b| {
        b.add_route(&bad);
    });
    let [Body::Error(err)] = replies.as_slice() else {
        panic!("{replies:?}")
    };
    assert_ne!(err.errno, 0);
    let message = err.message.as_deref().unwrap_or_default();
    assert!(message.contains("Nexthop id does not exist"), "{err}");

    // Deleting a nexthop deletes its routes.
    k.ok(|b| {
        b.delete_route(&r4);
        b.delete_nexthop(101);
        b.delete_nexthop(100);
    });
    assert!(k.routes(AF_UNSPEC).is_empty());
    assert_eq!(sh("ip nexthop show"), "");
}
