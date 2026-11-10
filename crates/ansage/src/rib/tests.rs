use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::mpsc as std_mpsc,
};

use crate::{
    config::Config,
    policy::{Export, Import},
};
use ansage_bgp::{
    session::{PeerInfo, Retain},
    wire::{
        AsPath, GRACEFUL_SHUTDOWN, Message, MpReach, Negotiated, NextHop, Origin, PathAttr,
        Prefix4, Update, split_message, type_code,
    },
};
use bytes::BytesMut;
use tokio::sync::oneshot;

use super::{
    msg::{Announce, DrainChange, OwnChange},
    *,
};
use crate::fib::FibMsg;

const LOCAL_ASN: u32 = 64500;

fn p(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn rib(limit_v4: Option<u32>) -> Rib {
    let mut peers = HashMap::new();
    for peer in [1, 2] {
        peers.insert(
            peer,
            PeerSettings {
                import: Import::All,
                max_prefixes_ipv4: limit_v4,
                ..PeerSettings::default()
            },
        );
    }
    Rib::new(RibConfig {
        local_asn: LOCAL_ASN,
        announce: vec![p("192.0.2.0/24"), p("2001:db8:1::/48")],
        max_prefix_restart: Duration::from_secs(300),
        peers,
        install_families: [true, true],
    })
}

fn up(peer: SourceId, asn: u32) -> (RibMsg, mpsc::Receiver<PeerMsg>) {
    let (tx, rx) = mpsc::channel(4);
    let info = PeerInfo {
        asn,
        bgp_id: Ipv4Addr::new(203, 0, 113, peer as u8),
        hold_time: 90,
        negotiated: Negotiated {
            four_octet_as: true,
            extended_message: false,
            ibgp: asn == LOCAL_ASN,
            extended_next_hop: false,
        },
        families: vec![(Afi::IPV4, Safi::UNICAST), (Afi::IPV6, Safi::UNICAST)],
        route_refresh: true,
        graceful_restart: None,
        offered_graceful_restart: None,
        role: None,
    };
    let msg = RibMsg::Up(Box::new(PeerUp {
        peer,
        info,
        addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, peer as u8)),
        local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        next_hop_ipv4: Some(Ipv4Addr::new(192, 0, 2, 1)),
        next_hop_ipv6: Some("2001:db8::1".parse().unwrap()),
        next_hop_ipv6_link_local: None,
        oif: None,
        tx,
    }));
    (msg, rx)
}

fn learned(path: &[u32], prefixes: &[&str]) -> Update {
    Update {
        attrs: vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence(path.to_vec())),
            PathAttr::NextHop(Ipv4Addr::new(127, 0, 0, 2)),
        ],
        nlri: prefixes.iter().map(|s| s.parse().unwrap()).collect(),
        ..Update::default()
    }
}

/// Handles `msgs`, flushes, and returns what peers got.
fn run(rib: &mut Rib, msgs: Vec<RibMsg>) -> Vec<(SourceId, PeerMsg)> {
    let mut out = Vec::new();
    for msg in msgs {
        rib.handle(msg, &mut out);
    }
    rib.flush(&mut out);
    out
}

fn exports(out: Vec<(SourceId, PeerMsg)>, peer: SourceId) -> Vec<ExportBatch> {
    out.into_iter()
        .filter(|(p, _)| *p == peer)
        .filter_map(|(_, m)| match m {
            PeerMsg::Export(batch) => Some(batch),
            PeerMsg::Teardown { .. } | PeerMsg::RouteRefresh(_) => None,
        })
        .collect()
}

#[test]
fn new_peer_gets_own_prefixes_then_end_of_rib() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    let mut batches = exports(run(&mut rib, vec![msg]), 1);
    assert_eq!(batches.len(), 1);
    let batch = batches.remove(0);
    assert_eq!(batch.end_of_rib, [Afi::IPV4, Afi::IPV6]);
    assert!(batch.withdraw.is_empty());

    let [group] = &batch.announce[..] else {
        panic!(
            "own prefixes share one attribute set: {:#?}",
            batch.announce
        );
    };
    let mut prefixes = group.prefixes.clone();
    prefixes.sort();
    assert_eq!(prefixes, [p("192.0.2.0/24"), p("2001:db8:1::/48")]);
    assert_eq!(
        group.attrs,
        [
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([LOCAL_ASN])),
            PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
        ]
    );
    assert_eq!(
        group.next_hop,
        Some(NextHop::V6 {
            global: "2001:db8::1".parse().unwrap(),
            link_local: None
        })
    );
}

#[test]
fn ibgp_peer_gets_local_pref_and_empty_path() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, LOCAL_ASN);
    let batch = exports(run(&mut rib, vec![msg]), 1).remove(0);
    assert_eq!(
        batch.announce[0].attrs,
        [
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::default()),
            PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
            PathAttr::LocalPref(100),
        ]
    );
}

#[test]
fn learned_routes_are_stored_but_never_exported() {
    let mut rib = rib(None);
    let (up1, _rx1) = up(1, 64501);
    let (up2, _rx2) = up(2, 64502);
    run(&mut rib, vec![up1, up2]);
    let out = run(
        &mut rib,
        vec![
            RibMsg::Ready { peer: 2 },
            RibMsg::Update {
                peer: 1,
                update: learned(&[64501, 3356], &["198.51.100.0/24", "203.0.113.0/24"]),
            },
        ],
    );
    assert!(exports(out, 2).is_empty(), "nothing to send to peer 2");
    let stats = rib.stats();
    assert_eq!(stats.prefixes_ipv4, 3, "own /24 + 2 learned");
    let (source, attrs) = rib.best_route(&p("198.51.100.0/24")).unwrap();
    assert_eq!(source, 1);
    assert_eq!(attrs[1], PathAttr::AsPath(AsPath::sequence([64501, 3356])));
}

#[test]
fn exports_wait_for_ready() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    assert_eq!(exports(run(&mut rib, vec![msg]), 1).len(), 1);
    // A refresh makes work, but the peer has not asked for more yet.
    let out = run(
        &mut rib,
        vec![RibMsg::RouteRefresh {
            peer: 1,
            afi: Afi::IPV4,
            safi: Safi::UNICAST,
        }],
    );
    assert!(exports(out, 1).is_empty());
    let batches = exports(run(&mut rib, vec![RibMsg::Ready { peer: 1 }]), 1);
    assert_eq!(batches[0].announce[0].prefixes, [p("192.0.2.0/24")]);
    assert!(batches[0].end_of_rib.is_empty(), "End-of-RIB only once");
}

#[test]
fn best_path_and_fallback_when_a_peer_goes_down() {
    let mut rib = rib(None);
    let (up1, _rx1) = up(1, 64501);
    let (up2, _rx2) = up(2, 64502);
    run(
        &mut rib,
        vec![
            up1,
            up2,
            RibMsg::Update {
                peer: 1,
                update: learned(&[64501, 3356, 1299], &["198.51.100.0/24"]),
            },
            RibMsg::Update {
                peer: 2,
                update: learned(&[64502, 1299], &["198.51.100.0/24"]),
            },
        ],
    );
    let prefix = p("198.51.100.0/24");
    assert_eq!(rib.route_count(&prefix), 2);
    assert_eq!(rib.best_route(&prefix).unwrap().0, 2, "shorter AS path");

    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 2,
            retain: None,
        }],
    );
    assert_eq!(rib.best_route(&prefix).unwrap().0, 1);
    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: None,
        }],
    );
    assert_eq!(rib.best_route(&prefix), None);
    // Only the set of our own prefixes is left in the pool.
    assert_eq!(rib.stats().attr_sets, 1);
}

#[test]
fn withdrawals_and_treat_as_withdraw() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    let update = learned(&[64501], &["198.51.100.0/24", "203.0.113.0/24"]);
    run(&mut rib, vec![msg, RibMsg::Update { peer: 1, update }]);

    let withdraw = Update {
        withdrawn: vec!["198.51.100.0/24".parse().unwrap()],
        ..Update::default()
    };
    let mut malformed = learned(&[64501], &["203.0.113.0/24"]);
    malformed.treat_as_withdraw = Some(ansage_bgp::wire::DecodeError::MalformedAsPath);
    run(
        &mut rib,
        vec![
            RibMsg::Update {
                peer: 1,
                update: withdraw,
            },
            RibMsg::Update {
                peer: 1,
                update: malformed,
            },
        ],
    );
    assert_eq!(rib.best_route(&p("198.51.100.0/24")), None);
    assert_eq!(rib.best_route(&p("203.0.113.0/24")), None);
    assert_eq!(rib.stats().prefixes_ipv4, 1, "only our own prefix");
}

#[test]
fn ipv6_routes_keep_their_next_hop() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    let next_hop = NextHop::V6 {
        global: "2001:db8:ffff::2".parse().unwrap(),
        link_local: None,
    };
    let update = Update {
        attrs: vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([64501])),
        ],
        mp_reach: Some(MpReach {
            afi: Afi::IPV6,
            safi: Safi::UNICAST,
            next_hop,
            nlri: vec![p("2001:db8:ffff::/48")],
        }),
        ..Update::default()
    };
    run(&mut rib, vec![msg, RibMsg::Update { peer: 1, update }]);
    assert_eq!(rib.stats().prefixes_ipv6, 2);
    assert_eq!(rib.best_route(&p("2001:db8:ffff::/48")).unwrap().0, 1);
}

#[test]
fn max_prefix_tears_down() {
    let mut rib = rib(Some(2));
    let (msg, _rx) = up(1, 64501);
    run(&mut rib, vec![msg]);
    let update = learned(
        &[64501],
        &["198.51.100.0/24", "198.51.101.0/24", "198.51.102.0/24"],
    );
    let out = run(&mut rib, vec![RibMsg::Update { peer: 1, update }]);
    let teardown = out.into_iter().find_map(|(peer, m)| match m {
        PeerMsg::Teardown {
            notification,
            retry_after,
        } if peer == 1 => Some((notification, retry_after)),
        _ => None,
    });
    let (n, retry_after) = teardown.expect("teardown sent");
    assert_eq!((n.code, n.subcode), (6, 1));
    assert_eq!(
        &n.data[..],
        &[0, 1, 1, 0, 0, 0, 2],
        "AFI 1, SAFI 1, limit 2"
    );
    assert_eq!(retry_after, Duration::from_secs(300));

    // Further updates are ignored until the session is down.
    let update = learned(&[64501], &["198.51.103.0/24"]);
    run(&mut rib, vec![RibMsg::Update { peer: 1, update }]);
    assert_eq!(rib.best_route(&p("198.51.103.0/24")), None);
}

#[test]
fn encoded_batch_decodes_back() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    let batch = exports(run(&mut rib, vec![msg]), 1).remove(0);
    let neg = Negotiated {
        four_octet_as: true,
        extended_message: false,
        ibgp: false,
        extended_next_hop: false,
    };
    let mut buf = BytesMut::from(&encode_batch(&batch, &neg).unwrap()[..]);
    let mut updates = Vec::new();
    while let Some((kind, body)) = split_message(&mut buf, 4096).unwrap() {
        let Message::Update(update) = Message::decode(kind, body, &neg).unwrap() else {
            panic!("not an UPDATE");
        };
        updates.push(update);
    }
    // IPv4 announce, IPv6 announce, two End-of-RIBs.
    assert_eq!(updates.len(), 4);
    assert_eq!(
        updates[0].nlri,
        ["192.0.2.0/24".parse::<Prefix4>().unwrap()]
    );
    assert!(updates[1].attr(type_code::NEXT_HOP).is_none());
    assert_eq!(updates[2].is_end_of_rib(), Some((Afi::IPV4, Safi::UNICAST)));
    assert_eq!(updates[3].is_end_of_rib(), Some((Afi::IPV6, Safi::UNICAST)));
}

#[test]
fn prefix_withdrawn_and_announced_in_one_update_is_announced() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    let mut update = learned(&[64501], &["198.51.100.0/24"]);
    update.withdrawn = vec!["198.51.100.0/24".parse().unwrap()];
    run(&mut rib, vec![msg, RibMsg::Update { peer: 1, update }]);
    assert_eq!(rib.best_route(&p("198.51.100.0/24")).unwrap().0, 1);
}

#[test]
fn ineligible_routes_are_not_stored() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    // Our own AS in the path (RFC 4271 §9.1.2).
    let looped = learned(&[64501, LOCAL_ASN, 3356], &["198.51.100.0/24"]);
    // Multicast prefix (RFC 4271 §6.3).
    let multicast = learned(&[64501], &["224.0.0.0/4"]);
    // NEXT_HOP is our own address 127.0.0.1.
    let mut own_next_hop = learned(&[64501], &["203.0.113.0/24"]);
    own_next_hop.attrs[2] = PathAttr::NextHop(Ipv4Addr::new(127, 0, 0, 1));
    run(
        &mut rib,
        vec![
            msg,
            RibMsg::Update {
                peer: 1,
                update: looped,
            },
            RibMsg::Update {
                peer: 1,
                update: multicast,
            },
            RibMsg::Update {
                peer: 1,
                update: own_next_hop,
            },
        ],
    );
    assert_eq!(rib.stats().prefixes_ipv4, 1, "only our own prefix");
}

#[test]
fn route_refresh_for_other_safi_is_ignored() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    run(&mut rib, vec![msg]);
    let out = run(
        &mut rib,
        vec![
            RibMsg::Ready { peer: 1 },
            RibMsg::RouteRefresh {
                peer: 1,
                afi: Afi::IPV4,
                safi: Safi(2),
            },
        ],
    );
    assert!(
        exports(out, 1).is_empty(),
        "multicast refresh must not resend unicast"
    );
}

#[test]
fn import_none_stores_nothing() {
    let mut config = RibConfig {
        local_asn: LOCAL_ASN,
        announce: vec![p("192.0.2.0/24")],
        max_prefix_restart: Duration::from_secs(300),
        peers: HashMap::new(),
        install_families: [false, false],
    };
    // No settings for peer 1: the default is import "none" (RFC 8212).
    config.peers.insert(3, PeerSettings::default());
    let mut rib = Rib::new(config);
    let (msg, _rx) = up(1, 64501);
    let update = learned(&[64501], &["198.51.100.0/24"]);
    let batches = exports(
        run(&mut rib, vec![msg, RibMsg::Update { peer: 1, update }]),
        1,
    );
    assert_eq!(rib.stats().prefixes_ipv4, 1, "only our own prefix");
    assert_eq!(batches.len(), 1, "own prefixes are still announced");
}

#[test]
fn export_none_sends_only_end_of_rib() {
    let mut rib = rib(None);
    rib.config.peers.get_mut(&1).unwrap().export = Export::None;
    let (msg, _rx) = up(1, 64501);
    let mut batches = exports(run(&mut rib, vec![msg]), 1);
    assert_eq!(batches.len(), 1);
    let batch = batches.remove(0);
    assert!(batch.announce.is_empty(), "no own prefixes: {batch:#?}");
    assert!(batch.withdraw.is_empty());
    assert_eq!(batch.end_of_rib, [Afi::IPV4, Afi::IPV6]);

    // Its routes are still learned, and later changes send nothing.
    let update = learned(&[64501], &["198.51.100.0/24"]);
    let out = run(
        &mut rib,
        vec![
            RibMsg::Ready { peer: 1 },
            RibMsg::Update { peer: 1, update },
        ],
    );
    assert!(exports(out, 1).is_empty());
    assert_eq!(
        rib.stats().prefixes_ipv4,
        2,
        "own prefix and the learned one"
    );
    let (_, out) = own(&mut rib, true, &["203.0.113.0/24"]);
    assert!(
        exports(out, 1).is_empty(),
        "a new own prefix is not sent either"
    );
}

fn ask<T>(rib: &mut Rib, query: impl FnOnce(oneshot::Sender<T>) -> Query) -> T {
    let (tx, mut rx) = oneshot::channel();
    let mut out = Vec::new();
    rib.handle(RibMsg::Query(query(tx)), &mut out);
    assert!(out.is_empty(), "queries send nothing to peers");
    rx.try_recv().expect("answered right away")
}

#[test]
fn summary_counts_routes_per_peer() {
    let mut rib = rib(None);
    let (up1, _rx1) = up(1, 64501);
    let (up2, _rx2) = up(2, 64502);
    let update = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["10.0.0.0/8", "10.1.0.0/16"]),
    };
    run(&mut rib, vec![up1, up2, update]);

    let summary = ask(&mut rib, Query::Summary);
    assert_eq!(summary.own, [p("192.0.2.0/24"), p("2001:db8:1::/48")]);
    assert_eq!(summary.stats.prefixes_ipv4, 3);
    assert_eq!(summary.stats.prefixes_ipv6, 1);
    let [one, two] = &summary.peers[..] else {
        panic!("two peers: {:?}", summary.peers);
    };
    assert_eq!((one.peer, one.received_ipv4, one.received_ipv6), (1, 2, 0));
    assert_eq!((two.peer, two.received_ipv4), (2, 0));
    // Both got our two prefixes and their End-of-RIB.
    for peer in [one, two] {
        assert_eq!((peer.advertised_ipv4, peer.advertised_ipv6), (1, 1));
        assert!(peer.initial_sync_done);
        assert_eq!(peer.pending, 0);
        assert!(!peer.torn_down);
    }
}

#[test]
fn prefix_query_lists_candidates_best_first() {
    let mut rib = rib(None);
    let (up1, _rx1) = up(1, 64501);
    let (up2, _rx2) = up(2, 64502);
    let longer = RibMsg::Update {
        peer: 1,
        update: learned(&[64501, 64999], &["10.0.0.0/8"]),
    };
    let shorter = RibMsg::Update {
        peer: 2,
        update: learned(&[64502], &["10.0.0.0/8"]),
    };
    run(&mut rib, vec![up1, up2, longer, shorter]);

    let prefix = p("10.0.0.0/8");
    let routes = ask(&mut rib, |reply| Query::Prefix { prefix, reply });
    let sources: Vec<_> = routes.iter().map(|r| (r.source, r.best)).collect();
    assert_eq!(sources, [(2, true), (1, false)], "shorter AS_PATH wins");
    assert!(routes.iter().all(|r| r.prefix == prefix));
    assert!(
        routes[0]
            .attrs
            .contains(&PathAttr::AsPath(AsPath::sequence(vec![64502])))
    );

    // Our own prefix comes from LOCAL; an unknown prefix has no routes.
    let prefix = p("192.0.2.0/24");
    let own = ask(&mut rib, |reply| Query::Prefix { prefix, reply });
    assert_eq!(own.len(), 1);
    assert_eq!((own[0].source, own[0].best), (LOCAL, true));
    let prefix = p("198.51.100.0/24");
    assert!(ask(&mut rib, |reply| Query::Prefix { prefix, reply }).is_empty());
}

#[test]
fn routes_query_is_limited_and_sorted() {
    let mut rib = rib(None);
    let (up1, _rx1) = up(1, 64501);
    let update = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["10.2.0.0/16", "10.1.0.0/16", "10.3.0.0/16"]),
    };
    run(&mut rib, vec![up1, update]);

    let all = ask(&mut rib, |reply| Query::Routes {
        afi: Afi::IPV4,
        limit: 100,
        reply,
    });
    assert_eq!(all.total, 4);
    let prefixes: Vec<_> = all.routes.iter().map(|r| r.prefix).collect();
    assert_eq!(
        prefixes,
        ["10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", "192.0.2.0/24"].map(p)
    );
    assert!(all.routes.iter().all(|r| r.best));

    let some = ask(&mut rib, |reply| Query::Routes {
        afi: Afi::IPV4,
        limit: 2,
        reply,
    });
    assert_eq!((some.total, some.routes.len()), (4, 2));

    let v6 = ask(&mut rib, |reply| Query::Routes {
        afi: Afi::IPV6,
        limit: 100,
        reply,
    });
    assert_eq!(v6.total, 1);
    assert!(
        v6.routes[0].mp_next_hop.is_none(),
        "own routes get the next hop on export"
    );
}

/// An IPv6 route over the (IPv4) test session with this MP_REACH next hop.
fn learned_v6(next_hop: NextHop, prefix: &str) -> Update {
    Update {
        attrs: vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence(vec![64501])),
        ],
        mp_reach: Some(MpReach {
            afi: Afi::IPV6,
            safi: Safi::UNICAST,
            next_hop,
            nlri: vec![prefix.parse().unwrap()],
        }),
        ..Update::default()
    }
}

#[test]
fn any_own_address_as_next_hop_is_not_used() {
    // The session runs over IPv4 (127.0.0.1); our IPv6
    // next hop on it is 2001:db8::1 (see `up`).
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    let v6 = |global: &str, link_local: Option<&str>| NextHop::V6 {
        global: global.parse().unwrap(),
        link_local: link_local.map(|ll| ll.parse().unwrap()),
    };
    let updates = [
        // Our announced IPv6 next hop.
        learned_v6(v6("2001:db8::1", None), "2001:db8:a::/48"),
        // A foreign next hop (with its link-local) is fine.
        learned_v6(v6("2001:db8::2", Some("fe80::2")), "2001:db8:b::/48"),
        // Our IPv4 session address, IPv4-mapped.
        learned_v6(v6("::ffff:127.0.0.1", None), "2001:db8:c::/48"),
    ];
    let mut msgs = vec![msg];
    msgs.extend(updates.map(|update| RibMsg::Update { peer: 1, update }));
    // And an IPv4 route whose NEXT_HOP is our configured next_hop_ipv4.
    let mut v4 = learned(&[64501], &["203.0.113.0/24"]);
    v4.attrs[2] = PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1));
    msgs.push(RibMsg::Update {
        peer: 1,
        update: v4,
    });
    run(&mut rib, msgs);

    assert_eq!(
        rib.route_count(&p("2001:db8:a::/48")),
        0,
        "own IPv6 next hop"
    );
    assert_eq!(
        rib.route_count(&p("2001:db8:b::/48")),
        1,
        "foreign next hop is fine"
    );
    assert_eq!(
        rib.route_count(&p("2001:db8:c::/48")),
        0,
        "own address, IPv4-mapped"
    );
    assert_eq!(
        rib.route_count(&p("203.0.113.0/24")),
        0,
        "own next_hop_ipv4"
    );
}

fn own(rib: &mut Rib, announce: bool, prefixes: &[&str]) -> (OwnChange, Vec<(SourceId, PeerMsg)>) {
    let (reply, mut rx) = oneshot::channel();
    let msg = RibMsg::Own {
        announce,
        prefixes: prefixes.iter().map(|s| p(s)).collect(),
        reply,
    };
    let out = run(rib, vec![msg, RibMsg::Ready { peer: 1 }]);
    (rx.try_recv().unwrap(), out)
}

#[test]
fn own_prefixes_change_at_runtime() {
    let mut rib = rib(None);
    let (msg, _rx) = up(1, 64501);
    assert_eq!(exports(run(&mut rib, vec![msg]), 1).len(), 1);

    let (change, out) = own(&mut rib, true, &["198.51.100.0/24", "192.0.2.0/24"]);
    assert_eq!(change.changed, [p("198.51.100.0/24")]);
    assert_eq!(change.unchanged, [p("192.0.2.0/24")]);
    let batches = exports(out, 1);
    assert_eq!(batches[0].announce[0].prefixes, [p("198.51.100.0/24")]);

    // A peer's route for the same prefix does not keep it exported.
    let learned = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["198.51.100.0/24"]),
    };
    run(&mut rib, vec![learned]);
    let (change, out) = own(&mut rib, false, &["198.51.100.0/24"]);
    assert_eq!(change.changed, [p("198.51.100.0/24")]);
    let batches = exports(out, 1);
    assert_eq!(batches[0].withdraw, [p("198.51.100.0/24")]);
    assert!(batches[0].announce.is_empty());

    let (change, _) = own(&mut rib, false, &["198.51.100.0/24"]);
    assert_eq!(change.unchanged, [p("198.51.100.0/24")]);
}

/// Up with Graceful Restart: the peer kept forwarding state (F bit) or not.
fn up_gr(peer: SourceId, forwarding: bool) -> (RibMsg, mpsc::Receiver<PeerMsg>) {
    let (mut msg, rx) = up(peer, 64501);
    if let RibMsg::Up(up) = &mut msg {
        up.info.graceful_restart = Some(ansage_bgp::session::PeerGr {
            restart_time: 120,
            restarting: true,
            notification: true,
            families: [Afi::IPV4, Afi::IPV6]
                .map(|afi| ansage_bgp::wire::GrFamily {
                    afi,
                    safi: Safi::UNICAST,
                    forwarding,
                })
                .to_vec(),
        });
    }
    (msg, rx)
}

fn retain(secs: u64, families: &[Afi]) -> Option<Retain> {
    Some(Retain {
        restart_time: Duration::from_secs(secs),
        families: families.iter().map(|&afi| (afi, Safi::UNICAST)).collect(),
    })
}

fn eor(afi: Afi) -> Update {
    Update::end_of_rib(afi, Safi::UNICAST)
}

fn stale_count(rib: &Rib, peer: SourceId) -> Option<usize> {
    rib.summary()
        .peers
        .iter()
        .find(|p| p.peer == peer)
        .map(|p| p.stale)
}

/// Peer 1 up with Graceful Restart, two IPv4 routes and one IPv6 route.
fn rib_with_gr_peer() -> (Rib, mpsc::Receiver<PeerMsg>) {
    let mut rib = rib(None);
    let (msg, rx) = up_gr(1, true);
    let v6 = learned_v6(
        NextHop::V6 {
            global: "2001:db8::2".parse().unwrap(),
            link_local: None,
        },
        "2001:db8:99::/48",
    );
    run(
        &mut rib,
        vec![
            msg,
            RibMsg::Update {
                peer: 1,
                update: learned(&[64501], &["198.51.100.0/24", "203.0.113.0/24"]),
            },
            RibMsg::Update {
                peer: 1,
                update: v6,
            },
        ],
    );
    (rib, rx)
}

#[test]
fn graceful_restart_keeps_routes_until_end_of_rib() {
    let (mut rib, _rx) = rib_with_gr_peer();
    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: retain(120, &[Afi::IPV4, Afi::IPV6]),
        }],
    );
    // Still there, and still used.
    assert_eq!(rib.best_route(&p("198.51.100.0/24")).unwrap().0, 1);
    assert_eq!(rib.route_count(&p("2001:db8:99::/48")), 1);
    assert_eq!(
        stale_count(&rib, 1),
        Some(3),
        "a down peer with stale routes is listed"
    );
    assert!(rib.next_deadline().is_some());

    // Back: one IPv4 route sent again, then End-of-RIB removes the other.
    let (msg, _rx) = up_gr(1, true);
    run(
        &mut rib,
        vec![
            msg,
            RibMsg::Update {
                peer: 1,
                update: learned(&[64501], &["198.51.100.0/24"]),
            },
        ],
    );
    assert_eq!(stale_count(&rib, 1), Some(2));
    run(
        &mut rib,
        vec![RibMsg::Update {
            peer: 1,
            update: eor(Afi::IPV4),
        }],
    );
    assert_eq!(rib.route_count(&p("198.51.100.0/24")), 1);
    assert_eq!(rib.route_count(&p("203.0.113.0/24")), 0);
    assert_eq!(
        rib.route_count(&p("2001:db8:99::/48")),
        1,
        "IPv6 waits for its EoR"
    );
    run(
        &mut rib,
        vec![RibMsg::Update {
            peer: 1,
            update: eor(Afi::IPV6),
        }],
    );
    assert_eq!(rib.route_count(&p("2001:db8:99::/48")), 0);
    assert_eq!(stale_count(&rib, 1), Some(0));
    assert_eq!(rib.next_deadline(), None);
    // Counts stay right: one route left, withdrawing it does not underflow.
    let summary = rib.summary();
    assert_eq!(summary.peers[0].received_ipv4, 1);
    assert_eq!(summary.peers[0].received_ipv6, 0);
    let withdraw = Update {
        withdrawn: vec!["198.51.100.0/24".parse().unwrap()],
        ..Update::default()
    };
    run(
        &mut rib,
        vec![RibMsg::Update {
            peer: 1,
            update: withdraw,
        }],
    );
    assert_eq!(rib.summary().peers[0].received_ipv4, 0);
}

#[test]
fn stale_routes_time_out() {
    let (mut rib, _rx) = rib_with_gr_peer();
    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: retain(120, &[Afi::IPV4, Afi::IPV6]),
        }],
    );
    let deadline = rib.next_deadline().unwrap();
    rib.expire(deadline - Duration::from_secs(1));
    assert_eq!(rib.route_count(&p("198.51.100.0/24")), 1);
    rib.expire(deadline);
    assert_eq!(rib.route_count(&p("198.51.100.0/24")), 0);
    assert_eq!(rib.route_count(&p("2001:db8:99::/48")), 0);
    assert_eq!(stale_count(&rib, 1), None);
    assert_eq!(rib.stats().attr_sets, 1, "only our own attributes are left");

    // Back without an End-of-RIB: removed after the stale path time.
    let (mut rib, _rx) = rib_with_gr_peer();
    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: retain(120, &[Afi::IPV4, Afi::IPV6]),
        }],
    );
    let (msg, _rx2) = up_gr(1, true);
    run(&mut rib, vec![msg]);
    let deadline = rib.next_deadline().unwrap();
    assert!(deadline > Instant::now() + STALE_PATH_TIME - Duration::from_secs(5));
    rib.expire(deadline);
    assert_eq!(rib.route_count(&p("198.51.100.0/24")), 0);
}

#[test]
fn stale_routes_go_without_forwarding_state_or_retain() {
    // Back without the F bit: removed at once.
    let (mut rib, _rx) = rib_with_gr_peer();
    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: retain(120, &[Afi::IPV4, Afi::IPV6]),
        }],
    );
    let (msg, _rx2) = up_gr(1, false);
    run(&mut rib, vec![msg]);
    assert_eq!(rib.route_count(&p("198.51.100.0/24")), 0);
    assert_eq!(rib.route_count(&p("2001:db8:99::/48")), 0);
    assert_eq!(rib.next_deadline(), None);

    // Back without Graceful Restart at all: same.
    let (mut rib, _rx) = rib_with_gr_peer();
    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: retain(120, &[Afi::IPV4, Afi::IPV6]),
        }],
    );
    let (msg, _rx2) = up(1, 64501);
    run(&mut rib, vec![msg]);
    assert_eq!(rib.route_count(&p("198.51.100.0/24")), 0);

    // Only the retained family is kept.
    let (mut rib, _rx) = rib_with_gr_peer();
    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: retain(120, &[Afi::IPV6]),
        }],
    );
    assert_eq!(rib.route_count(&p("198.51.100.0/24")), 0);
    assert_eq!(rib.route_count(&p("2001:db8:99::/48")), 1);

    // A later Down without retain removes the stale routes too.
    let (msg, _rx2) = up_gr(1, true);
    run(
        &mut rib,
        vec![
            msg,
            RibMsg::Down {
                peer: 1,
                retain: None,
            },
        ],
    );
    assert_eq!(rib.route_count(&p("2001:db8:99::/48")), 0);
    assert_eq!(rib.next_deadline(), None);
    assert_eq!(stale_count(&rib, 1), None);
}

fn drain(rib: &mut Rib, drained: bool) -> (DrainChange, Vec<(SourceId, PeerMsg)>) {
    let (reply, mut rx) = oneshot::channel();
    let msg = RibMsg::Drain { drained, reply };
    let out = run(
        rib,
        vec![msg, RibMsg::Ready { peer: 1 }, RibMsg::Ready { peer: 2 }],
    );
    (rx.try_recv().unwrap(), out)
}

/// Peer 1 eBGP with `drain_prepend = 2`, peer 2 iBGP; both have the table.
fn rib_for_drain() -> (Rib, [mpsc::Receiver<PeerMsg>; 2]) {
    let mut rib = rib(None);
    rib.config.peers.get_mut(&1).unwrap().drain_prepend = 2;
    rib.config.peers.get_mut(&2).unwrap().drain_prepend = 2;
    let (up1, rx1) = up(1, 64501);
    let (up2, rx2) = up(2, LOCAL_ASN);
    run(&mut rib, vec![up1, up2]);
    (rib, [rx1, rx2])
}

fn only_group(mut batches: Vec<ExportBatch>) -> Announce {
    assert_eq!(batches.len(), 1, "{batches:#?}");
    let batch = batches.remove(0);
    assert!(batch.withdraw.is_empty());
    let mut groups = batch.announce;
    assert_eq!(groups.len(), 1, "{groups:#?}");
    let mut group = groups.remove(0);
    group.prefixes.sort();
    group
}

#[test]
fn drain_marks_own_routes_and_undrain_restores_them() {
    let (mut rib, _rx) = rib_for_drain();
    let sets_before = rib.stats().attr_sets;
    let next_hop = PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1));

    let (change, out) = drain(&mut rib, true);
    assert!(change.changed);
    assert!(change.since.is_some());
    let mut ebgp = only_group(exports(out, 1));
    assert_eq!(ebgp.prefixes, [p("192.0.2.0/24"), p("2001:db8:1::/48")]);
    assert_eq!(
        ebgp.attrs,
        [
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([LOCAL_ASN; 3])),
            next_hop.clone(),
            PathAttr::Communities(vec![GRACEFUL_SHUTDOWN]),
        ],
        "eBGP: GRACEFUL_SHUTDOWN, 2 extra prepends, no LOCAL_PREF"
    );
    let (change, out) = drain(&mut rib, true);
    assert_eq!(change.since, rib.summary().drained);
    assert!(!change.changed);
    assert!(out.is_empty(), "already drained: nothing to send");

    let (change, out) = drain(&mut rib, false);
    assert_eq!(
        change,
        DrainChange {
            changed: true,
            since: None
        }
    );
    assert!(rib.summary().drained.is_none());
    ebgp = only_group(exports(out, 1));
    assert_eq!(
        ebgp.attrs,
        [
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([LOCAL_ASN])),
            next_hop,
        ]
    );
    assert_eq!(rib.stats().attr_sets, sets_before, "drained set released");
}

#[test]
fn drained_ibgp_peer_gets_local_pref_zero_and_no_prepend() {
    let (mut rib, _rx) = rib_for_drain();
    let (_, out) = drain(&mut rib, true);
    let ibgp = only_group(exports(out, 2));
    assert_eq!(
        ibgp.attrs,
        [
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::default()),
            PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
            PathAttr::LocalPref(0),
            PathAttr::Communities(vec![GRACEFUL_SHUTDOWN]),
        ]
    );
    let (_, out) = drain(&mut rib, false);
    let ibgp = only_group(exports(out, 2));
    assert!(ibgp.attrs.contains(&PathAttr::LocalPref(100)));
    assert!(
        !ibgp
            .attrs
            .iter()
            .any(|a| matches!(a, PathAttr::Communities(_)))
    );
}

#[test]
fn while_drained_new_prefixes_and_new_sessions_go_out_drained() {
    let mut rib = rib(None);
    rib.config.peers.get_mut(&1).unwrap().drain_prepend = 1;
    let (_, out) = drain(&mut rib, true);
    assert!(out.is_empty(), "no peers yet");

    // A session coming up gets the drained routes in its initial table.
    let (msg, _rx) = up(1, 64501);
    let batch = exports(run(&mut rib, vec![msg]), 1).remove(0);
    assert_eq!(batch.end_of_rib, [Afi::IPV4, Afi::IPV6]);
    assert_eq!(
        batch.announce[0].attrs[1],
        PathAttr::AsPath(AsPath::sequence([LOCAL_ASN; 2]))
    );
    assert!(
        batch.announce[0]
            .attrs
            .contains(&PathAttr::Communities(vec![GRACEFUL_SHUTDOWN]))
    );

    // A prefix announced at runtime while drained is drained too.
    let (_, out) = own(&mut rib, true, &["198.51.100.0/24"]);
    let group = only_group(exports(out, 1));
    assert_eq!(group.prefixes, [p("198.51.100.0/24")]);
    assert!(
        group
            .attrs
            .contains(&PathAttr::Communities(vec![GRACEFUL_SHUTDOWN]))
    );
}

/// A RIB with a FIB task attached: peer 1 installs, peer 2 does not.
fn rib_with_fib() -> (Rib, std_mpsc::Receiver<FibMsg>) {
    let mut rib = rib(None);
    for (peer, install) in [(1, true), (2, false)] {
        let settings = PeerSettings {
            import: Import::All,
            install,
            ..PeerSettings::default()
        };
        rib.config.peers.insert(peer, settings);
    }
    let (tx, rx) = std_mpsc::channel();
    rib.attach_fib(tx);
    (rib, rx)
}

/// Flushes the FIB batch, if any, and reports the FIB ready again; next
/// hops by address.
fn fib_batch(rib: &mut Rib, rx: &std_mpsc::Receiver<FibMsg>) -> Vec<(Prefix, Option<IpAddr>)> {
    fib_gateways(rib, rx)
        .into_iter()
        .map(|(p, g)| (p, g.map(|g| g.addr)))
        .collect()
}

fn fib_gateways(rib: &mut Rib, rx: &std_mpsc::Receiver<FibMsg>) -> Vec<(Prefix, Option<Gateway>)> {
    rib.flush_fib();
    let mut routes = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        match msg {
            FibMsg::Routes(batch) => routes.extend(batch),
            FibMsg::Synced => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    rib.handle(RibMsg::FibReady, &mut Vec::new());
    routes.sort();
    routes
}

fn hop(s: &str) -> Option<IpAddr> {
    Some(s.parse().unwrap())
}

#[test]
fn fib_gets_best_routes_of_installing_peers() {
    let (mut rib, rx) = rib_with_fib();
    assert!(
        fib_batch(&mut rib, &rx).is_empty(),
        "own prefixes never go in"
    );
    let (up1, _rx1) = up(1, 64501);
    let (up2, _rx2) = up(2, 64502);
    let update = |peer, path: &[u32], prefixes: &[&str]| RibMsg::Update {
        peer,
        update: learned(path, prefixes),
    };
    run(
        &mut rib,
        vec![
            up1,
            up2,
            update(1, &[64501], &["198.51.100.0/24"]),
            update(2, &[64502], &["203.0.113.0/24"]),
        ],
    );
    let v6 = learned_v6(
        NextHop::V6 {
            global: "2001:db8:ff::2".parse().unwrap(),
            link_local: Some("fe80::2".parse().unwrap()),
        },
        "2001:db8:2::/48",
    );
    run(
        &mut rib,
        vec![RibMsg::Update {
            peer: 1,
            update: v6,
        }],
    );
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [
            (p("198.51.100.0/24"), hop("127.0.0.2")),
            // Peer 2 does not install: its best route keeps the prefix out.
            (p("203.0.113.0/24"), None),
            (p("2001:db8:2::/48"), hop("2001:db8:ff::2")),
        ]
    );

    // Peer 1 goes down: the prefix leaves the kernel.
    run(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: None,
        }],
    );
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [(p("198.51.100.0/24"), None), (p("2001:db8:2::/48"), None)]
    );
}

#[test]
fn fib_batches_wait_for_ready() {
    let (mut rib, rx) = rib_with_fib();
    let (up1, _rx1) = up(1, 64501);
    let first = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["198.51.100.0/24"]),
    };
    run(&mut rib, vec![up1, first]);
    rib.flush_fib();
    assert!(matches!(rx.try_recv(), Ok(FibMsg::Routes(_))));
    let second = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["198.51.100.0/25"]),
    };
    run(&mut rib, vec![second]);
    rib.flush_fib();
    assert!(rx.try_recv().is_err(), "nothing before FibReady");
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [],
        "the ready report itself sends nothing"
    );
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [(p("198.51.100.0/25"), hop("127.0.0.2"))]
    );
}

#[test]
fn own_prefixes_stay_out_of_the_kernel_after_a_runtime_withdraw() {
    let (mut rib, rx) = rib_with_fib();
    let (up1, _rx1) = up(1, 64501);
    let learned = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["192.0.2.0/24", "198.51.100.0/24"]),
    };
    run(&mut rib, vec![up1, learned]);
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [(p("198.51.100.0/24"), hop("127.0.0.2"))]
    );
    own(&mut rib, false, &["192.0.2.0/24"]);
    assert_eq!(rib.best_route(&p("192.0.2.0/24")).unwrap().0, 1);
    assert_eq!(fib_batch(&mut rib, &rx), [(p("192.0.2.0/24"), None)]);
}

#[test]
fn install_and_family_changes_reevaluate_prefixes() {
    let (mut rib, rx) = rib_with_fib();
    let (up2, _rx2) = up(2, 64502);
    let learned = RibMsg::Update {
        peer: 2,
        update: learned(&[64502], &["198.51.100.0/24"]),
    };
    run(&mut rib, vec![up2, learned]);
    assert_eq!(fib_batch(&mut rib, &rx), [(p("198.51.100.0/24"), None)]);

    let settings = PeerSettings {
        import: Import::All,
        install: true,
        ..PeerSettings::default()
    };
    run(
        &mut rib,
        vec![RibMsg::PeerSettings {
            peer: 2,
            settings: Some(settings),
        }],
    );
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [(p("198.51.100.0/24"), hop("127.0.0.2"))]
    );

    run(&mut rib, vec![RibMsg::InstallFamilies([false, true])]);
    assert_eq!(fib_batch(&mut rib, &rx), [(p("198.51.100.0/24"), None)]);
    run(&mut rib, vec![RibMsg::InstallFamilies([false, false])]);
    assert_eq!(fib_batch(&mut rib, &rx), [], "IPv4 did not change");
}

#[test]
fn unreachable_next_hops_lose_and_leave_the_kernel() {
    let (mut rib, rx) = rib_with_fib();
    let (up1, _rx1) = up(1, 64501);
    let (up3, _rx3) = up(3, 64503);
    rib.config.peers.insert(
        3,
        PeerSettings {
            import: Import::All,
            install: true,
            ..PeerSettings::default()
        },
    );
    let mut via3 = learned(&[64503, 1], &["198.51.100.0/24"]);
    via3.attrs[2] = PathAttr::NextHop(Ipv4Addr::new(127, 0, 0, 3));
    run(
        &mut rib,
        vec![
            up1,
            up3,
            RibMsg::Update {
                peer: 1,
                update: learned(&[64501], &["198.51.100.0/24", "203.0.113.0/24"]),
            },
            RibMsg::Update {
                peer: 3,
                update: via3,
            },
        ],
    );
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [
            (p("198.51.100.0/24"), hop("127.0.0.2")),
            (p("203.0.113.0/24"), hop("127.0.0.2")),
        ]
    );

    // 127.0.0.2 (peer 1) is unreachable: the longer path through peer 3
    // wins; the other prefix has no alternative and leaves the kernel.
    let unreachable = RibMsg::NextHops(vec![(a4("127.0.0.2").into(), false)]);
    run(&mut rib, vec![unreachable]);
    assert_eq!(rib.best_route(&p("198.51.100.0/24")).unwrap().0, 3);
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [
            (p("198.51.100.0/24"), hop("127.0.0.3")),
            (p("203.0.113.0/24"), None),
        ]
    );

    // A report that changes nothing does nothing.
    run(
        &mut rib,
        vec![RibMsg::NextHops(vec![(a4("127.0.0.9").into(), true)])],
    );
    assert_eq!(fib_batch(&mut rib, &rx), []);

    // Back: the shorter path wins again.
    run(
        &mut rib,
        vec![RibMsg::NextHops(vec![(a4("127.0.0.2").into(), true)])],
    );
    assert_eq!(rib.best_route(&p("198.51.100.0/24")).unwrap().0, 1);
    assert_eq!(
        fib_batch(&mut rib, &rx),
        [
            (p("198.51.100.0/24"), hop("127.0.0.2")),
            (p("203.0.113.0/24"), hop("127.0.0.2")),
        ]
    );
}

fn a4(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn fib_is_told_when_installing_neighbors_are_in_sync() {
    let (mut rib, rx) = rib_with_fib();
    let synced = |rib: &mut Rib| {
        rib.flush_fib();
        let got: Vec<FibMsg> = rx.try_iter().collect();
        rib.handle(RibMsg::FibReady, &mut Vec::new());
        got.iter().any(|m| matches!(m, FibMsg::Synced))
    };
    // Peer 2 does not install: only peer 1 is waited for.
    let (up1, _rx1) = up(1, 64501);
    let routes = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["198.51.100.0/24"]),
    };
    run(&mut rib, vec![up1, routes]);
    assert!(!synced(&mut rib));
    let eor4 = RibMsg::Update {
        peer: 1,
        update: eor(Afi::IPV4),
    };
    run(&mut rib, vec![eor4]);
    assert!(!synced(&mut rib), "IPv6 End-of-RIB still owed");
    let eor6 = RibMsg::Update {
        peer: 1,
        update: eor(Afi::IPV6),
    };
    run(&mut rib, vec![eor6]);
    assert!(synced(&mut rib));
    assert!(!synced(&mut rib), "only once");
}

#[test]
fn fib_sync_waits_for_the_last_batch() {
    let (mut rib, rx) = rib_with_fib();
    let (up1, _rx1) = up(1, 64501);
    let routes = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["198.51.100.0/24"]),
    };
    run(&mut rib, vec![up1, routes]);
    rib.flush_fib(); // the batch is out, not applied yet
    for afi in [Afi::IPV4, Afi::IPV6] {
        let eor = RibMsg::Update {
            peer: 1,
            update: eor(afi),
        };
        run(&mut rib, vec![eor]);
    }
    rib.flush_fib();
    let msgs: Vec<FibMsg> = rx.try_iter().collect();
    assert!(matches!(msgs[..], [FibMsg::Routes(_)]), "{msgs:?}");
    rib.handle(RibMsg::FibReady, &mut Vec::new());
    rib.flush_fib();
    assert!(matches!(rx.try_recv(), Ok(FibMsg::Synced)));
}

#[test]
fn longest_match_and_unreachable_flag() {
    let (mut rib, _rx) = rib_with_fib();
    let (up1, _rx1) = up(1, 64501);
    let routes = RibMsg::Update {
        peer: 1,
        update: learned(&[64501], &["198.51.100.0/24", "198.51.100.128/25"]),
    };
    run(&mut rib, vec![up1, routes]);
    assert_eq!(
        rib.longest_match(a4("198.51.100.200")),
        Some(p("198.51.100.128/25"))
    );
    assert_eq!(
        rib.longest_match(a4("198.51.100.7")),
        Some(p("198.51.100.0/24"))
    );
    assert_eq!(rib.longest_match(a4("203.0.113.1")), None);
    assert_eq!(
        rib.longest_match(a4("2001:db8:1::1")),
        Some(p("2001:db8:1::/48"))
    );

    run(
        &mut rib,
        vec![RibMsg::NextHops(vec![(a4("127.0.0.2").into(), false)])],
    );
    let found = ask(&mut rib, |reply| Query::Longest {
        addr: a4("198.51.100.200"),
        reply,
    });
    assert_eq!(found.len(), 1);
    assert!(found[0].unreachable);
}

/// `up` for a neighbor on a shared link over interface `oif`.
fn up_on_link(peer: SourceId, asn: u32, oif: u32) -> (RibMsg, mpsc::Receiver<PeerMsg>) {
    let (msg, rx) = up(peer, asn);
    let RibMsg::Up(mut up) = msg else {
        unreachable!()
    };
    up.oif = Some(oif);
    (RibMsg::Up(up), rx)
}

#[test]
fn link_local_next_hops_carry_the_sessions_interface() {
    let (mut rib, rx) = rib_with_fib();
    rib.config.peers.insert(
        3,
        PeerSettings {
            import: Import::All,
            install: true,
            ..PeerSettings::default()
        },
    );
    let (up1, _rx1) = up_on_link(1, 64501, 5);
    let (up3, _rx3) = up_on_link(3, 64503, 6);
    let ll = "fe80::1".parse::<Ipv6Addr>().unwrap();
    // Both neighbors send only the link-local fe80::1 (each on its link).
    let only_ll = NextHop::V6 {
        global: ll,
        link_local: None,
    };
    let mut via3 = learned_v6(only_ll, "2001:db8:100::/48");
    for attr in &mut via3.attrs {
        if let PathAttr::AsPath(path) = attr {
            *path = AsPath::sequence(vec![64503, 1]);
        }
    }
    let mut via1 = learned_v6(only_ll, "2001:db8:100::/48");
    via1.mp_reach
        .as_mut()
        .unwrap()
        .nlri
        .push("2001:db8:200::/48".parse().unwrap());
    run(
        &mut rib,
        vec![
            up1,
            up3,
            RibMsg::Update {
                peer: 1,
                update: via1,
            },
            RibMsg::Update {
                peer: 3,
                update: via3,
            },
        ],
    );
    let on5 = Gateway::new(IpAddr::V6(ll), None, Some(5));
    let on6 = Gateway::new(IpAddr::V6(ll), None, Some(6));
    assert_eq!(on5.link, Some((ll, 5)));
    assert_eq!(
        fib_gateways(&mut rib, &rx),
        [
            (p("2001:db8:100::/48"), Some(on5)),
            (p("2001:db8:200::/48"), Some(on5)),
        ]
    );

    // fe80::1 on interface 5 is gone; the one on 6 is another next hop.
    run(&mut rib, vec![RibMsg::NextHops(vec![(on5, false)])]);
    assert_eq!(rib.best_route(&p("2001:db8:100::/48")).unwrap().0, 3);
    assert_eq!(
        fib_gateways(&mut rib, &rx),
        [
            (p("2001:db8:100::/48"), Some(on6)),
            (p("2001:db8:200::/48"), None),
        ]
    );
}

#[test]
fn global_next_hops_bring_the_link_local_one_along() {
    let (mut rib, rx) = rib_with_fib();
    let (up1, _rx1) = up_on_link(1, 64501, 5);
    let next_hop = NextHop::V6 {
        global: "2001:db8:ff::9".parse().unwrap(),
        link_local: Some("fe80::9".parse().unwrap()),
    };
    run(
        &mut rib,
        vec![
            up1,
            RibMsg::Update {
                peer: 1,
                update: learned_v6(next_hop, "2001:db8:100::/48"),
            },
        ],
    );
    let gw = Gateway {
        addr: "2001:db8:ff::9".parse().unwrap(),
        link: Some(("fe80::9".parse().unwrap(), 5)),
    };
    assert_eq!(
        fib_gateways(&mut rib, &rx),
        [(p("2001:db8:100::/48"), Some(gw))]
    );
}

#[test]
fn settings_from_config() {
    let text = r#"
        asn = 64500
        router_id = "203.0.113.1"
        drain_time = 60

        [[neighbor]]
        address = "192.0.2.2"
        asn = 64501
        max_prefixes_ipv4 = 1100000
        drain_prepend = 3

        [[neighbor]]
        address = "192.0.2.3"
        asn = 64502
        install = false
    "#;
    let config: Config = toml::from_str(text).unwrap();
    let rib = RibConfig::new(&config);
    assert_eq!(rib.peers[&1].max_prefixes_ipv4, Some(1_100_000));
    assert_eq!(rib.peers[&1].drain_prepend, 3);
    assert_eq!(rib.peers[&2].max_prefixes_ipv4, None);
    assert_eq!(rib.max_prefix_restart, Duration::from_secs(300));
    assert_eq!(rib.install_families, [false, false]);
    assert!(!rib.peers[&1].install, "no [kernel], nothing is installed");

    let config: Config =
        toml::from_str(&format!("{text}\n[kernel]\nfamilies = [\"ipv6\"]\n")).unwrap();
    let rib = RibConfig::new(&config);
    assert_eq!(rib.install_families, [false, true]);
    assert!(rib.peers[&1].install);
    assert!(!rib.peers[&2].install);
}

/// A session over IPv6 without `next_hop_ipv4`: only an IPv6 next hop
/// (2001:db8::1, see `up`), and RFC 8950 agreed or not.
fn up_ipv6_only(peer: SourceId, extended_next_hop: bool) -> (RibMsg, mpsc::Receiver<PeerMsg>) {
    let (msg, rx) = up(peer, 64500 + u32::from(peer));
    let RibMsg::Up(mut up) = msg else {
        unreachable!()
    };
    up.addr = format!("2001:db8::{peer:x}0").parse().unwrap();
    up.local_addr = IpAddr::V6("2001:db8::1".parse().unwrap());
    up.next_hop_ipv4 = None;
    up.info.negotiated.extended_next_hop = extended_next_hop;
    (RibMsg::Up(up), rx)
}

fn learned_v4_via(next_hop: NextHop, prefix: &str) -> Update {
    let mut update = learned_v6(next_hop, prefix);
    update.mp_reach.as_mut().unwrap().afi = Afi::IPV4;
    update
}

#[test]
fn ipv4_goes_out_with_the_ipv6_next_hop_when_agreed() {
    let mut rib = rib(None);
    let (msg, _rx) = up_ipv6_only(1, true);
    let batch = exports(run(&mut rib, vec![msg]), 1).remove(0);
    let [group] = &batch.announce[..] else {
        panic!("one attribute set: {:#?}", batch.announce);
    };
    let mut prefixes = group.prefixes.clone();
    prefixes.sort();
    assert_eq!(prefixes, [p("192.0.2.0/24"), p("2001:db8:1::/48")]);
    assert!(
        !group
            .attrs
            .iter()
            .any(|a| a.type_code() == type_code::NEXT_HOP)
    );

    // On the wire: IPv4 in MP_REACH with the IPv6 next hop.
    let neg = Negotiated {
        four_octet_as: true,
        extended_next_hop: true,
        ..Negotiated::default()
    };
    let mut buf = BytesMut::from(&encode_batch(&batch, &neg).unwrap()[..]);
    let mut reach = Vec::new();
    while let Some((kind, body)) = split_message(&mut buf, 4096).unwrap() {
        let Message::Update(update) = Message::decode(kind, body, &neg).unwrap() else {
            panic!("not an UPDATE");
        };
        assert!(update.nlri.is_empty());
        reach.extend(update.mp_reach.map(|m| (m.afi, m.next_hop)));
    }
    let v6 = NextHop::V6 {
        global: "2001:db8::1".parse().unwrap(),
        link_local: None,
    };
    assert_eq!(reach, [(Afi::IPV4, v6), (Afi::IPV6, v6)]);
}

#[test]
fn ipv4_is_not_announced_without_a_next_hop_for_it() {
    let mut rib = rib(None);
    let (msg, _rx) = up_ipv6_only(1, false);
    let batch = exports(run(&mut rib, vec![msg]), 1).remove(0);
    let prefixes: Vec<Prefix> = batch
        .announce
        .iter()
        .flat_map(|a| a.prefixes.clone())
        .collect();
    assert_eq!(prefixes, [p("2001:db8:1::/48")]);
}

#[test]
fn ipv4_routes_via_ipv6_next_hops_are_learned_and_installed() {
    let (mut rib, rx) = rib_with_fib();
    let (up1, _rx1) = up_on_link(1, 64501, 5);
    let foreign = NextHop::V6 {
        global: "2001:db8:ff::9".parse().unwrap(),
        link_local: Some("fe80::9".parse().unwrap()),
    };
    // Our own IPv6 next hop on this session: not usable.
    let ours = NextHop::V6 {
        global: "2001:db8::1".parse().unwrap(),
        link_local: None,
    };
    run(
        &mut rib,
        vec![
            up1,
            RibMsg::Update {
                peer: 1,
                update: learned_v4_via(foreign, "198.51.100.0/24"),
            },
            RibMsg::Update {
                peer: 1,
                update: learned_v4_via(ours, "203.0.113.0/24"),
            },
        ],
    );
    assert_eq!(rib.route_count(&p("203.0.113.0/24")), 0, "own next hop");
    let gw = Gateway {
        addr: "2001:db8:ff::9".parse().unwrap(),
        link: Some(("fe80::9".parse().unwrap(), 5)),
    };
    assert_eq!(
        fib_gateways(&mut rib, &rx),
        [(p("198.51.100.0/24"), Some(gw))]
    );
}

// --- Roles, filters and the default route: a provider (1), a customer (2)
// and a peer (3).

const TRANSIT: &str = r#"
    asn = 64500
    router_id = "203.0.113.1"
    announce = ["192.0.2.0/24"]

    [[neighbor]]
    address = "127.0.0.1"
    asn = 64501
    role = "provider"
    import = "all"

    [[neighbor]]
    address = "127.0.0.2"
    asn = 64510
    role = "customer"
    import = "from-customer"
    export = "to-customer"
    default_route = true

    [[neighbor]]
    address = "127.0.0.3"
    asn = 64502
    role = "peer"
    import = "all"
    export = "to-peer"

    [filter.from-customer]
    [[filter.from-customer.rule]]
    prefixes = ["203.0.113.0/24"]
    origin_as = [64510]
    action = "accept"
    local_pref = 200
    add_communities = ["64500:200"]

    [filter.to-customer]
    [[filter.to-customer.rule]]
    action = "accept"

    [filter.to-peer]
    [[filter.to-peer.rule]]
    source = "own"
    action = "accept"
    [[filter.to-peer.rule]]
    from_role = ["customer"]
    action = "accept"
    prepend = 1
"#;

fn transit_rib() -> (Rib, Vec<mpsc::Receiver<PeerMsg>>) {
    let config: Config = toml::from_str(TRANSIT).unwrap();
    let mut rib = Rib::new(RibConfig::new(&config));
    let mut rxs = Vec::new();
    for (peer, asn) in [(1, 64501), (2, 64510), (3, 64502)] {
        let (msg, rx) = up(peer, asn);
        rxs.push(rx);
        run(&mut rib, vec![msg]);
    }
    (rib, rxs)
}

/// Handles `msgs` with every peer ready, and returns what each got.
fn step(rib: &mut Rib, msgs: Vec<RibMsg>) -> HashMap<SourceId, Vec<ExportBatch>> {
    let mut all: Vec<RibMsg> = [1, 2, 3].map(|peer| RibMsg::Ready { peer }).into();
    all.extend(msgs);
    let mut got: HashMap<SourceId, Vec<ExportBatch>> = [1, 2, 3]
        .into_iter()
        .map(|peer| (peer, Vec::new()))
        .collect();
    for (peer, msg) in run(rib, all) {
        if let PeerMsg::Export(batch) = msg {
            got.entry(peer).or_default().push(batch);
        }
    }
    got
}

/// The attributes `prefix` went out with, if it was announced.
fn sent(batches: &[ExportBatch], prefix: &str) -> Option<Vec<PathAttr>> {
    batches.iter().flat_map(|b| &b.announce).find_map(|group| {
        group
            .prefixes
            .contains(&p(prefix))
            .then(|| group.attrs.clone())
    })
}

fn withdrawn(batches: &[ExportBatch], prefix: &str) -> bool {
    batches.iter().any(|b| b.withdraw.contains(&p(prefix)))
}

fn path_of(attrs: &[PathAttr]) -> Vec<u32> {
    attrs
        .iter()
        .find_map(|a| match a {
            PathAttr::AsPath(path) => {
                Some(path.segments.iter().flat_map(|s| s.asns.clone()).collect())
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn otc_of(attrs: &[PathAttr]) -> Option<u32> {
    attrs.iter().find_map(|a| match a {
        PathAttr::OnlyToCustomer(asn) => Some(*asn),
        _ => None,
    })
}

#[test]
fn customer_routes_are_filtered_and_go_to_peers() {
    let (mut rib, _rxs) = transit_rib();
    let update = learned(
        &[64510],
        &["203.0.113.0/24", "203.0.113.0/25", "198.51.100.0/24"],
    );
    let got = step(&mut rib, vec![RibMsg::Update { peer: 2, update }]);
    assert_eq!(rib.route_count(&p("203.0.113.0/24")), 1);
    assert_eq!(
        rib.route_count(&p("203.0.113.0/25")),
        0,
        "longer than the range"
    );
    assert_eq!(
        rib.route_count(&p("198.51.100.0/24")),
        0,
        "not the customer's"
    );

    // The peer gets it with the extra prepend and OTC (RFC 9234 egress).
    let attrs = sent(&got[&3], "203.0.113.0/24").expect("sent to the peer");
    assert_eq!(path_of(&attrs), [64500, 64500, 64510]);
    assert_eq!(otc_of(&attrs), Some(64500));
    assert!(attrs.contains(&PathAttr::Communities(vec![64500 << 16 | 200])));
    assert!(
        !attrs.iter().any(|a| matches!(a, PathAttr::LocalPref(_))),
        "eBGP"
    );
    // The provider's export is "own": nothing learned.
    assert!(sent(&got[&1], "203.0.113.0/24").is_none());

    // The customer sends the prefix again, now with another origin: the
    // filter rejects it, which withdraws the route everywhere.
    let update = learned(&[64510, 64999], &["203.0.113.0/24"]);
    let got = step(&mut rib, vec![RibMsg::Update { peer: 2, update }]);
    assert_eq!(rib.route_count(&p("203.0.113.0/24")), 0);
    assert!(withdrawn(&got[&3], "203.0.113.0/24"));
}

#[test]
fn provider_routes_get_otc_and_only_go_to_customers() {
    let (mut rib, _rxs) = transit_rib();
    let update = learned(&[64501, 3356], &["8.8.8.0/24"]);
    let got = step(&mut rib, vec![RibMsg::Update { peer: 1, update }]);
    let attrs = sent(&got[&2], "8.8.8.0/24").expect("sent to the customer");
    assert_eq!(path_of(&attrs), [64500, 64501, 3356]);
    assert_eq!(otc_of(&attrs), Some(64501), "added on ingress, kept");
    assert!(sent(&got[&3], "8.8.8.0/24").is_none(), "never to a peer");
}

#[test]
fn otc_from_a_customer_is_a_leak() {
    let (mut rib, _rxs) = transit_rib();
    let mut update = learned(&[64510], &["203.0.113.0/24"]);
    update.attrs.push(PathAttr::OnlyToCustomer(64777));
    step(&mut rib, vec![RibMsg::Update { peer: 2, update }]);
    assert_eq!(rib.route_count(&p("203.0.113.0/24")), 0);
}

#[test]
fn default_route_follows_the_provider_sessions() {
    let (mut rib, _rxs) = transit_rib();
    // Sent when the customer came up (the provider was up already); check
    // through a fresh session of the customer.
    step(
        &mut rib,
        vec![RibMsg::Down {
            peer: 2,
            retain: None,
        }],
    );
    let (msg, _rx) = up(2, 64510);
    let got = step(&mut rib, vec![msg]);
    let attrs = sent(&got[&2], "0.0.0.0/0").expect("default route");
    assert_eq!(path_of(&attrs), [64500]);
    assert_eq!(otc_of(&attrs), Some(64500));
    assert!(sent(&got[&2], "::/0").is_some());
    assert!(
        sent(&got[&3], "0.0.0.0/0").is_none(),
        "only with default_route"
    );

    let got = step(
        &mut rib,
        vec![RibMsg::Down {
            peer: 1,
            retain: None,
        }],
    );
    assert!(withdrawn(&got[&2], "0.0.0.0/0"));
    assert!(withdrawn(&got[&2], "::/0"));
    let (msg, _rx) = up(1, 64501);
    let got = step(&mut rib, vec![msg]);
    assert!(sent(&got[&2], "0.0.0.0/0").is_some());
}

#[test]
fn policy_changes_apply_to_the_running_session() {
    let (mut rib, _rxs) = transit_rib();
    let update = learned(&[64501, 3356], &["8.8.8.0/24"]);
    step(&mut rib, vec![RibMsg::Update { peer: 1, update }]);
    let config: Config = toml::from_str(TRANSIT).unwrap();
    let customer = &config.neighbors[1];

    // Export "none" for the customer: everything it had is withdrawn.
    let mut settings = PeerSettings::new(&config, customer);
    settings.export = Export::None;
    settings.default_route = false;
    let got = step(
        &mut rib,
        vec![RibMsg::PeerSettings {
            peer: 2,
            settings: Some(settings),
        }],
    );
    assert!(withdrawn(&got[&2], "8.8.8.0/24"));
    assert!(withdrawn(&got[&2], "0.0.0.0/0"));
    assert!(withdrawn(&got[&2], "192.0.2.0/24"));

    // Back to the filter: sent again.
    let settings = PeerSettings::new(&config, customer);
    let got = step(
        &mut rib,
        vec![RibMsg::PeerSettings {
            peer: 2,
            settings: Some(settings),
        }],
    );
    assert!(sent(&got[&2], "8.8.8.0/24").is_some());

    // A new import policy asks the provider for its routes again.
    let mut settings = PeerSettings::new(&config, &config.neighbors[0]);
    settings.import = Import::new(
        &config,
        &crate::config::ImportPolicy::Filter("from-customer".into()),
    );
    let mut out = Vec::new();
    rib.handle(
        RibMsg::PeerSettings {
            peer: 1,
            settings: Some(settings),
        },
        &mut out,
    );
    assert!(
        out.iter()
            .any(|(peer, msg)| *peer == 1
                && *msg == PeerMsg::RouteRefresh(vec![Afi::IPV4, Afi::IPV6]))
    );

    // Import "none": its routes go at once.
    let mut settings = PeerSettings::new(&config, &config.neighbors[0]);
    settings.import = Import::None;
    let got = step(
        &mut rib,
        vec![RibMsg::PeerSettings {
            peer: 1,
            settings: Some(settings),
        }],
    );
    assert_eq!(rib.route_count(&p("8.8.8.0/24")), 0);
    assert!(withdrawn(&got[&2], "8.8.8.0/24"));
}

fn test_route(from: &str, prefix: &str, path: &[u32]) -> TestQuery {
    TestQuery::Route(TestRoute {
        from: Some(from.parse().unwrap()),
        prefix: Some(p(prefix)),
        as_path: Some(path.to_vec()),
        ..TestRoute::default()
    })
}

#[test]
fn trace_explains_a_route_without_changing_anything() {
    let (mut rib, _rxs) = transit_rib();
    let attr_sets = rib.stats().attr_sets;
    let trace = rib
        .trace(test_route("127.0.0.2", "203.0.113.0/24", &[64510]))
        .unwrap();
    let import = trace.import.as_ref().unwrap();
    assert!(import.accepted);
    assert_eq!(import.rule, Some(0));
    assert_eq!(trace.tested_is_best, Some(true));
    let to = |peer: SourceId| trace.exports.iter().find(|e| e.peer == peer).unwrap();
    assert!(!to(1).sent, "provider: export own");
    assert_eq!(to(1).reason, "export own: a learned route");
    assert_eq!(to(2).reason, "came from this neighbor");
    assert!(to(3).sent);
    assert_eq!(to(3).rule, Some(1));
    assert_eq!(path_of(&to(3).attrs), [64500, 64500, 64510]);
    // Nothing stored, nothing sent, the pool as before.
    assert_eq!(rib.route_count(&p("203.0.113.0/24")), 0);
    assert_eq!(rib.stats().attr_sets, attr_sets);
    let out = run(
        &mut rib,
        [1, 2, 3].map(|peer| RibMsg::Ready { peer }).into(),
    );
    assert!(out.is_empty());

    // Rejections say why.
    let trace = rib
        .trace(test_route("127.0.0.2", "203.0.113.0/25", &[64510]))
        .unwrap();
    assert_eq!(
        trace.import.unwrap().reason,
        "no rule of the import filter matches"
    );
    let trace = rib
        .trace(test_route("127.0.0.1", "8.8.8.0/24", &[64501, 64500]))
        .unwrap();
    assert_eq!(trace.import.unwrap().reason, "AS loop");
    assert!(
        rib.trace(test_route("127.0.0.9", "8.8.8.0/24", &[1]))
            .is_err()
    );
}

#[test]
fn trace_of_an_existing_route() {
    let (mut rib, _rxs) = transit_rib();
    let update = learned(&[64501, 3356], &["8.8.8.0/24"]);
    step(&mut rib, vec![RibMsg::Update { peer: 1, update }]);
    let trace = rib
        .trace(TestQuery::Address("8.8.8.8".parse().unwrap()))
        .unwrap();
    assert_eq!(trace.prefix, p("8.8.8.0/24"));
    assert_eq!(trace.candidates.len(), 1);
    let to = |peer: SourceId| trace.exports.iter().find(|e| e.peer == peer).unwrap();
    assert!(to(2).sent);
    assert_eq!(to(3).reason, "carries OTC: only for customers (RFC 9234)");
    // The same prefix from the peer: a longer path, the provider's stays.
    let trace = rib
        .trace(test_route("127.0.0.3", "8.8.8.0/24", &[64502, 1, 3356]))
        .unwrap();
    assert_eq!(trace.tested_is_best, Some(false));
    assert_eq!(trace.candidates[0].source, 1);
    assert_eq!(trace.kernel.reason, "not the best route");
}

#[test]
fn adj_rib_out_shows_what_was_sent() {
    let (mut rib, _rxs) = transit_rib();
    let update = learned(&[64510], &["203.0.113.0/24"]);
    step(&mut rib, vec![RibMsg::Update { peer: 2, update }]);
    let page = ask(&mut rib, |reply| Query::AdjOut {
        peer: 3,
        afi: Afi::IPV4,
        limit: 10,
        reply,
    });
    assert_eq!(page.total, 2, "own prefix and the customer's");
    let route = page
        .routes
        .iter()
        .find(|r| r.prefix == p("203.0.113.0/24"))
        .unwrap();
    assert_eq!(path_of(&route.attrs), [64500, 64500, 64510]);
    assert!(
        route
            .attrs
            .contains(&PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1)))
    );
    assert_eq!(otc_of(&route.attrs), Some(64500));
    let page = ask(&mut rib, |reply| Query::AdjOut {
        peer: 1,
        afi: Afi::IPV4,
        limit: 10,
        reply,
    });
    assert_eq!(page.total, 1, "the provider only gets our own prefix");
}
