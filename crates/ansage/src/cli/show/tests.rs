use serde_json::json;

use super::{summary::announce, *};

#[test]
fn durations() {
    assert_eq!(duration(850), "850ms");
    assert_eq!(duration(4_200), "4.2s");
    assert_eq!(duration(184_000), "3m4s");
    assert_eq!(duration(7_380_000), "2h3m");
    assert_eq!(duration(5 * 86_400_000 + 2 * 3_600_000), "5d2h");
}

#[test]
fn long_announce_lists_are_cut() {
    let few: Vec<Value> = (0..3).map(|i| json!(format!("10.0.{i}.0/24"))).collect();
    assert_eq!(announce(&few), "10.0.0.0/24 10.0.1.0/24 10.0.2.0/24");
    let many: Vec<Value> = (0..100_001).map(|i| json!(format!("p{i}"))).collect();
    assert_eq!(
        announce(&many),
        "p0 p1 p2 p3 p4 p5 p6 p7 p8 p9 and 99991 more (100001 prefixes)"
    );
    assert_eq!(announce(&[]), "nothing");
}

#[test]
fn as_paths() {
    let path = json!([
        {"type": "confed-sequence", "asns": [65001]},
        {"type": "sequence", "asns": [64501, 64999]},
        {"type": "set", "asns": [1, 2]},
    ]);
    assert_eq!(as_path(&path), "(65001) 64501 64999 {1 2}");
    assert_eq!(as_path(&json!([])), "(empty)");
}

#[test]
fn summary_table() {
    let v = json!({
        "version": "0.0.1", "asn": 64500, "router_id": "203.0.113.1",
        "started": 0, "now": 7_380_000,
        "rib": {"prefixes_ipv4": 3, "prefixes_ipv6": 1, "attr_sets": 2},
        "announce": ["192.0.2.0/24"],
        "peers": [
            {"id": 1, "address": "10.201.11.2:179", "asn": 64510, "description": "r1 (FRR)",
             "state": "Established", "since": 7_200_000, "received_ipv4": 2, "received_ipv6": 1,
             "advertised_ipv4": 1, "advertised_ipv6": 1},
            {"id": 2, "address": "10.0.0.2:179", "asn": 64520, "description": null,
             "state": "Idle", "since": 0, "received_ipv4": 0, "received_ipv6": 0,
             "advertised_ipv4": 0, "advertised_ipv6": 0},
        ],
    });
    let out = summary(&v);
    let expected = "\
ansage 0.0.1, AS 64500, router ID 203.0.113.1, up 2h3m
RIB: 3 IPv4 and 1 IPv6 prefixes, 2 attribute sets
Announcing: 192.0.2.0/24

ID  NEIGHBOR         AS     STATE        FOR   RCVD v4/v6  SENT v4/v6  DESCRIPTION
1   10.201.11.2:179  64510  Established  3m0s  2/1         1/1         r1 (FRR)
2   10.0.0.2:179     64520  Idle         2h3m  0/0         0/0         -
";
    assert_eq!(out, expected);
}

#[test]
fn drained_summary_and_replies() {
    let v = json!({"now": 90_000, "drained": 30_000, "announce": [], "peers": []});
    assert!(summary(&v).contains(
        "Drained for 1m0s: our routes carry GRACEFUL_SHUTDOWN (ansage undrain ends it)\n"
    ));
    let v = json!({"now": 90_000, "drained": null, "announce": [], "peers": []});
    assert!(!summary(&v).contains("Drained"));

    let reply = json!({"changed": false, "drained": 30_000, "now": 90_000});
    assert_eq!(drain(&reply, true), "Already drained for 1m0s\n");
    let reply = json!({"changed": true, "drained": null, "now": 90_000});
    assert_eq!(
        drain(&reply, false),
        "Drain ended: our routes go out as usual\n"
    );
}

#[test]
fn peer_block() {
    let v = json!([{
        "neighbor": {"id": 1, "address": "10.201.11.2:179", "asn": 64510,
            "description": "r1", "import": "all", "export": "own",
            "max_prefixes_ipv4": 100, "max_prefixes_ipv6": null},
        "status": {"state": "Idle", "since": 1_000, "local": null, "session": null,
            "last_down": {"at": 1_000, "reason": "notification received",
                "notification": {"code": 6, "subcode": 2, "text": "cease (6/2)",
                    "shutdown_text": "maint", "data": "056d61696e74"}},
            "last_error": {"at": 2_000, "message": "connect: Connection refused (os error 111)"},
            "backoff_ms": 4_000, "next_connect": 4_500},
        "counters": {"messages_in": {"open": 1, "update": 2, "notification": 1, "keepalive": 3,
                "route_refresh": 0},
            "messages_out": {"open": 1, "update": 1, "notification": 0, "keepalive": 3,
                "route_refresh": 0},
            "prefixes_announced": 2, "prefixes_withdrawn": 0, "malformed_updates": 0,
            "discarded_attributes": 0, "decode_errors": 0, "control_drops": 0,
            "data_drops": 0, "connect_attempts": 3, "connect_failures": 1, "established": 1},
        "rib": null,
    }]);
    let out = peers(&v, 4_000);
    assert!(
        out.starts_with("Neighbor 10.201.11.2:179 (ID 1), AS 64510, \"r1\"\n"),
        "{out}"
    );
    assert!(out.contains("  Policy: import all, export own, max prefixes IPv4 100, IPv6 -\n"));
    assert!(
        !out.contains("Security:"),
        "older servers send neither field"
    );
    let mut secured = v.clone();
    secured[0]["neighbor"]["tcp_md5"] = json!(true);
    secured[0]["neighbor"]["ttl_security"] = json!(1);
    assert!(peers(&secured, 4_000).contains("  Security: TCP-MD5, GTSM 1 hop\n"));
    assert!(out.contains("  State: Idle for 3.0s\n"), "{out}");
    assert!(!out.contains("Session:"), "no session while Idle");
    assert!(out.contains("  Last down: 3.0s ago, notification received: cease (6/2) \"maint\"\n"));
    assert!(out.contains("  Last error: 2.0s ago, connect: Connection refused (os error 111)\n"));
    assert!(
        out.contains("  Reconnect: backoff 4.0s, next attempt in 500ms\n"),
        "{out}"
    );
    assert!(out.contains("  Connects: 3 attempts, 1 failed, 1 established\n"));
    assert!(!out.contains("Graceful restart"), "no session, GR off");

    // Established, our graceful restart off: what the peer offers.
    let mut up = v.clone();
    up[0]["status"]["state"] = json!("Established");
    up[0]["status"]["session"] = json!({"bgp_id": "203.0.113.11", "hold_time": 9,
        "families": ["ipv4-unicast"], "route_refresh": true, "four_octet_as": true,
        "extended_message": false, "ibgp": false,
        "peer_graceful_restart": {"restart_time": 120, "notification": true,
            "restarting": false, "forwarding": []}});
    let out = peers(&up, 4_000);
    assert!(
        out.contains(
            "  Graceful restart: off; the peer offers it (restart time 120 s, N bit): \
             graceful_restart = true would keep our routes there\n"
        ),
        "{out}"
    );
    up[0]["status"]["session"]["peer_graceful_restart"] = Value::Null;
    assert!(peers(&up, 4_000).contains("  Graceful restart: off; the peer does not offer it\n"));
    // An older daemon does not send the field: say nothing rather than "no".
    let mut old = up.clone();
    old[0]["status"]["session"]
        .as_object_mut()
        .unwrap()
        .remove("peer_graceful_restart");
    assert!(!peers(&old, 4_000).contains("Graceful restart"));

    // Ours on and negotiated.
    up[0]["neighbor"]["graceful_restart"] = json!(30);
    up[0]["status"]["session"]["graceful_restart"] = json!({"restart_time": 120,
        "notification": false, "restarting": true, "forwarding": ["ipv4-unicast"]});
    assert!(
        peers(&up, 4_000).contains(
            "  Graceful restart: 30 s; peer keeps ours, we keep its for 120 s, peer had restarted\n"
        ),
        "{}",
        peers(&up, 4_000)
    );
}

#[test]
fn restart_plan_names_the_way_out() {
    let v = json!({"restart_time": 30, "supervised": true, "neighbors": [
        {"address": "10.0.0.1:179", "action": "keep", "peer_offers": true},
        {"address": "10.0.0.2:179", "action": "drop", "peer_offers": true},
        {"address": "10.0.0.3:179", "action": "drop", "peer_offers": false},
    ]});
    let out = restart_plan(&v);
    assert!(
        out.contains("keeps our routes for 30 s (Cease without Hard Reset)"),
        "{out}"
    );
    assert!(out.contains("WITHDRAWS our routes (graceful restart off here; the peer offers it)"));
    assert!(out.contains("WITHDRAWS our routes (the peer does not offer graceful restart)"));
}

#[test]
fn rib_table() {
    let route = |prefix: &str, source: &str, best: bool| {
        json!({"prefix": prefix, "source": source, "best": best, "origin": "igp",
            "as_path": [{"type": "sequence", "asns": [64510]}], "next_hop": "10.201.11.2",
            "next_hop_link_local": null, "local_pref": null, "med": 5,
            "communities": ["64510:1"], "large_communities": []})
    };
    let v = json!({"total": 5, "routes": [
        route("10.0.0.0/8", "10.201.11.2", true),
        route("10.0.0.0/8", "10.201.12.2", false),
    ]});
    let expected =
        "   PREFIX      SOURCE       NEXT HOP     AS PATH  ORIGIN  LOCAL PREF  MED  COMMUNITIES
*  10.0.0.0/8  10.201.11.2  10.201.11.2  64510    igp     -           5    64510:1
   10.0.0.0/8  10.201.12.2  10.201.11.2  64510    igp     -           5    64510:1
2 of 5 best routes shown (use --limit, or give a prefix)
";
    assert_eq!(rib(&v), expected);
    assert_eq!(rib(&json!({"total": null, "routes": []})), "No routes.\n");
}

#[test]
fn fib_status() {
    let v = json!({
        "table": 254, "metric": 20, "resolve_via_default": false,
        "installed_ipv4": 3, "installed_ipv6": 1, "failed": 0, "unresolved": 2,
        "adopted": 0,
        "next_hops": [
            {"address": "10.0.0.2", "id": 3120562176u32, "via": "10.0.0.2",
             "dev": "eth0", "routes": 4},
            {"address": "172.16.5.5", "id": 3120562177u32, "via": null,
             "dev": null, "routes": 2},
            {"address": "fe80::1", "id": 3120562178u32, "via": "fe80::1",
             "dev": "eth1", "routes": 1, "link_local": "fe80::1", "link_dev": "eth1"},
            {"address": "2001:db8::7", "id": 3120562179u32, "via": "fe80::7",
             "dev": "eth1", "routes": 1, "link_local": "fe80::7", "link_dev": "eth1"},
        ],
        "errors": {"EINVAL": 1},
    });
    let out = fib(&v);
    assert!(
        out.starts_with("Kernel table 254, metric 20, protocol bgp\n"),
        "{out}"
    );
    assert!(
        out.contains("Routes: 3 IPv4, 1 IPv6 installed; 2 waiting"),
        "{out}"
    );
    let row = |start: &str| {
        let line = out
            .lines()
            .find(|l| l.starts_with(start))
            .unwrap_or_default();
        line[start.len()..]
            .split_whitespace()
            .next()
            .map(String::from)
    };
    assert_eq!(row("172.16.5.5 ").as_deref(), Some("unreachable"), "{out}");
    assert_eq!(row("fe80::1%eth1 ").as_deref(), Some("fe80::1"), "{out}");
    assert_eq!(
        row("2001:db8::7 or fe80::7%eth1 ").as_deref(),
        Some("fe80::7"),
        "{out}"
    );
    assert!(
        out.contains("Refused by the kernel since the start: EINVAL 1"),
        "{out}"
    );
}
