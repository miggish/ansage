//! `herald show peers` and `herald show peer`.

use std::fmt::Write as _;

use serde_json::Value;

use super::{ago, duration, list, text};

/// `show peers` / `show peer X`: one block per neighbor. `now` is the
/// current time in unix ms (the reply has none).
pub fn peers(v: &Value, now: u64) -> String {
    let blocks: Vec<String> = list(v).iter().map(|p| peer(p, now)).collect();
    blocks.join("\n")
}

pub(super) fn peer(p: &Value, now: u64) -> String {
    let mut out = String::new();
    let n = &p["neighbor"];
    let s = &p["status"];
    let c = &p["counters"];
    let description = match n["description"].as_str() {
        Some(d) => format!(", {d:?}"),
        None => String::new(),
    };
    let _ = writeln!(
        out,
        "Neighbor {} (ID {}), AS {}{description}",
        text(&n["address"]),
        text(&n["id"]),
        text(&n["asn"]),
    );
    let _ = writeln!(
        out,
        "  Policy: import {}, export {}, max prefixes IPv4 {}, IPv6 {}",
        text(&n["import"]),
        text(&n["export"]),
        text(&n["max_prefixes_ipv4"]),
        text(&n["max_prefixes_ipv6"]),
    );
    let mut security = Vec::new();
    if n["tcp_md5"].as_bool() == Some(true) {
        security.push("TCP-MD5".to_string());
    }
    if let Some(hops) = n["ttl_security"].as_u64() {
        security.push(format!(
            "GTSM {hops} hop{}",
            if hops == 1 { "" } else { "s" }
        ));
    }
    if !security.is_empty() {
        let _ = writeln!(out, "  Security: {}", security.join(", "));
    }
    if let Some(time) = n["graceful_restart"].as_u64() {
        let negotiated = &s["session"]["graceful_restart"];
        let peer = if negotiated.is_object() {
            let mut parts = vec![format!(
                "peer keeps ours, we keep its for {} s",
                text(&negotiated["restart_time"])
            )];
            if negotiated["notification"] == true {
                parts.push("N bit".into());
            }
            if negotiated["restarting"] == true {
                parts.push("peer had restarted".into());
            }
            parts.join(", ")
        } else if s["session"].is_object() {
            "not supported by the peer".to_string()
        } else {
            "no session".to_string()
        };
        let _ = writeln!(out, "  Graceful restart: {time} s; {peer}");
    } else if s["session"].get("peer_graceful_restart").is_some() {
        let _ = writeln!(
            out,
            "  Graceful restart: off; {}",
            peer_offer(&s["session"])
        );
    }
    let local = match s["local"].as_str() {
        Some(local) => format!(", local {local}"),
        None => String::new(),
    };
    let disabled = if s["disabled"].as_bool() == Some(true) {
        " (disabled)"
    } else {
        ""
    };
    let _ = writeln!(
        out,
        "  State: {}{disabled} for {}{local}",
        text(&s["state"]),
        ago(now, &s["since"])
    );

    let session = &s["session"];
    if session.is_object() {
        let mut features: Vec<String> = list(&session["families"]).iter().map(text).collect();
        for (key, name) in [
            ("route_refresh", "route refresh"),
            ("four_octet_as", "4-octet AS"),
            ("extended_message", "extended messages"),
        ] {
            if session[key] == true {
                features.push(name.to_string());
            }
        }
        features.push(
            if session["ibgp"] == true {
                "iBGP"
            } else {
                "eBGP"
            }
            .to_string(),
        );
        let _ = writeln!(
            out,
            "  Session: BGP ID {}, hold time {} s, {}",
            text(&session["bgp_id"]),
            text(&session["hold_time"]),
            features.join(", "),
        );
    }
    let rib = &p["rib"];
    if rib.is_object() {
        let sync = if rib["initial_sync_done"] == true {
            "initial sync done"
        } else {
            "initial sync running"
        };
        let mut torn = if rib["torn_down"] == true {
            ", prefix limit exceeded".to_string()
        } else {
            String::new()
        };
        if let Some(stale) = rib["stale"].as_u64().filter(|&n| n > 0) {
            let _ = write!(torn, ", {stale} stale (graceful restart)");
        }
        let _ = writeln!(
            out,
            "  Routes: received {} IPv4, {} IPv6; advertised {} IPv4, {} IPv6; {} pending, {sync}{torn}",
            text(&rib["received_ipv4"]),
            text(&rib["received_ipv6"]),
            text(&rib["advertised_ipv4"]),
            text(&rib["advertised_ipv6"]),
            text(&rib["pending"]),
        );
    }

    let down = &s["last_down"];
    if down.is_object() {
        let mut line = format!(
            "  Last down: {} ago, {}",
            ago(now, &down["at"]),
            text(&down["reason"])
        );
        let n = &down["notification"];
        if n.is_object() {
            let _ = write!(line, ": {}", text(&n["text"]));
            if let Some(shutdown) = n["shutdown_text"].as_str() {
                let _ = write!(line, " {shutdown:?}");
            } else if n["data"].as_str().is_some_and(|d| !d.is_empty()) {
                let _ = write!(line, ", data {}", text(&n["data"]));
            }
        }
        let _ = writeln!(out, "{line}");
    }
    let error = &s["last_error"];
    if error.is_object() {
        let _ = writeln!(
            out,
            "  Last error: {} ago, {}",
            ago(now, &error["at"]),
            text(&error["message"])
        );
    }
    let next = match s["next_connect"].as_u64() {
        Some(at) => format!(", next attempt in {}", duration(at.saturating_sub(now))),
        None => String::new(),
    };
    let _ = writeln!(
        out,
        "  Reconnect: backoff {}{next}",
        duration(s["backoff_ms"].as_u64().unwrap_or(0))
    );

    for (dir, key) in [("in ", "messages_in"), ("out", "messages_out")] {
        let m = &c[key];
        let _ = writeln!(
            out,
            "  Messages {dir}: {} OPEN, {} UPDATE, {} NOTIFICATION, {} KEEPALIVE, {} ROUTE-REFRESH",
            text(&m["open"]),
            text(&m["update"]),
            text(&m["notification"]),
            text(&m["keepalive"]),
            text(&m["route_refresh"]),
        );
    }
    let _ = writeln!(
        out,
        "  Prefixes sent: {} announced, {} withdrawn",
        text(&c["prefixes_announced"]),
        text(&c["prefixes_withdrawn"]),
    );
    let _ = writeln!(
        out,
        "  Connects: {} attempts, {} failed, {} established",
        text(&c["connect_attempts"]),
        text(&c["connect_failures"]),
        text(&c["established"]),
    );
    let accepted = c["incoming_accepted"].as_u64().unwrap_or(0);
    let rejected = c["incoming_rejected"].as_u64().unwrap_or(0);
    if accepted + rejected > 0 {
        let _ = writeln!(out, "  Incoming: {accepted} accepted, {rejected} rejected");
    }
    let _ = writeln!(
        out,
        "  Problems: {} malformed UPDATEs, {} with discarded attributes, {} decode errors, \
         {} control / {} data queue drops",
        text(&c["malformed_updates"]),
        text(&c["discarded_attributes"]),
        text(&c["decode_errors"]),
        text(&c["control_drops"]),
        text(&c["data_drops"]),
    );
    out
}

/// Whether the peer's OPEN had Graceful Restart (shown while ours is off).
fn peer_offer(session: &Value) -> String {
    let offer = &session["peer_graceful_restart"];
    if !offer.is_object() {
        return "the peer does not offer it".into();
    }
    let n_bit = if offer["notification"] == true {
        ", N bit"
    } else {
        ""
    };
    format!(
        "the peer offers it (restart time {} s{n_bit}): graceful_restart = true would keep our routes there",
        text(&offer["restart_time"])
    )
}
