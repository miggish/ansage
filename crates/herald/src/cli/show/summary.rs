//! `herald show summary`.

use std::fmt::Write as _;

use serde_json::Value;

use super::{Table, ago, list, text};

/// `show summary`.
pub fn summary(v: &Value) -> String {
    let mut out = String::new();
    let now = v["now"].as_u64().unwrap_or(0);
    let _ = writeln!(
        out,
        "herald {}, AS {}, router ID {}, up {}",
        text(&v["version"]),
        text(&v["asn"]),
        text(&v["router_id"]),
        ago(now, &v["started"]),
    );
    let rib = &v["rib"];
    let _ = writeln!(
        out,
        "RIB: {} IPv4 and {} IPv6 prefixes, {} attribute sets",
        text(&rib["prefixes_ipv4"]),
        text(&rib["prefixes_ipv6"]),
        text(&rib["attr_sets"]),
    );
    let _ = writeln!(out, "Announcing: {}", announce(list(&v["announce"])));
    if !v["drained"].is_null() {
        let _ = writeln!(
            out,
            "Drained for {}: our routes carry GRACEFUL_SHUTDOWN (herald undrain ends it)",
            ago(now, &v["drained"])
        );
    }

    let peers = list(&v["peers"]);
    if peers.is_empty() {
        out.push_str("\nNo neighbors configured.\n");
        return out;
    }
    let mut table = Table::new(&[
        "ID",
        "NEIGHBOR",
        "AS",
        "STATE",
        "FOR",
        "RCVD v4/v6",
        "SENT v4/v6",
        "DESCRIPTION",
    ]);
    for p in peers {
        table.row(vec![
            text(&p["id"]),
            text(&p["address"]),
            text(&p["asn"]),
            text(&p["state"]),
            ago(now, &p["since"]),
            format!(
                "{}/{}",
                text(&p["received_ipv4"]),
                text(&p["received_ipv6"])
            ),
            format!(
                "{}/{}",
                text(&p["advertised_ipv4"]),
                text(&p["advertised_ipv6"])
            ),
            text(&p["description"]),
        ]);
    }
    out.push('\n');
    out.push_str(&table.render());
    out
}

/// Own prefixes shown in the summary; the rest is counted (`--json` has all).
pub(super) const ANNOUNCE_SHOWN: usize = 10;

pub(super) fn announce(prefixes: &[Value]) -> String {
    if prefixes.is_empty() {
        return "nothing".to_string();
    }
    let shown: Vec<String> = prefixes.iter().take(ANNOUNCE_SHOWN).map(text).collect();
    let mut line = shown.join(" ");
    if prefixes.len() > ANNOUNCE_SHOWN {
        let _ = write!(
            line,
            " and {} more ({} prefixes)",
            prefixes.len() - ANNOUNCE_SHOWN,
            prefixes.len()
        );
    }
    line
}
