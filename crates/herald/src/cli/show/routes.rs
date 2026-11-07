//! `herald show rib` and `herald show fib`.

use std::fmt::Write as _;

use serde_json::Value;

use super::{Table, as_path, list, text};

/// `show rib`.
pub fn rib(v: &Value) -> String {
    let routes = list(&v["routes"]);
    let mut out = String::new();
    if routes.is_empty() {
        out.push_str("No routes.\n");
    } else {
        let mut table = Table::new(&[
            "",
            "PREFIX",
            "SOURCE",
            "NEXT HOP",
            "AS PATH",
            "ORIGIN",
            "LOCAL PREF",
            "MED",
            "COMMUNITIES",
        ]);
        for r in routes {
            let mut communities: Vec<String> = list(&r["communities"]).iter().map(text).collect();
            communities.extend(list(&r["large_communities"]).iter().map(text));
            let mut next_hop = match r["next_hop_link_local"].as_str() {
                Some(ll) => format!("{} ({ll})", text(&r["next_hop"])),
                None => text(&r["next_hop"]),
            };
            if r["unreachable"] == true {
                next_hop.push_str(" unreachable");
            }
            table.row(vec![
                if r["best"] == true { "*" } else { "" }.to_string(),
                text(&r["prefix"]),
                text(&r["source"]),
                next_hop,
                as_path(&r["as_path"]),
                text(&r["origin"]),
                text(&r["local_pref"]),
                text(&r["med"]),
                if communities.is_empty() {
                    "-".to_string()
                } else {
                    communities.join(" ")
                },
            ]);
        }
        out.push_str(&table.render());
    }
    if let Some(prefix) = routes.first().map(|r| text(&r["prefix"]))
        && v["total"].is_null()
    {
        let k = &v["kernel"];
        if k["state"] == "absent" {
            let _ = writeln!(out, "Kernel: {prefix} not installed");
        } else if k.is_object() {
            let _ = writeln!(
                out,
                "Kernel: {prefix} via {} ({})",
                text(&k["next_hop"]),
                text(&k["state"])
            );
        }
    }
    if let Some(total) = v["total"].as_u64()
        && total > routes.len() as u64
    {
        let _ = writeln!(
            out,
            "{} of {total} best routes shown (use --limit, or give a prefix)",
            routes.len()
        );
    }
    out
}

/// `show fib`.
pub fn fib(v: &Value) -> String {
    let mut out = String::new();
    let num = |key: &str| v[key].as_u64().unwrap_or(0);
    let _ = writeln!(
        out,
        "Kernel table {}, metric {}, protocol bgp{}",
        text(&v["table"]),
        text(&v["metric"]),
        if v["resolve_via_default"] == true {
            ", next hops may resolve via the default route"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "Routes: {} IPv4, {} IPv6 installed; {} waiting for their next hop; {} refused; \
         {} left to the kernel's own routes",
        num("installed_ipv4"),
        num("installed_ipv6"),
        num("unresolved"),
        num("failed"),
        num("shadowed")
    );
    if num("adopted") > 0 {
        let _ = writeln!(
            out,
            "{} routes of the earlier run still kept until the neighbors send them again",
            num("adopted")
        );
    }
    let hops = list(&v["next_hops"]);
    if !hops.is_empty() {
        out.push('\n');
        let mut table = Table::new(&["NEXT HOP", "VIA", "DEV", "ROUTES", "NEXTHOP ID"]);
        for h in hops {
            let reachable = !h["via"].is_null();
            table.row(vec![
                next_hop_name(h),
                if reachable {
                    text(&h["via"])
                } else {
                    "unreachable".to_string()
                },
                text(&h["dev"]),
                text(&h["routes"]),
                text(&h["id"]),
            ]);
        }
        out.push_str(&table.render());
    }
    if let Some(errors) = v["errors"].as_object()
        && !errors.is_empty()
    {
        let items: Vec<String> = errors.iter().map(|(k, n)| format!("{k} {n}")).collect();
        let _ = writeln!(
            out,
            "\nRefused by the kernel since the start: {}",
            items.join(", ")
        );
    }
    out
}

/// A next hop as `show fib` lists it: `fe80::1%eth1` for a link-local one,
/// `2001:db8::1 or fe80::1%eth1` with a link-local fallback.
fn next_hop_name(h: &Value) -> String {
    let address = text(&h["address"]);
    if h["link_local"].is_null() {
        return address;
    }
    let link = format!("{}%{}", text(&h["link_local"]), text(&h["link_dev"]));
    if h["link_local"] == h["address"] {
        link
    } else {
        format!("{address} or {link}")
    }
}
