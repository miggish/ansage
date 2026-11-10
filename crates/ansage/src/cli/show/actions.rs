//! Replies to actions: announce/withdraw, drain, reload, upgrade plan, peer
//! actions.

use std::fmt::Write as _;

use serde_json::Value;

use super::{ago, list, text};

/// AS_PATH like routers print it: sequences plain, sets in braces,
/// confederation segments in parentheses / brackets.
/// Reply to `announce` (`announce` true) or `withdraw`.
pub fn own(v: &Value, announce: bool) -> String {
    let join = |key: &str| {
        let items: Vec<String> = list(&v[key]).iter().map(text).collect();
        items.join(", ")
    };
    let (done, skipped) = if announce {
        ("Announced", "Already announced")
    } else {
        ("Withdrawn", "Not announced")
    };
    let mut out = String::new();
    for (label, key) in [(done, "changed"), (skipped, "unchanged")] {
        if !list(&v[key]).is_empty() {
            let _ = writeln!(out, "{label}: {}", join(key));
        }
    }
    let now = join("announce");
    let _ = writeln!(
        out,
        "Own prefixes now: {}",
        if now.is_empty() { "none" } else { &now }
    );
    out
}

/// What a restart does per neighbor (`ansage upgrade`, also `--dry-run`).
pub fn restart_plan(v: &Value) -> String {
    let mut out = String::new();
    let keep_for = v["restart_time"]
        .as_u64()
        .map_or(String::new(), |s| format!(" for {s} s"));
    for n in list(&v["neighbors"]) {
        let what = match n["action"].as_str().unwrap_or_default() {
            "keep" => format!("keeps our routes{keep_for} (Cease without Hard Reset)"),
            "keep (no NOTIFICATION)" => {
                format!("keeps our routes{keep_for} (closed without NOTIFICATION)")
            }
            "drop" if n["peer_offers"] == true => {
                "WITHDRAWS our routes (graceful restart off here; the peer offers it)".to_string()
            }
            "drop" => "WITHDRAWS our routes (the peer does not offer graceful restart)".to_string(),
            "down" => "no session".to_string(),
            other => other.to_string(),
        };
        let _ = writeln!(out, "  {:<40} {what}", text(&n["address"]));
    }
    if v["supervised"].as_bool() == Some(false) {
        out.push_str("ansage does not run under systemd: nothing would start it again\n");
    }
    out
}

/// Reply to `reload`: what changed.
pub fn reload(v: &Value) -> String {
    let mut out = String::new();
    for (key, label) in [
        ("added", "Neighbors added"),
        ("removed", "Neighbors removed"),
        ("restarted", "Neighbors reconnecting with new settings"),
        ("updated", "Neighbors updated without reconnecting"),
        ("announce", "Prefixes announced"),
        ("withdraw", "Prefixes withdrawn"),
    ] {
        let items: Vec<String> = list(&v[key]).iter().map(text).collect();
        if !items.is_empty() {
            let _ = writeln!(out, "{label}: {}", items.join(", "));
        }
    }
    if let Some(secs) = v["max_prefix_restart"].as_u64() {
        let _ = writeln!(out, "max_prefix_restart: {secs} s");
    }
    if let Some(secs) = v["drain_time"].as_u64() {
        let _ = writeln!(out, "drain_time: {secs} s");
    }
    if out.is_empty() {
        out.push_str("Config reloaded, nothing changed\n");
    }
    out
}

/// Reply to `drain` (`drained` true) or `undrain`.
pub fn drain(v: &Value, drained: bool) -> String {
    let changed = v["changed"] == true;
    match (drained, changed) {
        (true, true) => {
            "Drained: our routes go out with GRACEFUL_SHUTDOWN 65535:0 until `ansage undrain`\n"
                .into()
        }
        (true, false) => format!(
            "Already drained for {}\n",
            ago(v["now"].as_u64().unwrap_or(0), &v["drained"])
        ),
        (false, true) => "Drain ended: our routes go out as usual\n".into(),
        (false, false) => "Not drained\n".into(),
    }
}

/// Reply to `peer ... disable|enable|reset`.
pub fn peer_action(v: &Value) -> String {
    format!(
        "Neighbor {} (ID {}): {} requested\n",
        text(&v["address"]),
        text(&v["id"]),
        text(&v["action"]),
    )
}
