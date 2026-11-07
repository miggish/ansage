//! The Prometheus text exposition at `/metrics`.

use std::fmt::Write as _;

use herald_bgp::session::State;

use crate::{
    control::{self, Context},
    peer::status::PeerHandle,
    rib::Query,
};

/// One metric family: HELP and TYPE lines, then the samples.
pub(super) struct Family<'a> {
    pub(super) out: &'a mut String,
}

impl<'a> Family<'a> {
    pub(super) fn new(out: &'a mut String, name: &str, kind: &str, help: &str) -> Self {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
        Self { out }
    }

    pub(super) fn sample(
        &mut self,
        name: &str,
        labels: &[(&str, &str)],
        value: impl std::fmt::Display,
    ) {
        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (i, (key, val)) in labels.iter().enumerate() {
                if i > 0 {
                    self.out.push(',');
                }
                let _ = write!(self.out, "{key}=\"{}\"", escape(val));
            }
            self.out.push('}');
        }
        let _ = writeln!(self.out, " {value}");
    }
}

/// Label value escaping of the text format.
pub(super) fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// The whole exposition.
pub async fn render(ctx: &Context) -> String {
    let peers = ctx.peers();
    let rib = control::ask(ctx, Query::Summary).await.ok();
    let mut out = String::with_capacity(4096 + peers.len() * 2048);

    let router_id = ctx.router_id.to_string();
    let asn = ctx.asn.to_string();
    Family::new(
        &mut out,
        "herald_info",
        "gauge",
        "herald version and identity.",
    )
    .sample(
        "herald_info",
        &[
            ("version", env!("CARGO_PKG_VERSION")),
            ("asn", &asn),
            ("router_id", &router_id),
        ],
        1,
    );
    Family::new(
        &mut out,
        "herald_start_time_seconds",
        "gauge",
        "When herald started, unix time.",
    )
    .sample("herald_start_time_seconds", &[], seconds(ctx.started.0));

    if let Some(rib) = &rib {
        let mut f = Family::new(
            &mut out,
            "herald_rib_prefixes",
            "gauge",
            "Prefixes in the RIB.",
        );
        f.sample(
            "herald_rib_prefixes",
            &[("family", "ipv4")],
            rib.stats.prefixes_ipv4,
        );
        f.sample(
            "herald_rib_prefixes",
            &[("family", "ipv6")],
            rib.stats.prefixes_ipv6,
        );
        Family::new(
            &mut out,
            "herald_rib_attribute_sets",
            "gauge",
            "Distinct path attribute sets in the RIB.",
        )
        .sample("herald_rib_attribute_sets", &[], rib.stats.attr_sets);
        Family::new(
            &mut out,
            "herald_own_prefixes",
            "gauge",
            "Own prefixes announced to neighbors.",
        )
        .sample("herald_own_prefixes", &[], rib.own.len());
        Family::new(
            &mut out,
            "herald_drained",
            "gauge",
            "1 while our routes go out with GRACEFUL_SHUTDOWN (herald drain).",
        )
        .sample("herald_drained", &[], u8::from(rib.drained.is_some()));
    }
    Family::new(
        &mut out,
        "herald_rib_up",
        "gauge",
        "1 if the RIB answered this scrape.",
    )
    .sample("herald_rib_up", &[], u8::from(rib.is_some()));

    peer_metrics(&mut out, &peers, rib.as_ref());
    if ctx.fib.is_some() {
        let fib = control::ask_fib(ctx, crate::fib::FibQuery::Status)
            .await
            .ok();
        fib_metrics(&mut out, fib.as_ref());
    }
    process_metrics(&mut out);
    out
}

/// With `[kernel]`: what the FIB installed.
fn fib_metrics(out: &mut String, fib: Option<&crate::fib::FibStatus>) {
    Family::new(
        out,
        "herald_fib_up",
        "gauge",
        "1 if the FIB answered this scrape.",
    )
    .sample("herald_fib_up", &[], u8::from(fib.is_some()));
    let Some(fib) = fib else {
        return;
    };
    let mut f = Family::new(
        out,
        "herald_fib_routes",
        "gauge",
        "Prefixes herald wants in the kernel, by state.",
    );
    for (family, state, n) in [
        ("ipv4", "installed", fib.installed_ipv4),
        ("ipv6", "installed", fib.installed_ipv6),
        ("all", "unresolved", fib.unresolved),
        ("all", "failed", fib.failed),
        ("all", "shadowed", fib.shadowed),
    ] {
        f.sample(
            "herald_fib_routes",
            &[("family", family), ("state", state)],
            n,
        );
    }
    Family::new(
        out,
        "herald_fib_adopted_routes",
        "gauge",
        "Kernel routes of an earlier run not taken over yet.",
    )
    .sample("herald_fib_adopted_routes", &[], fib.adopted);
    let reachable = fib.next_hops.iter().filter(|h| h.via.is_some()).count();
    let mut f = Family::new(
        out,
        "herald_fib_next_hops",
        "gauge",
        "BGP next hops by reachability through the kernel.",
    );
    f.sample("herald_fib_next_hops", &[("state", "reachable")], reachable);
    f.sample(
        "herald_fib_next_hops",
        &[("state", "unreachable")],
        fib.next_hops.len() - reachable,
    );
    let mut f = Family::new(
        out,
        "herald_fib_errors_total",
        "counter",
        "Changes the kernel refused, by errno.",
    );
    for (reason, n) in &fib.errors {
        f.sample("herald_fib_errors_total", &[("reason", reason)], n);
    }
}

pub(super) fn seconds(ms: u64) -> String {
    format!("{}.{:03}", ms / 1000, ms % 1000)
}

fn peer_metrics(out: &mut String, peers: &[PeerHandle], rib: Option<&crate::rib::RibSummary>) {
    struct Row {
        neighbor: String,
        asn: String,
        description: String,
        handle: PeerHandle,
    }
    let rows: Vec<Row> = peers
        .iter()
        .map(|h| Row {
            neighbor: h.neighbor.address.to_string(),
            asn: h.neighbor.asn.to_string(),
            description: h.neighbor.description.clone().unwrap_or_default(),
            handle: h.clone(),
        })
        .collect();
    let labels = |r: &Row| [("neighbor", r.neighbor.clone()), ("asn", r.asn.clone())];

    let mut f = Family::new(
        out,
        "herald_peer_info",
        "gauge",
        "Configured neighbors (description as a label).",
    );
    for r in &rows {
        let l = labels(r);
        f.sample(
            "herald_peer_info",
            &[
                ("neighbor", &l[0].1),
                ("asn", &l[1].1),
                ("description", &r.description),
            ],
            1,
        );
    }

    let states = [
        State::Idle,
        State::Active,
        State::Connect,
        State::OpenSent,
        State::OpenConfirm,
        State::Established,
    ];
    let mut f = Family::new(
        out,
        "herald_peer_state",
        "gauge",
        "BGP FSM state, 1 for the current one.",
    );
    for r in &rows {
        let state = r.handle.status.borrow().state;
        for s in states {
            let name = format!("{s:?}");
            f.sample(
                "herald_peer_state",
                &[("neighbor", &r.neighbor), ("state", &name)],
                u8::from(s == state),
            );
        }
    }

    type Show = fn(&crate::peer::status::PeerStatus) -> String;
    let gauges: [(&str, &str, Show); 6] = [
        (
            "herald_peer_up",
            "1 while the session is Established.",
            |s| u8::from(s.state == State::Established).to_string(),
        ),
        (
            "herald_peer_disabled",
            "1 while disabled by the operator.",
            |s| u8::from(s.disabled).to_string(),
        ),
        (
            "herald_peer_state_since_seconds",
            "When the current state was entered, unix time.",
            |s| seconds(s.since.0),
        ),
        (
            "herald_peer_graceful_restart",
            "1 if the current session negotiated Graceful Restart (both sides offered it).",
            |s| {
                u8::from(
                    s.session
                        .as_ref()
                        .is_some_and(|x| x.graceful_restart.is_some()),
                )
                .to_string()
            },
        ),
        (
            "herald_peer_graceful_restart_notification",
            "1 if the current session also negotiated the N bit (RFC 8538).",
            |s| {
                let n = s
                    .session
                    .as_ref()
                    .and_then(|x| x.graceful_restart.as_ref())
                    .is_some_and(|g| g.notification);
                u8::from(n).to_string()
            },
        ),
        (
            "herald_peer_graceful_restart_offered",
            "1 if the peer offers Graceful Restart in its OPEN (also while ours is off).",
            |s| {
                u8::from(
                    s.session
                        .as_ref()
                        .is_some_and(|x| x.peer_graceful_restart.is_some()),
                )
                .to_string()
            },
        ),
    ];
    for (name, help, value) in gauges {
        let mut f = Family::new(out, name, "gauge", help);
        for r in &rows {
            let l = labels(r);
            let status = r.handle.status.borrow().clone();
            f.sample(
                name,
                &[("neighbor", &l[0].1), ("asn", &l[1].1)],
                value(&status),
            );
        }
    }

    let mut f = Family::new(
        out,
        "herald_peer_graceful_restart_enabled",
        "gauge",
        "1 if we offer Graceful Restart to this neighbor (config).",
    );
    for r in &rows {
        let l = labels(r);
        f.sample(
            "herald_peer_graceful_restart_enabled",
            &[("neighbor", &l[0].1), ("asn", &l[1].1)],
            u8::from(r.handle.neighbor.graceful_restart.is_some()),
        );
    }

    // Counters.
    type Get = fn(&crate::peer::status::CounterSnapshot) -> u64;
    let counters: [(&str, &str, Get); 12] = [
        (
            "herald_peer_established_total",
            "Sessions that reached Established.",
            |c| c.established,
        ),
        (
            "herald_peer_connect_attempts_total",
            "Outgoing connection attempts.",
            |c| c.connect_attempts,
        ),
        (
            "herald_peer_connect_failures_total",
            "Outgoing connection attempts that failed.",
            |c| c.connect_failures,
        ),
        (
            "herald_peer_incoming_accepted_total",
            "Connections from the peer used for the session.",
            |c| c.incoming_accepted,
        ),
        (
            "herald_peer_incoming_rejected_total",
            "Connections from the peer turned away.",
            |c| c.incoming_rejected,
        ),
        (
            "herald_peer_prefixes_announced_total",
            "Prefixes in UPDATEs sent.",
            |c| c.prefixes_announced,
        ),
        (
            "herald_peer_prefixes_withdrawn_total",
            "Prefixes withdrawn in UPDATEs sent.",
            |c| c.prefixes_withdrawn,
        ),
        (
            "herald_peer_malformed_updates_total",
            "UPDATEs treated as withdraw (RFC 7606).",
            |c| c.malformed_updates,
        ),
        (
            "herald_peer_discarded_attributes_total",
            "UPDATEs with attributes discarded (RFC 7606).",
            |c| c.discarded_attributes,
        ),
        (
            "herald_peer_decode_errors_total",
            "Messages that could not be decoded.",
            |c| c.decode_errors,
        ),
        (
            "herald_peer_control_drops_total",
            "Control messages dropped on a full queue.",
            |c| c.control_drops,
        ),
        (
            "herald_peer_data_drops_total",
            "Route batches dropped on a full queue.",
            |c| c.data_drops,
        ),
    ];
    let snapshots: Vec<_> = rows.iter().map(|r| r.handle.counters.snapshot()).collect();
    for (name, help, get) in counters {
        let mut f = Family::new(out, name, "counter", help);
        for (r, c) in rows.iter().zip(&snapshots) {
            let l = labels(r);
            f.sample(name, &[("neighbor", &l[0].1), ("asn", &l[1].1)], get(c));
        }
    }

    for (name, help, dir) in [
        (
            "herald_peer_messages_received_total",
            "BGP messages received, by type.",
            true,
        ),
        (
            "herald_peer_messages_sent_total",
            "BGP messages sent, by type.",
            false,
        ),
    ] {
        let mut f = Family::new(out, name, "counter", help);
        for (r, c) in rows.iter().zip(&snapshots) {
            let m = if dir { c.messages_in } else { c.messages_out };
            for (kind, n) in [
                ("open", m.open),
                ("update", m.update),
                ("notification", m.notification),
                ("keepalive", m.keepalive),
                ("route_refresh", m.route_refresh),
            ] {
                f.sample(name, &[("neighbor", &r.neighbor), ("type", kind)], n);
            }
        }
    }

    if let Some(rib) = rib {
        for (name, help, received) in [
            (
                "herald_peer_prefixes_received",
                "Routes stored from the neighbor.",
                true,
            ),
            (
                "herald_peer_prefixes_advertised",
                "Prefixes advertised to the neighbor.",
                false,
            ),
        ] {
            let mut f = Family::new(out, name, "gauge", help);
            for r in &rows {
                let status = rib.peers.iter().find(|p| p.peer == r.handle.neighbor.id);
                let (v4, v6) = match (status, received) {
                    (Some(s), true) => (s.received_ipv4 as usize, s.received_ipv6 as usize),
                    (Some(s), false) => (s.advertised_ipv4, s.advertised_ipv6),
                    (None, _) => (0, 0),
                };
                f.sample(name, &[("neighbor", &r.neighbor), ("family", "ipv4")], v4);
                f.sample(name, &[("neighbor", &r.neighbor), ("family", "ipv6")], v6);
            }
        }
        let mut f = Family::new(
            out,
            "herald_peer_prefixes_stale",
            "gauge",
            "Routes from the neighbor kept through a Graceful Restart and not sent again yet.",
        );
        for r in &rows {
            let stale = rib
                .peers
                .iter()
                .find(|p| p.peer == r.handle.neighbor.id)
                .map_or(0, |p| p.stale);
            let l = labels(r);
            f.sample(
                "herald_peer_prefixes_stale",
                &[("neighbor", &l[0].1), ("asn", &l[1].1)],
                stale,
            );
        }
    }
}

/// The usual process_* metrics from /proc/self (Linux).
fn process_metrics(out: &mut String) {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status")
        && let Some(kb) = status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
    {
        Family::new(
            out,
            "process_resident_memory_bytes",
            "gauge",
            "Resident memory size in bytes.",
        )
        .sample("process_resident_memory_bytes", &[], kb * 1024);
    }
    if let Ok(fds) = std::fs::read_dir("/proc/self/fd") {
        Family::new(out, "process_open_fds", "gauge", "Open file descriptors.").sample(
            "process_open_fds",
            &[],
            fds.count(),
        );
    }
}
