//! What a reload changes, computed from the old and the new config alone.

use std::{collections::HashSet, net::SocketAddr};

use crate::config::Config;

use crate::config::Kernel;

use crate::config::Neighbor;

use ansage_bgp::wire::Prefix;
use serde::Serialize;

/// What a reload does, computed from the old and the new config alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub added: Vec<SocketAddr>,
    pub removed: Vec<SocketAddr>,
    /// Session settings changed: closed and reconnected.
    pub restarted: Vec<SocketAddr>,
    /// Only the description changed.
    pub updated: Vec<SocketAddr>,
    #[serde(serialize_with = "as_strings")]
    pub announce: Vec<Prefix>,
    #[serde(serialize_with = "as_strings")]
    pub withdraw: Vec<Prefix>,
    pub max_prefix_restart: Option<u64>,
    /// New `drain_time` (applies to the next stop).
    pub drain_time: Option<u64>,
    /// New `[kernel]` settings: routes move to the new table or metric,
    /// families follow.
    pub kernel: Option<Kernel>,
}

fn as_strings<S: serde::Serializer>(prefixes: &[Prefix], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(prefixes.iter().map(ToString::to_string))
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        *self == Plan::default()
    }
}

/// Compares two valid configs. Errors name settings that only a restart can
/// change.
pub fn plan(old: &Config, new: &Config) -> Result<Plan, String> {
    let restart_only = [
        ("asn", old.asn != new.asn),
        ("router_id", old.router_id != new.router_id),
        ("listen", old.listen != new.listen),
        ("control_socket", old.control_socket != new.control_socket),
        ("metrics_listen", old.metrics_listen != new.metrics_listen),
        ("[kernel]", old.kernel.is_some() != new.kernel.is_some()),
    ];
    let changed: Vec<&str> = restart_only
        .iter()
        .filter(|(_, changed)| *changed)
        .map(|(name, _)| *name)
        .collect();
    if !changed.is_empty() {
        return Err(format!(
            "{} changed: only a restart applies that",
            changed.join(", ")
        ));
    }

    let mut plan = Plan::default();
    for n in &new.neighbors {
        let key = n.socket_addr();
        match old.neighbors.iter().find(|o| o.socket_addr() == key) {
            None => plan.added.push(key),
            Some(o) if old.session(o) != new.session(n) => plan.restarted.push(key),
            Some(o) if o == n => {}
            Some(o) => {
                // Neither needs the session: `install` only changes what
                // goes into the kernel.
                let same_but_description = Neighbor {
                    description: n.description.clone(),
                    install: n.install,
                    ..o.clone()
                };
                if same_but_description == *n {
                    plan.updated.push(key);
                } else {
                    plan.restarted.push(key);
                }
            }
        }
    }
    let kept: HashSet<SocketAddr> = new.neighbors.iter().map(Neighbor::socket_addr).collect();
    plan.removed = old
        .neighbors
        .iter()
        .map(Neighbor::socket_addr)
        .filter(|a| !kept.contains(a))
        .collect();

    let before: HashSet<&Prefix> = old.announce.iter().collect();
    let after: HashSet<&Prefix> = new.announce.iter().collect();
    plan.announce = new
        .announce
        .iter()
        .filter(|p| !before.contains(p))
        .copied()
        .collect();
    plan.withdraw = old
        .announce
        .iter()
        .filter(|p| !after.contains(p))
        .copied()
        .collect();
    if old.max_prefix_restart != new.max_prefix_restart {
        plan.max_prefix_restart = Some(new.max_prefix_restart);
    }
    if old.drain_time != new.drain_time {
        plan.drain_time = Some(new.drain_time);
    }
    if old.kernel != new.kernel {
        plan.kernel = new.kernel.clone();
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
        asn = 64500
        router_id = "203.0.113.1"
        announce = ["192.0.2.0/24", "2001:db8:1::/48"]

        [[neighbor]]
        address = "10.0.0.1"
        asn = 64501
        description = "r1"

        [[neighbor]]
        address = "10.0.0.2"
        asn = 64502
    "#;

    fn parse(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    fn addr(s: &str) -> SocketAddr {
        format!("{s}:179").parse().unwrap()
    }

    #[test]
    fn same_config_changes_nothing() {
        assert!(plan(&parse(BASE), &parse(BASE)).unwrap().is_empty());
    }

    #[test]
    fn restart_only_settings_are_refused() {
        let new = BASE.replace("asn = 64500", "asn = 64599");
        let err = plan(&parse(BASE), &parse(&new)).unwrap_err();
        assert!(err.contains("asn"), "{err}");
        let new = format!("listen = [\"0.0.0.0:179\"]\n{BASE}");
        let err = plan(&parse(BASE), &parse(&new)).unwrap_err();
        assert!(err.contains("listen"), "{err}");
    }

    #[test]
    fn neighbors_added_removed_restarted_updated() {
        let new = BASE
            .replace("description = \"r1\"", "description = \"r1 (FRR)\"")
            .replace("asn = 64502", "asn = 64502\nhold_time = 30")
            + "\n[[neighbor]]\naddress = \"10.0.0.3\"\nasn = 64503\n";
        let p = plan(&parse(BASE), &parse(&new)).unwrap();
        assert_eq!(p.updated, [addr("10.0.0.1")]);
        assert_eq!(p.restarted, [addr("10.0.0.2")]);
        assert_eq!(p.added, [addr("10.0.0.3")]);
        assert!(p.removed.is_empty());

        let p = plan(&parse(&new), &parse(BASE)).unwrap();
        assert_eq!(p.removed, [addr("10.0.0.3")]);
    }

    #[test]
    fn global_session_settings_restart_every_neighbor() {
        let new = format!("hold_time = 30\n{BASE}");
        let p = plan(&parse(BASE), &parse(&new)).unwrap();
        assert_eq!(p.restarted, [addr("10.0.0.1"), addr("10.0.0.2")]);
    }

    #[test]
    fn own_prefixes_follow_the_file_difference() {
        let new = BASE.replace("\"2001:db8:1::/48\"", "\"198.51.100.0/24\"");
        let p = plan(&parse(BASE), &parse(&new)).unwrap();
        assert_eq!(p.announce, ["198.51.100.0/24".parse().unwrap()]);
        assert_eq!(p.withdraw, ["2001:db8:1::/48".parse().unwrap()]);
        assert!(p.restarted.is_empty());
        let new = format!("max_prefix_restart = 60\n{BASE}");
        let p = plan(&parse(BASE), &parse(&new)).unwrap();
        assert_eq!(p.max_prefix_restart, Some(60));
        let new = format!("drain_time = 30\n{BASE}");
        let p = plan(&parse(BASE), &parse(&new)).unwrap();
        assert_eq!(p.drain_time, Some(30));
        assert!(p.restarted.is_empty(), "drain_time only matters at stop");
    }

    #[test]
    fn a_new_drain_prepend_restarts_the_neighbor() {
        let new = BASE.replace("asn = 64502", "asn = 64502\ndrain_prepend = 3");
        let p = plan(&parse(BASE), &parse(&new)).unwrap();
        assert_eq!(p.restarted, [addr("10.0.0.2")]);
    }

    #[test]
    fn kernel_settings_reload_but_the_section_needs_a_restart() {
        let with = format!("{BASE}\n[kernel]\n");
        let err = plan(&parse(BASE), &parse(&with)).unwrap_err();
        assert!(err.contains("[kernel]"), "{err}");
        let moved = format!("{BASE}\n[kernel]\ntable = 100\n");
        let p = plan(&parse(&with), &parse(&moved)).unwrap();
        assert_eq!(p.kernel.unwrap().table, 100);
        assert!(p.restarted.is_empty());
    }

    #[test]
    fn install_changes_no_session() {
        let base = format!("{BASE}\n[kernel]\n");
        let new = base.replace("asn = 64502", "asn = 64502\ninstall = false");
        let p = plan(&parse(&base), &parse(&new)).unwrap();
        assert_eq!(p.updated, [addr("10.0.0.2")]);
        assert!(p.restarted.is_empty());
    }

    #[test]
    fn a_new_password_restarts_the_neighbor() {
        let new = BASE.replace("asn = 64502", "asn = 64502\npassword = \"s\"");
        let p = plan(&parse(BASE), &parse(&new)).unwrap();
        assert_eq!(p.restarted, [addr("10.0.0.2")]);
    }
}
