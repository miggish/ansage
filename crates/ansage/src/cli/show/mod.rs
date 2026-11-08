//! `ansage show`, and the human-readable output of every reply.
//!
//! Works on `serde_json::Value` rather than the server's types, so a CLI
//! talking to a slightly newer or older ansage prints what it understands
//! and shows missing fields as "-".

mod actions;
mod peers;
mod routes;
mod summary;

pub use actions::{drain, own, peer_action, reload, restart_plan};
pub use peers::peers;
pub use routes::{fib, rib};
pub use summary::summary;

use std::{fmt::Write as _, path::Path, process::ExitCode};

use serde_json::Value;

use super::{FamilyArg, Show, call};
use crate::{
    control::proto::{Family, Request},
    peer::status::Timestamp,
};

/// `ansage show`: one request, printed as text or JSON.
pub(super) fn run(socket: &Path, json: bool, what: Show) -> ExitCode {
    let request = match &what {
        Show::Summary => Request::Summary,
        Show::Peers => Request::Peers { peer: None },
        Show::Peer { neighbor } => Request::Peers {
            peer: Some(neighbor.clone()),
        },
        Show::Rib {
            prefix,
            family,
            limit,
        } => Request::Rib {
            prefix: prefix.clone(),
            family: family.map(|f| match f {
                FamilyArg::Ipv4 => Family::Ipv4,
                FamilyArg::Ipv6 => Family::Ipv6,
            }),
            limit: *limit,
        },
        Show::Fib => Request::Fib,
    };
    call(socket, json, request, |reply| match what {
        Show::Summary => summary(reply),
        Show::Peers | Show::Peer { .. } => peers(reply, Timestamp::now().0),
        Show::Rib { .. } => rib(reply),
        Show::Fib => fib(reply),
    })
}

pub fn as_path(segments: &Value) -> String {
    let parts: Vec<String> = list(segments)
        .iter()
        .map(|s| {
            let asns: Vec<String> = list(&s["asns"]).iter().map(text).collect();
            let asns = asns.join(" ");
            match s["type"].as_str() {
                Some("set") => format!("{{{asns}}}"),
                Some("confed-sequence") => format!("({asns})"),
                Some("confed-set") => format!("[{asns}]"),
                _ => asns,
            }
        })
        .collect();
    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(" ")
    }
}

/// A short duration: "850ms", "4.2s", "3m4s", "2h3m", "5d2h".
pub fn duration(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        _ if ms < 1000 => format!("{ms}ms"),
        0..60 => format!("{:.1}s", ms as f64 / 1000.0),
        60..3600 => format!("{}m{}s", s / 60, s % 60),
        3600..86400 => format!("{}h{}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d{}h", s / 86400, s % 86400 / 3600),
    }
}

/// Time since the unix-ms timestamp `at`.
fn ago(now: u64, at: &Value) -> String {
    match at.as_u64() {
        Some(at) => duration(now.saturating_sub(at)),
        None => "-".to_string(),
    }
}

fn list(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

/// A scalar as text; strings without quotes, null and missing as "-".
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_string(),
        other => other.to_string(),
    }
}

/// Left-aligned columns separated by two spaces.
struct Table {
    rows: Vec<Vec<String>>,
}

impl Table {
    fn new(header: &[&str]) -> Self {
        Self {
            rows: vec![header.iter().map(ToString::to_string).collect()],
        }
    }

    fn row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    fn render(&self) -> String {
        let columns = self.rows[0].len();
        let widths: Vec<usize> = (0..columns)
            .map(|i| {
                self.rows
                    .iter()
                    .map(|r| r[i].chars().count())
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let mut out = String::new();
        for row in &self.rows {
            let mut line = String::new();
            for (i, cell) in row.iter().enumerate() {
                if i + 1 == columns {
                    line.push_str(cell);
                } else {
                    let _ = write!(line, "{cell:<width$}  ", width = widths[i]);
                }
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests;
