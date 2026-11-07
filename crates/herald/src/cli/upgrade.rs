//! `herald upgrade`: restart herald (usually into a new binary) while
//! neighbors with Graceful Restart keep our routes, then wait until it is
//! back. The exit status tells a deploy script whether to roll back.
//!
//! 1. Ask the daemon what a restart would do (`restart` with `dry_run`): per
//!    neighbor keep / drop, whether systemd will start herald again.
//! 2. With `--binary`: run it with `--version` and `check` against the running
//!    config, so a broken build or config never takes herald down.
//! 3. Restart (`restart`; the daemon refuses on its own when a neighbor would
//!    withdraw our routes or nothing would start it again, unless `--force`).
//! 4. Wait for the new process (another start time), then for every neighbor
//!    that was Established to be Established again with our End-of-RIB sent:
//!    that is what makes it drop the stale copies of our routes. The peer's
//!    End-of-RIB does not matter here.

use std::{
    collections::BTreeMap,
    path::Path,
    process::{Command, ExitCode},
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::{client, show};
use crate::control::proto::Request;

/// Poll interval while waiting for the new process.
const POLL: Duration = Duration::from_millis(250);
/// Wait when the daemon reports no restart time (no graceful neighbor).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub fn run(
    socket: &Path,
    json: bool,
    binary: Option<&Path>,
    force: bool,
    dry_run: bool,
    timeout: Option<u64>,
) -> ExitCode {
    match upgrade(socket, json, binary, force, dry_run, timeout) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("herald: {err}");
            ExitCode::FAILURE
        }
    }
}

fn upgrade(
    socket: &Path,
    json: bool,
    binary: Option<&Path>,
    force: bool,
    dry_run: bool,
    timeout: Option<u64>,
) -> Result<bool, String> {
    let request = |r| client::request(socket, r).map_err(|err| err.to_string());
    let plan = request(Request::Restart {
        force,
        dry_run: true,
    })?;
    if !json {
        print!("{}", show::restart_plan(&plan));
    }
    if let Some(binary) = binary {
        let version = check_binary(binary, plan["config"].as_str())?;
        if !json {
            println!("New binary: {version}, config OK");
        }
    }
    let refused: Vec<String> = list(&plan["refused"])
        .iter()
        .filter_map(|r| r.as_str().map(str::to_owned))
        .collect();
    if dry_run {
        if json {
            print_json(&plan);
        } else if !refused.is_empty() {
            println!("Would be refused without --force: {}", refused.join("; "));
        }
        return Ok(true);
    }
    if !refused.is_empty() && !force {
        return Err(format!(
            "upgrade refused: {} (--force to restart anyway)",
            refused.join("; ")
        ));
    }

    let waiting: Vec<String> = list(&plan["neighbors"])
        .iter()
        .filter(|n| n["action"].as_str() != Some("down"))
        .filter_map(|n| n["address"].as_str().map(str::to_owned))
        .collect();
    let old_start = plan["started"].clone();
    let timeout = timeout
        .map(Duration::from_secs)
        .or(plan["restart_time"].as_u64().map(Duration::from_secs))
        .unwrap_or(DEFAULT_TIMEOUT);

    request(Request::Restart {
        force,
        dry_run: false,
    })?;
    let start = Instant::now();
    if !json {
        println!(
            "Restarting; waiting up to {} s for {} neighbors",
            timeout.as_secs(),
            waiting.len()
        );
    }

    let mut restarted_after = None;
    let mut back: BTreeMap<String, Duration> = BTreeMap::new();
    // Always until the new process is up, also with no neighbor to wait for.
    while start.elapsed() < timeout && (restarted_after.is_none() || back.len() < waiting.len()) {
        std::thread::sleep(POLL);
        // Errors while the old process exits and the new one starts.
        let Ok(summary) = client::request(socket, Request::Summary) else {
            continue;
        };
        if summary["started"] == old_start {
            continue;
        }
        if restarted_after.is_none() {
            restarted_after = Some(start.elapsed());
            if !json {
                println!("herald is back after {}", secs(start.elapsed()));
            }
        }
        let Ok(peers) = client::request(socket, Request::Peers { peer: None }) else {
            continue;
        };
        for p in list(&peers) {
            let Some(address) = p["neighbor"]["address"].as_str() else {
                continue;
            };
            let done =
                p["status"]["state"] == "Established" && p["rib"]["initial_sync_done"] == true;
            if done && waiting.iter().any(|w| w == address) && !back.contains_key(address) {
                back.insert(address.to_owned(), start.elapsed());
                if !json {
                    println!("  {address:<40} back after {}", secs(start.elapsed()));
                }
            }
        }
    }

    let missing: Vec<&String> = waiting.iter().filter(|w| !back.contains_key(*w)).collect();
    let ok = restarted_after.is_some() && missing.is_empty();
    if json {
        print_json(&json!({
            "plan": plan,
            "restarted_after_ms": restarted_after.map(|d| d.as_millis() as u64),
            "back_after_ms": back.iter().map(|(a, d)| (a.clone(), d.as_millis() as u64)).collect::<BTreeMap<_, _>>(),
            "missing": missing,
            "ok": ok,
        }));
    } else if restarted_after.is_none() {
        println!("herald did not come back within {} s", timeout.as_secs());
    } else if !missing.is_empty() {
        let missing: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        println!(
            "Not back within {} s: {}",
            timeout.as_secs(),
            missing.join(", ")
        );
    } else {
        println!("Upgrade done");
    }
    Ok(ok)
}

/// Runs the new binary with `--version` and `check` against the running
/// config; returns its version line.
fn check_binary(binary: &Path, config: Option<&str>) -> Result<String, String> {
    let shown = binary.display();
    let out = Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|err| format!("cannot run {shown}: {err}"))?;
    if !out.status.success() {
        return Err(format!("{shown} --version failed ({})", out.status));
    }
    let version = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let config = config.ok_or("the running herald did not report its config file")?;
    let out = Command::new(binary)
        .args(["--config", config, "check"])
        .output()
        .map_err(|err| format!("cannot run {shown}: {err}"))?;
    if !out.status.success() {
        return Err(format!(
            "{shown} does not accept the config {config}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(version)
}

fn list(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).expect("a JSON value serializes")
    );
}
