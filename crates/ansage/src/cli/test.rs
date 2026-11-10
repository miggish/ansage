//! `ansage test`: one route through import, best path, kernel and export,
//! asked from the running ansage or (`--offline`) worked out from the config
//! file alone. `--file` runs a list of such tests with expected outcomes.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Args;
use serde::Deserialize;
use serde_json::Value;

use super::{call, client, show};
use crate::{
    config::{Action, Config},
    control::proto::{Request, TestRequest, TraceJson},
    rib::{LOCAL, Rib, RibConfig},
};

#[derive(Args)]
pub struct TestArgs {
    /// A prefix, or (without --from) an address.
    #[arg(required_unless_present = "file")]
    target: Option<String>,
    /// The neighbor (address) the route comes from.
    #[arg(long)]
    from: Option<String>,
    /// AS path, e.g. "64501 64510" [default: the neighbor's AS].
    #[arg(long, requires = "from")]
    as_path: Option<String>,
    /// A community "asn:value" the route carries (repeatable).
    #[arg(long = "community", requires = "from")]
    communities: Vec<String>,
    /// A large community "global:data1:data2" (repeatable).
    #[arg(long = "large-community", requires = "from")]
    large_communities: Vec<String>,
    #[arg(long, requires = "from")]
    med: Option<u32>,
    /// [default: the neighbor's address]
    #[arg(long, requires = "from")]
    next_hop: Option<String>,
    /// RFC 9234 Only-To-Customer: the AS that set it.
    #[arg(long, requires = "from")]
    otc: Option<u32>,
    /// Work it out from the config file (--config) instead of asking the
    /// running ansage: no learned routes, every session assumed up.
    #[arg(long)]
    pub offline: bool,
    /// Run the tests in this TOML file ([[test]] entries with `expect`);
    /// exit 1 if one fails.
    #[arg(long, conflicts_with = "target")]
    file: Option<PathBuf>,
}

impl TestArgs {
    fn request(&self) -> Result<TestRequest, String> {
        let as_path = match &self.as_path {
            Some(path) => Some(
                path.split_whitespace()
                    .map(|asn| asn.parse().map_err(|_| format!("AS path: {asn:?}")))
                    .collect::<Result<_, _>>()?,
            ),
            None => None,
        };
        Ok(TestRequest {
            target: self.target.clone().unwrap_or_default(),
            from: self.from.clone(),
            as_path,
            communities: self.communities.clone(),
            large_communities: self.large_communities.clone(),
            med: self.med,
            next_hop: self.next_hop.clone(),
            otc: self.otc,
        })
    }
}

/// One `[[test]]` of a `--file`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: Option<String>,
    /// A prefix, or (without `from`) an address.
    prefix: String,
    from: Option<String>,
    as_path: Option<Vec<u32>>,
    #[serde(default)]
    communities: Vec<String>,
    #[serde(default)]
    large_communities: Vec<String>,
    med: Option<u32>,
    next_hop: Option<String>,
    otc: Option<u32>,
    #[serde(default)]
    expect: Expect,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    /// "accept" or "reject" on import (a route with `from`).
    import: Option<Action>,
    /// The route is (would be) the best one.
    best: Option<bool>,
    /// It is (would be) installed in the kernel.
    installed: Option<bool>,
    /// Neighbors (addresses) that get it.
    #[serde(default)]
    sent_to: Vec<String>,
    /// Neighbors that do not.
    #[serde(default)]
    not_sent_to: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseFile {
    #[serde(rename = "test")]
    tests: Vec<Case>,
}

impl Case {
    fn request(&self) -> TestRequest {
        TestRequest {
            target: self.prefix.clone(),
            from: self.from.clone(),
            as_path: self.as_path.clone(),
            communities: self.communities.clone(),
            large_communities: self.large_communities.clone(),
            med: self.med,
            next_hop: self.next_hop.clone(),
            otc: self.otc,
        }
    }

    /// What does not match the expectation, if anything.
    fn check(&self, trace: &Value) -> Vec<String> {
        let mut failed = Vec::new();
        let expect = &self.expect;
        if let Some(action) = expect.import {
            let accepted = trace["import"]["accepted"] == true;
            if accepted != (action == Action::Accept) {
                failed.push(format!(
                    "import: expected {}, got {} ({})",
                    if action == Action::Accept {
                        "accept"
                    } else {
                        "reject"
                    },
                    if accepted { "accept" } else { "reject" },
                    show::text(&trace["import"]["reason"]),
                ));
            }
        }
        if let Some(best) = expect.best {
            let is_best = match trace["tested_is_best"].as_bool() {
                Some(is_best) => is_best,
                None => !show::list(&trace["routes"]).is_empty(),
            };
            if is_best != best {
                failed.push(format!("best: expected {best}, got {is_best}"));
            }
        }
        if let Some(installed) = expect.installed
            && trace["kernel"]["installed"].as_bool() != Some(installed)
        {
            failed.push(format!(
                "kernel: expected installed = {installed} ({})",
                show::text(&trace["kernel"]["reason"])
            ));
        }
        let export = |neighbor: &str| {
            show::list(&trace["exports"])
                .iter()
                .find(|e| e["neighbor"] == neighbor)
                .cloned()
        };
        for (neighbors, want) in [(&expect.sent_to, true), (&expect.not_sent_to, false)] {
            for neighbor in neighbors {
                match export(neighbor) {
                    None => failed.push(format!("{neighbor} is not a neighbor")),
                    Some(e) if (e["sent"] == true) != want => failed.push(format!(
                        "{neighbor}: expected {}, got {} ({})",
                        if want { "sent" } else { "not sent" },
                        if want { "not sent" } else { "sent" },
                        show::text(&e["reason"]),
                    )),
                    Some(_) => {}
                }
            }
        }
        failed
    }
}

/// `ansage test` against the running ansage.
pub fn live(socket: &Path, json: bool, args: &TestArgs) -> ExitCode {
    if let Some(file) = &args.file {
        return run_file(file, json, |request| {
            client::request(socket, Request::Test(request)).map_err(|err| err.to_string())
        });
    }
    match args.request() {
        Ok(request) => call(socket, json, Request::Test(request), trace),
        Err(err) => {
            eprintln!("ansage: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `ansage test --offline`: from the config file alone.
pub fn offline(path: &Path, json: bool, args: &TestArgs) -> ExitCode {
    let config = match Config::load(path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("ansage: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut rib = Rib::new(RibConfig::new(&config));
    let mut ask = |request: TestRequest| -> Result<Value, String> {
        let trace = rib.trace(request.query()?)?;
        let name = |id| match id {
            LOCAL => "local".to_string(),
            id => config
                .neighbors
                .get(usize::from(id) - 1)
                .map_or_else(|| format!("peer {id}"), |n| n.address.to_string()),
        };
        serde_json::to_value(TraceJson::new(&trace, name)).map_err(|err| err.to_string())
    };
    if let Some(file) = &args.file {
        return run_file(file, json, ask);
    }
    let reply = match args.request().and_then(&mut ask) {
        Ok(reply) => reply,
        Err(err) => {
            eprintln!("ansage: {err}");
            return ExitCode::FAILURE;
        }
    };
    if json {
        let mut out = serde_json::to_string_pretty(&reply).expect("a JSON value serializes");
        out.push('\n');
        print!("{out}");
    } else {
        print!("{}", trace(&reply));
    }
    ExitCode::SUCCESS
}

/// Runs every case of `file` through `ask`; exit 1 if one fails.
fn run_file(
    file: &Path,
    json: bool,
    mut ask: impl FnMut(TestRequest) -> Result<Value, String>,
) -> ExitCode {
    let cases = match std::fs::read_to_string(file)
        .map_err(|err| err.to_string())
        .and_then(|text| toml::from_str::<CaseFile>(&text).map_err(|err| err.to_string()))
    {
        Ok(file) => file.tests,
        Err(err) => {
            eprintln!("ansage: {}: {err}", file.display());
            return ExitCode::FAILURE;
        }
    };
    let mut failures = 0;
    let mut results = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let name = case
            .name
            .clone()
            .unwrap_or_else(|| format!("test {}", i + 1));
        let failed = match ask(case.request()) {
            Ok(trace) => case.check(&trace),
            Err(err) => vec![err],
        };
        if !failed.is_empty() {
            failures += 1;
        }
        if json {
            results
                .push(serde_json::json!({"name": name, "ok": failed.is_empty(), "failed": failed}));
        } else if failed.is_empty() {
            println!("ok    {name}");
        } else {
            println!("FAIL  {name}");
            for reason in failed {
                println!("      {reason}");
            }
        }
    }
    if json {
        let out = serde_json::json!({"passed": cases.len() - failures, "failed": failures, "tests": results});
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("a JSON value serializes")
        );
    } else {
        println!("{} passed, {failures} failed", cases.len() - failures);
    }
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// One route's attributes in a line.
fn route_line(r: &Value) -> String {
    let mut parts = vec![format!("AS path {}", show::as_path(&r["as_path"]))];
    if let Some(hop) = r["next_hop"].as_str() {
        parts.push(format!("next hop {hop}"));
    }
    if !r["local_pref"].is_null() {
        parts.push(format!("local pref {}", show::text(&r["local_pref"])));
    }
    if !r["med"].is_null() {
        parts.push(format!("MED {}", show::text(&r["med"])));
    }
    let communities: Vec<String> = show::list(&r["communities"])
        .iter()
        .chain(show::list(&r["large_communities"]))
        .map(show::text)
        .collect();
    if !communities.is_empty() {
        parts.push(format!("communities {}", communities.join(" ")));
    }
    if let Some(asn) = r["only_to_customer"].as_u64() {
        parts.push(format!("OTC {asn}"));
    }
    parts.join(", ")
}

/// "accepted by the import filter (filter in, rule 2)": the reason, with
/// the filter where it decided.
fn why(step: &Value) -> String {
    let reason = show::text(&step["reason"]);
    match (step["filter"].as_str(), step["rule"].as_u64()) {
        (Some(f), Some(r)) => format!("{reason} (filter {f}, rule {r})"),
        (Some(f), None) if reason.contains("filter") => format!("{reason} (filter {f})"),
        _ => reason,
    }
}

/// The text form of a `test` reply.
pub fn trace(v: &Value) -> String {
    let mut out = String::new();
    let prefix = show::text(&v["prefix"]);
    let routes = show::list(&v["routes"]);
    if let Some(tested) = v["tested"].as_object() {
        let tested = Value::Object(tested.clone());
        let _ = writeln!(
            out,
            "Route   {prefix} from {}",
            show::text(&tested["source"])
        );
        let _ = writeln!(out, "        {}", route_line(&tested));
        let import = &v["import"];
        let mut line = why(import);
        if !line.starts_with("accepted") && !line.starts_with("rejected") {
            let verdict = if import["accepted"] == true {
                "accepted"
            } else {
                "rejected"
            };
            line = format!("{verdict}: {line}");
        }
        let _ = writeln!(out, "Import  {line}");
        if import["accepted"] != true {
            return out;
        }
        if let Some(stored) = routes.iter().find(|r| r["source"] == tested["source"]) {
            let _ = writeln!(out, "Stored  {}", route_line(stored));
        }
        let best = if v["tested_is_best"] == true {
            format!("yes, of {} route(s)", routes.len())
        } else {
            match routes.first() {
                Some(b) => format!("no: the route from {} wins", show::text(&b["source"])),
                None => "no".to_string(),
            }
        };
        let _ = writeln!(out, "Best    {best}");
    } else {
        match routes.first() {
            Some(best) => {
                let _ = writeln!(
                    out,
                    "Route   {prefix} from {} (best of {})",
                    show::text(&best["source"]),
                    routes.len()
                );
                let _ = writeln!(out, "        {}", route_line(best));
            }
            None => {
                let _ = writeln!(out, "Route   {prefix}: no route");
            }
        }
    }
    let kernel = &v["kernel"];
    let _ = writeln!(out, "Kernel  {}", show::text(&kernel["reason"]));
    out.push('\n');
    let mut table = show::Table::new(&["NEIGHBOR", "ROLE", "SESSION", "RESULT", "WHY", "SENT AS"]);
    for e in show::list(&v["exports"]) {
        table.row(vec![
            show::text(&e["neighbor"]),
            show::text(&e["role"]),
            if e["up"] == true { "up" } else { "not up*" }.to_string(),
            if e["sent"] == true {
                "sent"
            } else {
                "not sent"
            }
            .to_string(),
            why(e),
            if e["sent"] == true {
                route_line(&e["route"])
            } else {
                String::new()
            },
        ]);
    }
    out.push_str(&table.render());
    if show::list(&v["exports"]).iter().any(|e| e["up"] != true) {
        out.push_str("* not up: both families and a next hop assumed\n");
    }
    out
}
