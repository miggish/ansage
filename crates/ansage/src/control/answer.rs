//! Answers to control requests: queries go to the RIB, FIB or peer handles,
//! actions to the daemon.

use std::net::{IpAddr, SocketAddr};

use ansage_bgp::wire::Afi;

use ansage_bgp::wire::Prefix;
use tokio::sync::oneshot;

use super::{
    Context, DEFAULT_LIMIT, MAX_LIMIT, QUERY_TIMEOUT, RELOAD_TIMEOUT, json,
    proto::{Family, PeerAction, PeerBrief, PeerDetail, Request, RibReply, RouteJson, TraceJson},
};
use crate::{
    fib::{FibMsg, FibQuery},
    peer::status::{PeerCommand, PeerHandle, Timestamp},
    rib::{PeerRibStatus, Query, RibMsg, RibSummary, RouteInfo, RoutePage, SourceId},
};

pub(crate) async fn answer(ctx: &Context, request: Request) -> Result<serde_json::Value, String> {
    let peers = ctx.peers();
    match request {
        Request::Summary => {
            let rib = ask(ctx, Query::Summary).await?;
            let peers = peers
                .iter()
                .map(|h| {
                    let status = h.status.borrow().clone();
                    PeerBrief::new(&h.neighbor, &status, peer_rib(&rib, h.neighbor.id))
                })
                .collect();
            json(super::proto::Summary {
                version: env!("CARGO_PKG_VERSION"),
                asn: ctx.asn,
                router_id: ctx.router_id,
                started: ctx.started,
                now: Timestamp::now(),
                rib: rib.stats,
                announce: rib.own.iter().map(ToString::to_string).collect(),
                drained: rib.drained.map(Timestamp::from_instant),
                peers,
            })
        }
        Request::Peers { peer } => {
            let selected: Vec<&PeerHandle> = match &peer {
                None => peers.iter().collect(),
                Some(filter) => {
                    let selected: Vec<_> = peers
                        .iter()
                        .filter(|h| matches(filter, h.neighbor.id, h.neighbor.address))
                        .collect();
                    if selected.is_empty() {
                        return Err(format!("no neighbor matches {filter:?}"));
                    }
                    selected
                }
            };
            let rib = ask(ctx, Query::Summary).await?;
            let details: Vec<PeerDetail> = selected
                .into_iter()
                .map(|h| PeerDetail {
                    neighbor: h.neighbor.clone(),
                    status: h.status.borrow().clone(),
                    counters: h.counters.snapshot(),
                    rib: peer_rib(&rib, h.neighbor.id).copied(),
                })
                .collect();
            json(details)
        }
        Request::Test(test) => {
            let query = test.query()?;
            let trace = ask(ctx, |reply| Query::Test { query, reply }).await??;
            let name = |id: SourceId| {
                peers.iter().find(|h| h.neighbor.id == id).map_or_else(
                    || format!("peer {id}"),
                    |h| h.neighbor.address.ip().to_string(),
                )
            };
            json(TraceJson::new(&trace, name))
        }
        Request::Fib => json(ask_fib(ctx, FibQuery::Status).await?),
        Request::Reload => reload(ctx).await,
        Request::Restart { force, dry_run } => restart(ctx, force, dry_run).await,
        Request::Crash => {
            if std::env::var_os("ANSAGE_CRASH_TEST").is_none() {
                return Err("crash is only for tests (ANSAGE_CRASH_TEST)".into());
            }
            panic!("crash requested over the control socket (ANSAGE_CRASH_TEST)");
        }
        Request::Drain => drain(ctx, true).await,
        Request::Undrain => drain(ctx, false).await,
        Request::Announce { prefixes } => own(ctx, true, &prefixes).await,
        Request::Withdraw { prefixes } => own(ctx, false, &prefixes).await,
        Request::Peer {
            peer,
            action,
            reason,
        } => peer_action(ctx, &peer, action, reason).await,
        Request::Rib {
            prefix,
            family,
            limit,
            out,
        } => {
            let name = |id: SourceId| {
                peers.iter().find(|h| h.neighbor.id == id).map_or_else(
                    || format!("peer {id}"),
                    |h| h.neighbor.address.ip().to_string(),
                )
            };
            let to_json =
                |routes: Vec<RouteInfo>| routes.iter().map(|r| RouteJson::new(r, name)).collect();
            if let Some(filter) = out {
                if prefix.is_some() {
                    return Err("give either prefix or out".into());
                }
                let selected: Vec<&PeerHandle> = peers
                    .iter()
                    .filter(|h| matches(&filter, h.neighbor.id, h.neighbor.address))
                    .collect();
                let [handle] = selected[..] else {
                    return Err(format!("{filter:?} must match exactly one neighbor"));
                };
                let peer = handle.neighbor.id;
                let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
                let mut total = 0;
                let mut routes = Vec::new();
                for afi in families(family) {
                    let page: RoutePage = ask(ctx, |reply| Query::AdjOut {
                        peer,
                        afi,
                        limit,
                        reply,
                    })
                    .await?;
                    total += page.total;
                    routes.extend(page.routes);
                }
                return json(RibReply {
                    total: Some(total),
                    routes: to_json(routes),
                    kernel: None,
                    sent_to: Some(handle.neighbor.address.ip().to_string()),
                });
            }
            if let Some(prefix) = prefix {
                if family.is_some() || limit.is_some() {
                    return Err("give either prefix or family/limit".into());
                }
                let routes = match prefix.parse::<IpAddr>() {
                    Ok(addr) => ask(ctx, |reply| Query::Longest { addr, reply }).await?,
                    Err(_) => {
                        let prefix: Prefix = prefix
                            .parse()
                            .map_err(|err| format!("prefix {prefix:?}: {err}"))?;
                        ask(ctx, |reply| Query::Prefix { prefix, reply }).await?
                    }
                };
                let kernel = match routes.first() {
                    Some(route) if ctx.fib.is_some() => {
                        let prefix = route.prefix;
                        let status =
                            ask_fib(ctx, |reply| FibQuery::Prefix { prefix, reply }).await?;
                        Some(match status {
                            Some(status) => json(status)?,
                            None => serde_json::json!({"state": "absent"}),
                        })
                    }
                    _ => None,
                };
                return json(RibReply {
                    total: None,
                    routes: to_json(routes),
                    kernel,
                    sent_to: None,
                });
            }
            let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
            let mut total = 0;
            let mut routes = Vec::new();
            for afi in families(family) {
                let page: RoutePage = ask(ctx, |reply| Query::Routes { afi, limit, reply }).await?;
                total += page.total;
                routes.extend(page.routes);
            }
            json(RibReply {
                total: Some(total),
                routes: to_json(routes),
                kernel: None,
                sent_to: None,
            })
        }
    }
}

fn families(family: Option<Family>) -> Vec<Afi> {
    match family {
        Some(Family::Ipv4) => vec![Afi::IPV4],
        Some(Family::Ipv6) => vec![Afi::IPV6],
        None => vec![Afi::IPV4, Afi::IPV6],
    }
}

/// Parses prefixes strictly (host bits are an error, as in the config).
fn parse_prefixes(prefixes: &[String]) -> Result<Vec<Prefix>, String> {
    if prefixes.is_empty() {
        return Err("no prefixes given".into());
    }
    prefixes
        .iter()
        .map(|s| s.parse().map_err(|err| format!("prefix {s:?}: {err}")))
        .collect()
}

pub(super) async fn reload(ctx: &Context) -> Result<serde_json::Value, String> {
    let reload = ctx.reload.as_ref().ok_or("reload is not available")?;
    let (tx, rx) = oneshot::channel();
    reload
        .send(tx)
        .await
        .map_err(|_| "ansage is shutting down".to_string())?;
    tokio::time::timeout(RELOAD_TIMEOUT, rx)
        .await
        .map_err(|_| format!("no reload result within {} s", RELOAD_TIMEOUT.as_secs()))?
        .map_err(|_| "the reload was aborted".to_string())?
}

/// What `ansage restart` / `ansage upgrade` does per neighbor, and whether
/// it is refused; without `dry_run` and not refused, ansage exits after the
/// reply.
pub(super) async fn restart(
    ctx: &Context,
    force: bool,
    dry_run: bool,
) -> Result<serde_json::Value, String> {
    let restart = ctx.restart.as_ref().ok_or("restart is not available")?;
    // systemd (RestartForceExitStatus=75), or another supervisor that says
    // it starts ansage again after exit 75.
    let supervised = std::env::var_os("NOTIFY_SOCKET").is_some()
        || std::env::var_os("ANSAGE_SUPERVISED").is_some_and(|v| v == "1");
    let mut neighbors = Vec::new();
    let mut dropping = Vec::new();
    let mut restart_time: Option<u16> = None;
    for h in ctx.peers() {
        let address = h.neighbor.address.to_string();
        let status = h.status.borrow();
        let established = status.state == ansage_bgp::session::State::Established;
        let gr = status
            .session
            .as_ref()
            .and_then(|s| s.graceful_restart.as_ref());
        // The peer keeps our routes for the time we advertised.
        let action = match (established, gr) {
            (false, _) => "down",
            (true, Some(gr)) if gr.notification => "keep",
            (true, Some(_)) => "keep (no NOTIFICATION)",
            (true, None) => "drop",
        };
        if action.starts_with("keep")
            && let Some(time) = h.neighbor.graceful_restart
        {
            restart_time = Some(restart_time.map_or(time, |t| t.min(time)));
        }
        if action == "drop" {
            dropping.push(address.clone());
        }
        let peer_offers = status
            .session
            .as_ref()
            .is_some_and(|s| s.peer_graceful_restart.is_some());
        neighbors.push(serde_json::json!({
            "address": address,
            "action": action,
            "peer_offers": peer_offers,
        }));
    }
    let mut refused = Vec::new();
    if !dropping.is_empty() {
        refused.push(format!(
            "these neighbors have no graceful restart and would withdraw our routes: {}",
            dropping.join(", ")
        ));
    }
    if !supervised {
        refused.push("ansage does not run under systemd (no NOTIFY_SOCKET, no ANSAGE_SUPERVISED=1): nothing would start it again".into());
    }
    let report = serde_json::json!({
        "started": ctx.started,
        "config": ctx.config_path,
        "supervised": supervised,
        "restart_time": restart_time,
        "neighbors": neighbors,
        "refused": refused,
    });
    if dry_run {
        return Ok(report);
    }
    if !force && !refused.is_empty() {
        return Err(format!(
            "restart refused: {} (--force to restart anyway)",
            refused.join("; ")
        ));
    }
    let (tx, rx) = oneshot::channel();
    restart
        .send(tx)
        .await
        .map_err(|_| "ansage is shutting down".to_string())?;
    rx.await
        .map_err(|_| "ansage is already shutting down".to_string())?;
    Ok(report)
}

pub(super) async fn own(
    ctx: &Context,
    announce: bool,
    prefixes: &[String],
) -> Result<serde_json::Value, String> {
    let prefixes = parse_prefixes(prefixes)?;
    let change = ask_rib(ctx, |reply| RibMsg::Own {
        announce,
        prefixes,
        reply,
    })
    .await?;
    let rib = ask(ctx, Query::Summary).await?;
    let text = |p: Vec<Prefix>| p.iter().map(ToString::to_string).collect();
    json(super::proto::OwnReply {
        changed: text(change.changed),
        unchanged: text(change.unchanged),
        announce: text(rib.own),
    })
}

pub(super) async fn drain(ctx: &Context, drained: bool) -> Result<serde_json::Value, String> {
    let change = ask_rib(ctx, |reply| RibMsg::Drain { drained, reply }).await?;
    json(super::proto::DrainReply {
        changed: change.changed,
        drained: change.since.map(Timestamp::from_instant),
        now: Timestamp::now(),
    })
}

async fn peer_action(
    ctx: &Context,
    filter: &str,
    action: PeerAction,
    reason: Option<String>,
) -> Result<serde_json::Value, String> {
    let peers = ctx.peers();
    let selected: Vec<&PeerHandle> = peers
        .iter()
        .filter(|h| matches(filter, h.neighbor.id, h.neighbor.address))
        .collect();
    let handle = match selected[..] {
        [one] => one,
        [] => return Err(format!("no neighbor matches {filter:?}")),
        _ => {
            return Err(format!(
                "{filter:?} matches {} neighbors, give address:port or the ID",
                selected.len()
            ));
        }
    };
    if reason.is_some() && action != PeerAction::Disable {
        return Err("a reason only goes with disable".into());
    }
    let command = match action {
        PeerAction::Disable => PeerCommand::Disable {
            reason: reason.unwrap_or_else(|| "disabled by the operator".into()),
        },
        PeerAction::Enable => PeerCommand::Enable,
        PeerAction::Reset => PeerCommand::Reset,
    };
    tokio::time::timeout(QUERY_TIMEOUT, handle.commands.send(command))
        .await
        .map_err(|_| "the peer task did not take the command".to_string())?
        .map_err(|_| "the peer task is not running".to_string())?;
    json(super::proto::PeerActionReply {
        id: handle.neighbor.id,
        address: handle.neighbor.address,
        action,
    })
}

fn peer_rib(rib: &RibSummary, id: SourceId) -> Option<&PeerRibStatus> {
    rib.peers.iter().find(|p| p.peer == id)
}

/// Whether `filter` names the neighbor: its ID, address or address:port.
pub(super) fn matches(filter: &str, id: SourceId, address: SocketAddr) -> bool {
    if let Ok(n) = filter.parse::<SourceId>() {
        return n == id;
    }
    if let Ok(ip) = filter.parse::<IpAddr>() {
        return ip == address.ip();
    }
    filter.parse::<SocketAddr>() == Ok(address)
}

/// Sends a query to the RIB and waits for the answer.
pub(crate) async fn ask<T>(
    ctx: &Context,
    query: impl FnOnce(oneshot::Sender<T>) -> Query,
) -> Result<T, String> {
    ask_rib(ctx, |reply| RibMsg::Query(query(reply))).await
}

/// Asks the FIB thread; an error without `[kernel]`.
pub(crate) async fn ask_fib<T>(
    ctx: &Context,
    query: impl FnOnce(oneshot::Sender<T>) -> FibQuery,
) -> Result<T, String> {
    let fib = ctx
        .fib
        .as_ref()
        .ok_or("no [kernel] in the config: ansage installs no routes")?;
    let gone = || "the FIB is not running".to_string();
    let (tx, rx) = oneshot::channel();
    fib.send(FibMsg::Query(query(tx))).map_err(|_| gone())?;
    // A large batch can keep the FIB busy for a moment.
    tokio::time::timeout(QUERY_TIMEOUT, rx)
        .await
        .map_err(|_| {
            format!(
                "the FIB did not answer within {} s",
                QUERY_TIMEOUT.as_secs()
            )
        })?
        .map_err(|_| gone())
}

/// Sends a message with a reply channel to the RIB and waits for the answer.
async fn ask_rib<T>(
    ctx: &Context,
    msg: impl FnOnce(oneshot::Sender<T>) -> RibMsg,
) -> Result<T, String> {
    let gone = || "the RIB is not running".to_string();
    let (tx, rx) = oneshot::channel();
    let exchange = async {
        // Hold the strong sender only while sending, never while waiting.
        let rib = ctx.rib.upgrade().ok_or_else(gone)?;
        rib.send(msg(tx)).await.map_err(|_| gone())?;
        drop(rib);
        rx.await.map_err(|_| gone())
    };
    tokio::time::timeout(QUERY_TIMEOUT, exchange)
        .await
        .map_err(|_| {
            format!(
                "the RIB did not answer within {} s",
                QUERY_TIMEOUT.as_secs()
            )
        })?
}
