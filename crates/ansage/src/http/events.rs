//! Live updates for a dashboard: `/api/events` as Server-Sent Events.

use std::io;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

use super::{EVENT_POLL, SUMMARY_INTERVAL};
use crate::{
    control::{self, Context, proto::Request},
    peer::status::PeerHandle,
};

/// `GET /api/events`: Server-Sent Events, until the client goes or ansage
/// stops. `summary` (the `/api/summary` JSON) first, every
/// [`SUMMARY_INTERVAL`] and when the neighbors change (reload); `peer`
/// (that neighbor's `/api/peers` entry) when its state, timers or last
/// error change. `error` when an answer fails.
pub(super) async fn events(
    stream: &mut TcpStream,
    ctx: &Context,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut peers: Vec<PeerHandle> = Vec::new();
    let mut last_summary: Option<tokio::time::Instant> = None;
    let mut tick = tokio::time::interval(EVENT_POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut buf = [0u8; 256];
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            // The client closed (or sent something we do not want).
            read = stream.read(&mut buf) => match read {
                Ok(0) | Err(_) => return Ok(()),
                Ok(_) => continue,
            },
            _ = tick.tick() => {}
        }
        let current = ctx.peers();
        let ids = |p: &[PeerHandle]| p.iter().map(|h| h.neighbor.id).collect::<Vec<_>>();
        let reloaded = ids(&current) != ids(&peers);
        if reloaded {
            peers = current;
            for p in &mut peers {
                p.status.mark_unchanged();
            }
        }
        if reloaded || last_summary.is_none_or(|t| t.elapsed() >= SUMMARY_INTERVAL) {
            last_summary = Some(tokio::time::Instant::now());
            send_event(
                stream,
                "summary",
                control::answer(ctx, Request::Summary).await,
            )
            .await?;
        }
        for p in &mut peers {
            if !p.status.has_changed().unwrap_or(false) {
                continue;
            }
            p.status.mark_unchanged();
            let request = Request::Peers {
                peer: Some(p.neighbor.id.to_string()),
            };
            let detail = control::answer(ctx, request)
                .await
                .map(|v| v.get(0).cloned().unwrap_or_default());
            send_event(stream, "peer", detail).await?;
        }
    }
}

async fn send_event(
    stream: &mut TcpStream,
    name: &str,
    data: Result<serde_json::Value, String>,
) -> io::Result<()> {
    let (name, data) = match data {
        Ok(value) => (name, value),
        Err(err) => ("error", serde_json::json!({ "error": err, "event": name })),
    };
    // serde_json writes one line, as an SSE data field needs.
    let event = format!("event: {name}\ndata: {data}\n\n");
    stream.write_all(event.as_bytes()).await
}
