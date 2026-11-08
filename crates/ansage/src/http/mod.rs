//! Prometheus metrics over plain HTTP (`metrics_listen`), from the same
//! sources as the control socket: the peer handles, a RIB summary and
//! /proc/self.
//!
//! A deliberately small HTTP/1.1 responder: `GET /metrics` (any query
//! string) gets the text exposition format, `GET /api/summary`, `/api/peers`
//! (`?peer=`), `/api/rib` (`?prefix=` or `?family=&limit=`) and `/api/fib`
//! the control socket's JSON (read-only, for a dashboard), `GET /` a
//! pointer, anything else 404 or 405. One request per connection, then close.

mod api;
mod events;
mod prometheus;

pub use prometheus::render;

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
};
use tracing::{debug, warn};

use crate::control::{self, Context};
use api::{ApiError, api_request};
use events::events;

/// Scrapes served at the same time; more are refused.
const MAX_CONNECTIONS: usize = 8;
/// Open `/api/events` streams; they do not count against MAX_CONNECTIONS.
const MAX_STREAMS: usize = 4;
/// How often a stream looks for changed neighbors.
const EVENT_POLL: Duration = Duration::from_millis(250);
/// A stream sends the summary (prefix counts, RIB) this often.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(5);
/// The whole request (line and headers) must arrive within this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest request head we read.
const MAX_REQUEST: usize = 8192;

pub async fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

/// Serves scrapes until `shutdown` flips to true.
pub async fn run(listener: TcpListener, ctx: Arc<Context>, mut shutdown: watch::Receiver<bool>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let streams = Arc::new(Semaphore::new(MAX_STREAMS));
    loop {
        let stream = tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(err) => {
                    warn!(%err, "metrics accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            debug!("too many metrics clients, closing one");
            continue;
        };
        let (ctx, streams, shutdown) = (ctx.clone(), streams.clone(), shutdown.clone());
        tokio::spawn(async move {
            if let Err(err) = serve(stream, &ctx, slot, &streams, shutdown).await {
                debug!(%err, "metrics request failed");
            }
        });
    }
}

async fn serve(
    mut stream: TcpStream,
    ctx: &Context,
    slot: OwnedSemaphorePermit,
    streams: &Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let head = match tokio::time::timeout(REQUEST_TIMEOUT, read_head(&mut stream)).await {
        Ok(head) => head?,
        Err(_) => return Ok(()),
    };
    let line = head.lines().next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = target.split('?').next().unwrap_or("");
    let (status, content_type, body) = if method == "GET" && path == "/api/events" {
        match streams.clone().try_acquire_owned() {
            Ok(stream_slot) => {
                drop(slot);
                let result = events(&mut stream, ctx, shutdown).await;
                drop(stream_slot);
                return result;
            }
            Err(_) => (
                "503 Service Unavailable",
                JSON,
                error_json("too many event streams"),
            ),
        }
    } else {
        route(ctx, method, target).await
    };
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if method != "HEAD" {
        response.push_str(&body);
    }
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// Status line, content type and body for one request.
pub(crate) async fn route(
    ctx: &Context,
    method: &str,
    target: &str,
) -> (&'static str, &'static str, String) {
    if method != "GET" && method != "HEAD" {
        return ("405 Method Not Allowed", "text/plain", "only GET\n".into());
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match path {
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render(ctx).await,
        ),
        "/" => (
            "200 OK",
            "text/plain; charset=utf-8",
            "ansage: metrics at /metrics; JSON at /api/summary, /api/peers, /api/rib, /api/fib, /api/events (SSE)\n"
                .to_string(),
        ),
        _ => match path
            .strip_prefix("/api/")
            .map(|name| api_request(name, query))
        {
            Some(Ok(request)) => match control::answer(ctx, request).await {
                Ok(value) => ("200 OK", JSON, json_line(&value)),
                Err(err) => ("400 Bad Request", JSON, error_json(&err)),
            },
            Some(Err(ApiError::Bad(err))) => ("400 Bad Request", JSON, error_json(&err)),
            Some(Err(ApiError::NotFound)) | None => {
                ("404 Not Found", "text/plain", "not found\n".into())
            }
        },
    }
}

const JSON: &str = "application/json";

fn json_line(value: &serde_json::Value) -> String {
    let mut body = value.to_string();
    body.push('\n');
    body
}

fn error_json(err: &str) -> String {
    json_line(&serde_json::json!({ "error": err }))
}

/// Reads until the blank line that ends the request head.
async fn read_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && !buf.windows(2).any(|w| w == b"\n\n") {
        if buf.len() > MAX_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too long",
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests;
