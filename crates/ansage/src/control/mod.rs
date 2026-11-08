//! Local control socket: questions about peers and the RIB, and operator
//! commands (own prefixes, disable / enable / reset a neighbor).
//!
//! A unix socket speaking the line protocol in [`proto`]. Peer state comes
//! from the [`PeerHandle`]s (no peer task is asked), RIB answers from
//! [`RibMsg::Query`]. The server holds only a weak sender to the RIB: the
//! RIB stops once the last peer task is gone, and a socket client must not
//! keep it alive.

mod answer;
pub mod proto;

pub(crate) use answer::{answer, ask, ask_fib};

use std::{
    fs::Permissions,
    io,
    net::Ipv4Addr,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
};
use tracing::{debug, warn};

use crate::{
    fib::FibMsg,
    peer::status::{PeerHandle, Timestamp},
    rib::RibMsg,
};
use proto::{Envelope, Reply};

/// Longest request line in bytes.
pub const MAX_LINE: usize = 4096;
/// Clients served at the same time; more are refused.
const MAX_CONNECTIONS: usize = 16;
/// A client that sends nothing for this long is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// The RIB may be busy with a full table; give up after this.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// A reload stops changed neighbors (each within a few seconds).
const RELOAD_TIMEOUT: Duration = Duration::from_secs(20);
/// Routes per family in a `rib` reply without `limit`, and the maximum.
const DEFAULT_LIMIT: usize = 1000;
const MAX_LIMIT: usize = 100_000;

/// What the server answers from.
pub struct Context {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub started: Timestamp,
    /// One per neighbor, in config order; replaced by a config reload.
    pub peers: Arc<RwLock<Vec<PeerHandle>>>,
    pub rib: mpsc::WeakSender<RibMsg>,
    /// The FIB thread, with `[kernel]`.
    pub fib: Option<std::sync::mpsc::Sender<FibMsg>>,
    /// Asks the daemon to reload its config; None: reload not available.
    pub reload: Option<mpsc::Sender<ReloadRequest>>,
    /// Asks the daemon to restart gracefully; None: not available.
    pub restart: Option<mpsc::Sender<RestartRequest>>,
    /// The config file the daemon runs with (for `ansage upgrade`).
    pub config_path: Option<std::path::PathBuf>,
}

/// A reload request: the reply is the report or why nothing changed.
pub type ReloadRequest = oneshot::Sender<Result<serde_json::Value, String>>;

/// A restart request, acknowledged before the sessions are ended.
pub type RestartRequest = oneshot::Sender<()>;

impl Context {
    /// The current neighbors (a snapshot).
    pub fn peers(&self) -> Vec<PeerHandle> {
        self.peers.read().expect("never poisoned").clone()
    }
}

/// Binds the socket at `path` with mode 0660. A stale socket left by a
/// crashed ansage is removed; a live one (another ansage answers) or a
/// file that is not a socket is an error.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another ansage is listening on it",
                ));
            }
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "exists and is not a socket",
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// Serves clients until `shutdown` flips to true, then removes the socket.
pub async fn run(
    listener: UnixListener,
    path: PathBuf,
    ctx: Arc<Context>,
    mut shutdown: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => match slots.clone().try_acquire_owned() {
                    Ok(slot) => {
                        clients.spawn(serve(stream, ctx.clone(), slot));
                    }
                    Err(_) => {
                        debug!("too many control clients, refusing one");
                        clients.spawn(refuse(stream));
                    }
                },
                Err(err) => {
                    // Usually out of file descriptors; don't spin.
                    warn!(%err, "control socket accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    clients.abort_all();
    drop(listener);
    if let Err(err) = std::fs::remove_file(&path) {
        warn!(%err, path = %path.display(), "cannot remove the control socket");
    }
}

async fn refuse(mut stream: UnixStream) {
    let line = encode(&Reply::Error("too many clients".into()));
    let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(line.as_bytes())).await;
}

async fn serve(stream: UnixStream, ctx: Arc<Context>, _slot: OwnedSemaphorePermit) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        let limited = (&mut reader).take(MAX_LINE as u64 + 1);
        let read = tokio::time::timeout(IDLE_TIMEOUT, read_line(limited, &mut line)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(_)) => {}
        }
        if line.last() != Some(&b'\n') && line.len() > MAX_LINE {
            let reply = encode(&Reply::Error(format!(
                "request longer than {MAX_LINE} bytes"
            )));
            let _ = writer.write_all(reply.as_bytes()).await;
            return;
        }
        let reply = handle(&ctx, &line).await;
        if writer.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

async fn read_line(
    mut reader: impl AsyncBufReadExt + Unpin,
    line: &mut Vec<u8>,
) -> io::Result<usize> {
    reader.read_until(b'\n', line).await
}

/// Answers one request line; the reply ends with a newline.
pub async fn handle(ctx: &Context, line: &[u8]) -> String {
    let reply = match serde_json::from_slice::<Envelope>(line) {
        Err(err) => Reply::Error(format!("bad request: {err}")),
        Ok(envelope) if envelope.v != proto::VERSION => Reply::Error(format!(
            "protocol version {} not supported (this ansage speaks {})",
            envelope.v,
            proto::VERSION
        )),
        Ok(envelope) => match answer(ctx, envelope.request).await {
            Ok(value) => Reply::Ok(value),
            Err(err) => Reply::Error(err),
        },
    };
    encode(&reply)
}

fn encode(reply: &Reply) -> String {
    let mut line = serde_json::to_string(reply).expect("replies always serialize");
    line.push('\n');
    line
}

fn json(value: impl Serialize) -> Result<serde_json::Value, String> {
    serde_json::to_value(value).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests;
