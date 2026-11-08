//! The running daemon: starts the RIB, one task per neighbor, the listener
//! and the control socket, and applies config reloads (SIGHUP or
//! `ansage reload`).
//!
//! A reload is all or nothing at the planning stage: an invalid file or a
//! change that needs a restart (asn, router_id, listen, control_socket)
//! leaves everything as it is. Otherwise, per neighbor (by address:port):
//! removed ones get Cease / Peer De-configured, changed ones Cease / Other
//! Configuration Change and reconnect with the new settings, a changed
//! description only updates what `show` prints. Own prefixes follow the
//! difference between the old and the new file, so prefixes withdrawn or
//! announced at runtime (a health check) stay as they are unless the file
//! changed them too. A disabled neighbor stays disabled, a drained ansage
//! stays drained.
//!
//! On SIGTERM/SIGINT with `drain_time`, ansage first drains (RFC 8326) and
//! waits, so traffic moves elsewhere before the sessions close.
//!
//! With `[kernel]`, the FIB thread installs routes; a stop removes them, a
//! restart (`ansage upgrade`) leaves them for the next start.

mod peer;
mod plan;
mod reload;
mod stop;
mod systemd;

pub use plan::{Plan, plan};

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::config::Config;
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tracing::{Instrument, error, info, info_span};

use crate::{
    control::{self, ReloadRequest, RestartRequest},
    fib::{self, FibHandle},
    http,
    peer::{
        listen,
        status::{PeerHandle, Timestamp},
    },
    rib::{self, Rib, RibConfig, RibMsg, SourceId},
};
use peer::Peer;
use reload::reload_logged;
use systemd::{ready, sd_notify};

/// Messages from peers waiting for the RIB.
const RIB_QUEUE: usize = 1024;
/// A stopping peer task flushes its last NOTIFICATION within 2 s (+1 s
/// safety in the task); give it a little more before aborting it.
const PEER_STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// Exit status after `ansage restart` (EX_TEMPFAIL): the systemd unit's
/// RestartForceExitStatus starts ansage again.
pub const RESTART_EXIT_CODE: u8 = 75;

/// How the daemon ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// SIGTERM or SIGINT: sessions ended with a Cease (Hard Reset with the
    /// N bit), neighbors dropped our routes.
    Stopped,
    /// `ansage restart`: sessions ended so that neighbors with Graceful
    /// Restart keep our routes until we are back.
    Restart,
}

pub struct Daemon {
    path: PathBuf,
    config: Config,
    /// In config order.
    peers: Vec<Peer>,
    next_id: SourceId,
    rib: mpsc::Sender<RibMsg>,
    fib: Option<FibHandle>,
    listeners: Vec<Arc<TcpListener>>,
    listen_neighbors: listen::Neighbors,
    /// What the control socket shows.
    handles: Arc<RwLock<Vec<PeerHandle>>>,
}

/// Runs ansage with the config at `path` until SIGTERM, SIGINT or
/// `ansage restart`.
pub async fn run(path: &Path) -> Result<Exit, String> {
    crate::peer::crash::install();
    let started = Timestamp::now();
    let config = Config::load(path).map_err(|err| err.to_string())?;

    let (rib_tx, rib_rx) = mpsc::channel(RIB_QUEUE);
    // Before any session: missing rights end the start here.
    let fib = match &config.kernel {
        Some(kernel) => Some(fib::start(kernel.into(), rib_tx.downgrade())?),
        None => None,
    };
    let mut table = Rib::new(RibConfig::new(&config));
    if let Some(fib) = &fib {
        table.attach_fib(fib.sender());
    }
    let rib = tokio::spawn(rib::run(table, rib_rx).instrument(info_span!("rib")));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Without its listener a passive neighbor never comes up: that is fatal,
    // and checked before any session starts.
    let listeners = listen::bind(&config.listen).map_err(|err| err.to_string())?;
    for addr in &config.listen {
        info!(%addr, "listening");
    }
    let mut daemon = Daemon {
        path: path.to_owned(),
        config,
        peers: Vec::new(),
        next_id: 0,
        rib: rib_tx,
        fib,
        listeners,
        listen_neighbors: listen::neighbors(Vec::new()),
        handles: Arc::default(),
    };
    for neighbor in daemon.config.neighbors.clone() {
        daemon.next_id += 1;
        let peer = daemon.spawn(daemon.next_id, &neighbor, false)?;
        daemon.peers.push(peer);
    }
    daemon.publish_handles();
    let listener = (!daemon.listeners.is_empty()).then(|| {
        let task = listen::run(
            daemon.listeners.clone(),
            daemon.listen_neighbors.clone(),
            shutdown_rx.clone(),
        );
        tokio::spawn(task.instrument(info_span!("listen")))
    });

    let (reload_tx, mut reload_rx) = mpsc::channel::<ReloadRequest>(1);
    let (restart_tx, mut restart_rx) = mpsc::channel::<RestartRequest>(1);
    let ctx = Arc::new(control::Context {
        asn: daemon.config.asn,
        router_id: daemon.config.router_id,
        started,
        peers: daemon.handles.clone(),
        // Weak: the RIB must still stop once the daemon is gone.
        rib: daemon.rib.downgrade(),
        fib: daemon.fib.as_ref().map(FibHandle::sender),
        reload: Some(reload_tx),
        restart: Some(restart_tx),
        config_path: Some(path.to_owned()),
    });
    let control = start_control(&daemon.config.control_socket, ctx.clone(), &shutdown_rx);
    let metrics = match daemon.config.metrics_listen {
        Some(addr) => start_metrics(addr, ctx, &shutdown_rx).await,
        None => None,
    };
    info!(
        asn = daemon.config.asn,
        router_id = %daemon.config.router_id,
        neighbors = daemon.config.neighbors.len(),
        announce = daemon.config.announce.len(),
        "ansage started"
    );
    ready(&daemon.config);

    let mut terminate = signal(SignalKind::terminate()).map_err(|err| err.to_string())?;
    let mut hangup = signal(SignalKind::hangup()).map_err(|err| err.to_string())?;
    let exit = loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(err) = result {
                    error!(%err, "cannot listen for SIGINT");
                }
                break Exit::Stopped;
            }
            _ = terminate.recv() => break Exit::Stopped,
            Some(reply) = restart_rx.recv() => {
                let _ = reply.send(());
                break Exit::Restart;
            }
            _ = hangup.recv() => {
                info!("SIGHUP: reloading the config");
                let _ = reload_logged(&mut daemon).await;
            }
            Some(reply) = reload_rx.recv() => {
                info!("reload requested over the control socket");
                let result = reload_logged(&mut daemon).await;
                let _ = reply.send(result.map(|plan| {
                    serde_json::to_value(plan).expect("a plan serializes")
                }));
            }
        }
    };

    match exit {
        Exit::Stopped => info!("shutting down"),
        Exit::Restart => info!("restarting: ending sessions so neighbors keep our routes"),
    }
    sd_notify("STOPPING=1");
    if exit == Exit::Stopped {
        daemon.drain_before_stop(&mut terminate).await;
    }
    // A restart keeps the kernel routes for the next start to adopt: the
    // FIB stops before the sessions end and their routes leave the RIB.
    let mut fib = daemon.fib.take();
    if exit == Exit::Restart
        && let Some(fib) = fib.take()
    {
        fib.stop(false).await;
    }
    daemon.stop_all(exit).await;
    let _ = shutdown_tx.send(true);
    if let Some(listener) = listener {
        let _ = listener.await;
    }
    if let Some(control) = control {
        let _ = control.await;
    }
    if let Some(metrics) = metrics {
        let _ = metrics.await;
    }
    // The RIB stops once the last sender is gone.
    drop(daemon);
    let _ = rib.await;
    if let Some(fib) = fib {
        fib.stop(true).await;
    }
    Ok(exit)
}

/// Opens the control socket unless it is turned off. Failing to open it is
/// logged and ansage runs without it: routing matters more than queries.
fn start_control(
    path: &Path,
    ctx: Arc<control::Context>,
    shutdown: &watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    let path = path.to_owned();
    if path.as_os_str().is_empty() {
        return None;
    }
    let listener = match control::bind(&path) {
        Ok(listener) => listener,
        Err(err) => {
            error!(%err, path = %path.display(), "cannot open the control socket, running without it");
            return None;
        }
    };
    info!(path = %path.display(), "control socket ready");
    let task = control::run(listener, path, ctx, shutdown.clone());
    Some(tokio::spawn(task.instrument(info_span!("control"))))
}

/// Serves metrics unless the address cannot be bound: logged, and ansage
/// runs without them, like without the control socket.
async fn start_metrics(
    addr: SocketAddr,
    ctx: Arc<control::Context>,
    shutdown: &watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    match http::bind(addr).await {
        Ok(listener) => {
            info!(%addr, "metrics at http://{addr}/metrics");
            let task = http::run(listener, ctx, shutdown.clone());
            Some(tokio::spawn(task.instrument(info_span!("metrics"))))
        }
        Err(err) => {
            error!(%err, %addr, "cannot serve metrics, running without them");
            None
        }
    }
}
