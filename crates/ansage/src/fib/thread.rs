//! The FIB thread: started by the daemon, fed by the RIB and kernel events.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    thread::JoinHandle,
    time::Instant,
};

use ansage_netlink::AF_INET;

use ansage_netlink::Nexthop;

use ansage_netlink::RTPROT_BGP;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, info_span};

use super::{
    DEBOUNCE, Fib, FibMsg, PROBE_ID, SWEEP_INTERVAL, Settings,
    kernel::{Kernel, Netlink, Op, OpError},
};
use crate::rib::{RibMsg, STALE_PATH_TIME};

/// Checks that ansage may and can install routes: creates and deletes a
/// blackhole nexthop object. The error says what to change.
pub fn probe<K: Kernel>(kernel: &mut K) -> Result<(), String> {
    let nh = Nexthop {
        id: PROBE_ID,
        family: AF_INET,
        protocol: RTPROT_BGP,
        flags: 0,
        oif: None,
        gateway: None,
        blackhole: true,
        group: Vec::new(),
    };
    let results = kernel.apply(&[Op::AddNexthop(nh), Op::DeleteNexthop(PROBE_ID)]);
    match results.into_iter().next() {
        Some(Ok(())) | None => Ok(()),
        Some(Err(OpError::Kernel(err))) if err.errno == libc::EPERM => Err(format!(
            "[kernel]: not allowed to change routes ({err}); ansage needs CAP_NET_ADMIN \
             (systemd: AmbientCapabilities=CAP_NET_ADMIN, see dist/ansage.service)"
        )),
        Some(Err(OpError::Kernel(err)))
            if err.errno == libc::EOPNOTSUPP || err.errno == libc::EINVAL =>
        {
            Err(format!(
                "[kernel]: the kernel has no nexthop objects ({err}); ansage needs Linux 5.3 or newer"
            ))
        }
        Some(Err(err)) => Err(format!("[kernel]: cannot install routes: {err}")),
    }
}

/// Turns a failure to open the netlink socket into advice.
fn open_error(err: io::Error) -> String {
    match err.raw_os_error() {
        Some(libc::EAFNOSUPPORT | libc::EPERM | libc::EACCES) => format!(
            "[kernel]: cannot open a netlink socket ({err}); with systemd add AF_NETLINK to \
             RestrictAddressFamilies (see dist/ansage.service)"
        ),
        _ => format!("[kernel]: cannot open a netlink socket: {err}"),
    }
}

/// The running FIB thread.
pub struct FibHandle {
    tx: std_mpsc::Sender<FibMsg>,
    thread: JoinHandle<()>,
}

impl FibHandle {
    /// For the RIB.
    pub fn sender(&self) -> std_mpsc::Sender<FibMsg> {
        self.tx.clone()
    }

    pub fn set_settings(&self, settings: Settings) {
        let _ = self.tx.send(FibMsg::Settings(settings));
    }

    /// Ends the thread; `flush` removes ansage's routes from the kernel.
    pub async fn stop(self, flush: bool) {
        let (done, rx) = oneshot::channel();
        if self.tx.send(FibMsg::Stop { flush, done }).is_ok() {
            let _ = rx.await;
        }
        let _ = tokio::task::spawn_blocking(move || self.thread.join()).await;
    }
}

/// Opens the netlink socket, checks the rights and starts the thread. It
/// takes over what an earlier run left in the kernel (see [`Fib::adopt`]).
pub fn start(settings: Settings, rib: mpsc::WeakSender<RibMsg>) -> Result<FibHandle, String> {
    let mut kernel = Netlink::open().map_err(open_error)?;
    probe(&mut kernel)?;
    let (tx, rx) = std_mpsc::channel();
    // Set while a KernelChanged is queued, so a burst queues only one.
    let pending = Arc::new(AtomicBool::new(false));
    super::events::spawn(tx.clone(), pending.clone())
        .map_err(|err| format!("[kernel]: cannot watch the kernel for changes: {err}"))?;
    let thread = std::thread::Builder::new()
        .name("ansage-fib".into())
        .spawn(move || {
            let _span = info_span!("fib").entered();
            run(Fib::new(kernel, settings), rx, rib, &pending);
        })
        .map_err(|err| format!("[kernel]: cannot start the FIB thread: {err}"))?;
    Ok(FibHandle { tx, thread })
}

pub(super) fn run<K: Kernel>(
    mut fib: Fib<K>,
    rx: std_mpsc::Receiver<FibMsg>,
    rib: mpsc::WeakSender<RibMsg>,
    pending: &AtomicBool,
) {
    fib.load_local();
    let mut adopt_until = None;
    match fib.adopt() {
        Ok((0, _)) => {}
        Ok((nexthops, routes)) => {
            info!(
                nexthops,
                routes,
                "kept the kernel routes of an earlier run until the neighbors send them again"
            );
            adopt_until = Some(Instant::now() + STALE_PATH_TIME);
        }
        Err(err) => error!(%err, "cannot read what an earlier run left in the kernel"),
    }
    let end_adoption = |fib: &mut Fib<K>, why: &str| {
        let left = fib.end_adoption();
        info!(
            left,
            "{why}: kernel routes of the earlier run not sent again removed"
        );
    };
    let settings = fib.settings();
    info!(
        table = settings.table,
        metric = settings.metric,
        resolve_via_default = settings.resolve_via_default,
        "installing routes into the kernel"
    );
    let mut next_sweep: Option<Instant> = None;
    let mut resolve_at: Option<Instant> = None;
    loop {
        let wake = next_sweep
            .into_iter()
            .chain(resolve_at)
            .chain(adopt_until)
            .min();
        let msg = match wake {
            Some(at) => rx.recv_timeout(at.saturating_duration_since(Instant::now())),
            None => rx
                .recv()
                .map_err(|_| std_mpsc::RecvTimeoutError::Disconnected),
        };
        let mut ready = false;
        match msg {
            Ok(FibMsg::Routes(routes)) => {
                fib.update(&routes);
                ready = true;
            }
            Ok(FibMsg::Settings(settings)) => fib.set_settings(settings),
            Ok(FibMsg::Query(query)) => fib.answer(query),
            Ok(FibMsg::Synced) => {
                if adopt_until.take().is_some() {
                    end_adoption(&mut fib, "neighbors in sync");
                }
            }
            Ok(FibMsg::KernelChanged) => {
                pending.store(false, Ordering::Relaxed);
                resolve_at.get_or_insert_with(|| Instant::now() + DEBOUNCE);
            }
            Ok(FibMsg::Stop { flush, done }) => {
                if flush {
                    match fib.purge() {
                        Ok(n) => info!(nexthops = n, "kernel routes removed"),
                        Err(err) => error!(%err, "cannot remove kernel routes"),
                    }
                } else {
                    info!("kernel routes kept for the next start");
                }
                let _ = done.send(());
                return;
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if adopt_until.is_some_and(|at| at <= now) {
                    adopt_until = None;
                    end_adoption(&mut fib, "waited long enough");
                }
                if next_sweep.is_some_and(|at| at <= now) || resolve_at.is_some_and(|at| at <= now)
                {
                    next_sweep = None;
                    resolve_at = None;
                    fib.refresh();
                }
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
        }
        // Blocks only while the RIB's queue is full; the RIB never waits
        // for us, so this always ends. Reachability first: the RIB decides
        // again before it sends the next batch.
        let reports = fib.take_reports();
        if let Some(rib) = rib.upgrade() {
            if !reports.is_empty() {
                let _ = rib.blocking_send(RibMsg::NextHops(reports));
            }
            if ready {
                let _ = rib.blocking_send(RibMsg::FibReady);
            }
        }
        next_sweep = match next_sweep {
            _ if !fib.needs_sweep() => None,
            Some(at) => Some(at),
            None => Some(Instant::now() + SWEEP_INTERVAL),
        };
    }
}
