//! Stopping: the drain before a stop (`drain_time`) and ending every
//! session.

use std::time::{Duration, Instant};

use ansage_bgp::session::State;

use ansage_bgp::wire::Notification;
use tokio::sync::oneshot;
use tracing::info;

use super::{Daemon, Exit, PEER_STOP_TIMEOUT, systemd::sd_notify};
use crate::{
    peer::{SHUTDOWN_TEXT, StopRequest},
    rib::RibMsg,
};

impl Daemon {
    /// Before a stop with `drain_time`: drains and waits until the drain
    /// is `drain_time` old (an earlier `ansage drain` counts), or until a
    /// second SIGTERM/SIGINT. Skipped when no session is up.
    pub(super) async fn drain_before_stop(&self, terminate: &mut tokio::signal::unix::Signal) {
        let drain_time = Duration::from_secs(self.config.drain_time);
        if drain_time.is_zero() {
            return;
        }
        let up = self
            .peers
            .iter()
            .any(|p| p.handle.status.borrow().state == State::Established);
        if !up {
            info!("no session is up: stopping without a drain");
            return;
        }
        let (reply, rx) = oneshot::channel();
        let drained = RibMsg::Drain {
            drained: true,
            reply,
        };
        if self.rib.send(drained).await.is_err() {
            return;
        }
        let Ok(change) = rx.await else {
            return;
        };
        let since = change.since.unwrap_or_else(Instant::now);
        let wait = drain_time.saturating_sub(since.elapsed());
        if wait.is_zero() {
            return;
        }
        info!(
            seconds = wait.as_secs(),
            "draining before the stop (SIGTERM or SIGINT again stops at once)"
        );
        // systemd's stop timeout counts from STOPPING=1; extend it by the
        // wait plus the time the sessions need to close.
        let extend = wait + PEER_STOP_TIMEOUT + Duration::from_secs(5);
        sd_notify(&format!(
            "EXTEND_TIMEOUT_USEC={}\nSTATUS=draining for {} s before the stop",
            extend.as_micros(),
            wait.as_secs()
        ));
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = tokio::signal::ctrl_c() => info!("SIGINT: ending the drain early"),
            _ = terminate.recv() => info!("SIGTERM: ending the drain early"),
        }
    }

    /// Stops every peer task: with Cease / Administrative Shutdown, or for
    /// a graceful restart.
    pub(super) async fn stop_all(&mut self, exit: Exit) {
        let peers = std::mem::take(&mut self.peers);
        for peer in &peers {
            peer.request_stop(match exit {
                Exit::Stopped => StopRequest::Cease(Notification::admin_shutdown(SHUTDOWN_TEXT)),
                Exit::Restart => StopRequest::Restart,
            });
        }
        for peer in peers {
            peer.join().await;
        }
    }
}
