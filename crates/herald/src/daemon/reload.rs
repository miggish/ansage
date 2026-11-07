//! Config reload (SIGHUP or `herald reload`): applies the [`Plan`] between
//! the running and the new config.

use std::{net::SocketAddr, time::Duration};

use crate::config::Config;
use bytes::Bytes;
use herald_bgp::wire::{Notification, Prefix, cease_subcode, error_code};
use tokio::sync::oneshot;
use tracing::{error, info};

use super::{
    Daemon, Plan,
    peer::Peer,
    plan,
    systemd::{self, ready, sd_notify},
};
use crate::{
    peer::{StopRequest, status::NeighborInfo},
    rib::{PeerSettings, RibMsg, SourceId},
};

impl Daemon {
    /// Re-reads the config file and applies what changed.
    pub async fn reload(&mut self) -> Result<Plan, String> {
        let new = Config::load(&self.path).map_err(|err| err.to_string())?;
        let plan = plan(&self.config, &new)?;
        if plan.is_empty() {
            self.config = new;
            return Ok(plan);
        }
        let added_count = u32::try_from(plan.added.len()).unwrap_or(u32::MAX);
        if u32::from(self.next_id) + added_count >= u32::from(SourceId::MAX) {
            return Err("too many neighbors added since start: restart herald".into());
        }

        // Stop removed and changed neighbors, all at once.
        let cease = |subcode| Notification::new(error_code::CEASE, subcode, Bytes::new());
        let mut stopping = Vec::new();
        let mut remaining = Vec::new();
        for peer in std::mem::take(&mut self.peers) {
            let key = peer.neighbor.socket_addr();
            if plan.removed.contains(&key) {
                peer.request_stop(StopRequest::Cease(cease(cease_subcode::PEER_DECONFIGURED)));
                stopping.push((peer, None));
            } else if plan.restarted.contains(&key) {
                peer.request_stop(StopRequest::Cease(cease(
                    cease_subcode::OTHER_CONFIGURATION_CHANGE,
                )));
                let disabled = peer.handle.status.borrow().disabled;
                stopping.push((peer, Some(disabled)));
            } else {
                remaining.push(peer);
            }
        }
        let mut restart = Vec::new();
        for (peer, restart_disabled) in stopping {
            let (id, address) = (peer.id, peer.neighbor.socket_addr());
            self.forget(&peer).await;
            peer.join().await;
            if let Some(disabled) = restart_disabled {
                restart.push((address, id, disabled));
            }
        }

        self.config = new;
        let mut by_key: Vec<(SocketAddr, Peer)> = remaining
            .into_iter()
            .map(|p| (p.neighbor.socket_addr(), p))
            .collect();
        let mut peers = Vec::new();
        let mut failed = Vec::new();
        for neighbor in self.config.neighbors.clone() {
            let key = neighbor.socket_addr();
            if let Some(i) = by_key.iter().position(|(k, _)| *k == key) {
                let (_, mut peer) = by_key.swap_remove(i);
                if plan.updated.contains(&key) {
                    peer.handle.neighbor = NeighborInfo::new(&self.config, peer.id, &neighbor);
                    let _ = self
                        .rib
                        .send(RibMsg::PeerSettings {
                            peer: peer.id,
                            settings: Some(PeerSettings::new(&self.config, &neighbor)),
                        })
                        .await;
                    peer.neighbor = neighbor;
                }
                peers.push(peer);
                continue;
            }
            let (id, disabled) = match restart.iter().find(|(k, _, _)| *k == key) {
                Some(&(_, id, disabled)) => (id, disabled),
                None => {
                    self.next_id += 1;
                    (self.next_id, false)
                }
            };
            let _ = self
                .rib
                .send(RibMsg::PeerSettings {
                    peer: id,
                    settings: Some(PeerSettings::new(&self.config, &neighbor)),
                })
                .await;
            match self.spawn(id, &neighbor, disabled) {
                Ok(peer) => peers.push(peer),
                Err(err) => failed.push(format!("{key}: {err}")),
            }
        }
        self.peers = peers;
        self.publish_handles();

        if let Some(kernel) = &plan.kernel {
            if let Some(fib) = &self.fib {
                fib.set_settings(kernel.into());
            }
            let families = RibMsg::InstallFamilies(kernel.install_families());
            let _ = self.rib.send(families).await;
        }
        if let Some(secs) = plan.max_prefix_restart {
            let restart = Duration::from_secs(secs);
            let _ = self.rib.send(RibMsg::MaxPrefixRestart(restart)).await;
        }
        for (announce, prefixes) in [(true, &plan.announce), (false, &plan.withdraw)] {
            if prefixes.is_empty() {
                continue;
            }
            let (reply, rx) = oneshot::channel();
            let msg = RibMsg::Own {
                announce,
                prefixes: prefixes.clone(),
                reply,
            };
            if self.rib.send(msg).await.is_err() || rx.await.is_err() {
                failed.push("own prefixes: the RIB is not running".into());
            }
        }
        if failed.is_empty() {
            Ok(plan)
        } else {
            Err(format!(
                "reload partly applied, failed: {}",
                failed.join("; ")
            ))
        }
    }
}

fn strings(prefixes: &[Prefix]) -> Vec<String> {
    prefixes.iter().map(ToString::to_string).collect()
}

pub(super) async fn reload_logged(daemon: &mut Daemon) -> Result<Plan, String> {
    sd_notify(&systemd::reloading());
    let result = daemon.reload().await;
    ready(&daemon.config);
    match &result {
        Ok(plan) if plan.is_empty() => info!("config reloaded: nothing changed"),
        Ok(plan) => info!(
            added = ?plan.added,
            removed = ?plan.removed,
            restarted = ?plan.restarted,
            updated = ?plan.updated,
            announce = ?strings(&plan.announce),
            withdraw = ?strings(&plan.withdraw),
            "config reloaded"
        ),
        Err(err) => error!("config reload failed, nothing changed: {err}"),
    }
    result
}
