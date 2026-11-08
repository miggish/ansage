//! The daemon's side of a running neighbor: its peer task, its entry in the
//! listener and its handle for the control socket.

use crate::config::Neighbor;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tracing::{Instrument, info_span, warn};

use super::{Daemon, PEER_STOP_TIMEOUT};
use crate::{
    peer::{
        self, PeerConfig, StopRequest, listen,
        status::{self, NeighborInfo, PeerHandle},
    },
    rib::{RibMsg, SourceId},
};

/// One running neighbor.
pub(super) struct Peer {
    pub id: SourceId,
    pub neighbor: Neighbor,
    stop: watch::Sender<Option<StopRequest>>,
    task: JoinHandle<()>,
    pub handle: PeerHandle,
}

impl Peer {
    /// Asks the task to end.
    pub fn request_stop(&self, request: StopRequest) {
        let _ = self.stop.send(Some(request));
    }

    /// Waits for the task to end (after `request_stop`).
    pub async fn join(self) {
        let addr = self.neighbor.socket_addr();
        let abort = self.task.abort_handle();
        if tokio::time::timeout(PEER_STOP_TIMEOUT, self.task)
            .await
            .is_err()
        {
            warn!(%addr, "peer task did not stop in time, aborting it");
            abort.abort();
        }
    }
}

impl Daemon {
    pub(super) fn spawn(
        &self,
        id: SourceId,
        neighbor: &Neighbor,
        disabled: bool,
    ) -> Result<Peer, String> {
        let mut config = PeerConfig::new(&self.config, id, neighbor, self.rib.clone());
        config.start_disabled = disabled;
        let (reporter, handle) = status::peer_channel(
            NeighborInfo::new(&self.config, id, neighbor),
            config.session.connect_retry,
        );
        let incoming = if self.config.listen.is_empty() {
            None
        } else {
            let (tx, rx) = mpsc::channel(listen::QUEUE);
            let entry = listen::Neighbor {
                address: neighbor.address,
                md5_key: neighbor.password.clone(),
                ttl_security: neighbor.ttl_security,
                tx,
            };
            let mut map = self.listen_neighbors.write().expect("never poisoned");
            listen::update(&self.listeners, map.get(&neighbor.address), Some(&entry))
                .map_err(|err| format!("listener for {}: {err}", neighbor.address))?;
            map.insert(neighbor.address, entry);
            Some(rx)
        };
        let (stop, stop_rx) = watch::channel(None);
        let span = info_span!("peer", id, addr = %neighbor.socket_addr(), asn = neighbor.asn);
        let task = tokio::spawn(peer::run(config, reporter, incoming, stop_rx).instrument(span));
        Ok(Peer {
            id,
            neighbor: neighbor.clone(),
            stop,
            task,
            handle,
        })
    }

    pub(super) fn publish_handles(&self) {
        let handles = self.peers.iter().map(|p| p.handle.clone()).collect();
        *self.handles.write().expect("never poisoned") = handles;
    }

    /// Removes a stopped neighbor from the listener and forgets its RIB
    /// settings.
    pub(super) async fn forget(&self, peer: &Peer) {
        let address = peer.neighbor.address;
        let entry = self
            .listen_neighbors
            .write()
            .expect("never poisoned")
            .remove(&address);
        if let Some(entry) = entry
            && let Err(err) = listen::update(&self.listeners, Some(&entry), None)
        {
            warn!(%err, %address, "cannot remove the neighbor from the listener");
        }
        let _ = self
            .rib
            .send(RibMsg::PeerSettings {
                peer: peer.id,
                settings: None,
            })
            .await;
    }
}
