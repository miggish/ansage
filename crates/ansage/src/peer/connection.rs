//! One TCP connection: the writer task with its two queues, and how a
//! connection ends.

use std::{
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
    time::Duration,
};

use ansage_bgp::wire::{Message, Negotiated};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, info, warn};

use super::{CONTROL_QUEUE, DATA_QUEUE, crash::SharedWriteState, status::PeerCounters};

pub(super) struct Connection {
    /// Our end of the TCP connection; the default next hop.
    pub(super) local: SocketAddr,
    pub(super) reader: OwnedReadHalf,
    pub(super) rbuf: BytesMut,
    pub(super) control: mpsc::Sender<Bytes>,
    pub(super) data: mpsc::Sender<Bytes>,
    pub(super) writer: JoinHandle<()>,
    /// Hands the read half to the writer on close, so it can wait for the
    /// peer's EOF (see [`finish`]).
    closing: oneshot::Sender<OwnedReadHalf>,
    pub(super) counters: Arc<PeerCounters>,
    /// The socket, for the panic hook.
    pub(super) fd: RawFd,
    /// Where the writer is in the current message, for the panic hook.
    pub(super) write_state: SharedWriteState,
}

impl Connection {
    /// `flush_timeout` bounds how long closing may take (see [`finish`]).
    pub(super) fn new(
        stream: TcpStream,
        counters: Arc<PeerCounters>,
        flush_timeout: Duration,
    ) -> io::Result<Self> {
        let local = stream.local_addr()?;
        // Keepalives are tiny; don't let Nagle hold them back.
        if let Err(err) = stream.set_nodelay(true) {
            warn!(%err, "setting TCP_NODELAY failed");
        }
        let fd = stream.as_raw_fd();
        let write_state = SharedWriteState::default();
        let (reader, writer) = stream.into_split();
        let (control, control_rx) = mpsc::channel(CONTROL_QUEUE);
        let (data, data_rx) = mpsc::channel(DATA_QUEUE);
        let (closing, closing_rx) = oneshot::channel();
        let task = write_loop(
            writer,
            control_rx,
            data_rx,
            closing_rx,
            flush_timeout,
            write_state.clone(),
        );
        Ok(Self {
            local,
            reader,
            rbuf: BytesMut::with_capacity(64 * 1024),
            control,
            data,
            writer: tokio::spawn(task),
            closing,
            counters,
            fd,
            write_state,
        })
    }

    pub(super) fn send_control(&self, message: &Message, neg: Negotiated) {
        let mut buf = BytesMut::new();
        if let Err(err) = message.encode(&neg, &mut buf) {
            warn!(%err, kind = ?message.kind(), "cannot encode message");
            return;
        }
        // Control messages are rare; a full queue means the peer stopped
        // reading long ago and its session is about to time out anyway.
        match self.control.try_send(buf.freeze()) {
            Ok(()) => self.counters.messages_out.add(message.kind(), 1),
            Err(err) => {
                super::status::bump(&self.counters.control_drops);
                warn!(%err, "control queue full, dropping message");
            }
        }
    }

    /// Only called after the RIB was told there is room; false if the
    /// routes were dropped anyway.
    pub(super) fn send_data(&self, bytes: Bytes) -> bool {
        match self.data.try_send(bytes) {
            Ok(()) => true,
            Err(err) => {
                super::status::bump(&self.counters.data_drops);
                warn!(%err, "data queue full, dropping routes");
                false
            }
        }
    }

    /// Stops reading; the writer flushes queued control messages (the final
    /// NOTIFICATION) and closes the connection (see [`finish`]). Queued
    /// routes are dropped. The handle completes within the flush timeout.
    pub(super) fn close(self) -> JoinHandle<()> {
        // The writer is gone only if a write failed; then nothing is left to
        // do.
        let _ = self.closing.send(self.reader);
        drop(self.control);
        drop(self.data);
        self.writer
    }
}

async fn write_loop(
    mut writer: OwnedWriteHalf,
    mut control: mpsc::Receiver<Bytes>,
    mut data: mpsc::Receiver<Bytes>,
    mut closing: oneshot::Receiver<OwnedReadHalf>,
    flush_timeout: Duration,
    write_state: SharedWriteState,
) {
    let reader = loop {
        let mut bytes = tokio::select! {
            biased;
            reader = &mut closing => break reader.ok(),
            msg = control.recv() => match msg {
                Some(bytes) => bytes,
                None => break (&mut closing).await.ok(),
            },
            Some(bytes) = data.recv() => bytes,
        };
        // One batch can take minutes on a slow link, so close() must be able
        // to interrupt it.
        let mut boundaries = super::crash::Boundaries::default();
        while !bytes.is_empty() {
            tokio::select! {
                biased;
                ready = writer.writable() => {
                    let written = ready.and_then(|()| {
                        write_some(&writer, &mut bytes, &mut boundaries, &write_state)
                    });
                    if let Err(err) = written {
                        debug!(%err, "write failed");
                        return;
                    }
                }
                reader = &mut closing => {
                    // A message is cut in half, so no NOTIFICATION can follow:
                    // the peer is not keeping up, reset at once.
                    info!("closing while the peer is not keeping up, resetting the connection");
                    reset(writer, reader.ok());
                    return;
                }
            }
        }
    };
    match reader {
        Some(reader) => finish(writer, reader, control, flush_timeout).await,
        // The connection was dropped without `close`.
        None => {
            let _ = writer.shutdown().await;
        }
    }
}

/// One non-blocking write, under the write state lock: the panic hook must
/// see where the current message ends (see `crate::peer::crash`).
fn write_some(
    writer: &OwnedWriteHalf,
    bytes: &mut Bytes,
    boundaries: &mut super::crash::Boundaries,
    write_state: &SharedWriteState,
) -> io::Result<()> {
    let mut state = super::crash::lock(write_state);
    match writer.try_write(bytes) {
        Ok(0) => Err(io::ErrorKind::WriteZero.into()),
        Ok(n) => {
            state.set_rest(boundaries.advance(bytes, n));
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(err) => Err(err),
    }
}

/// Closes the connection so the last messages are known to arrive:
/// writes what is left in the control queue (the final NOTIFICATION), sends
/// FIN and reads until the peer's EOF. Only that EOF proves the peer read
/// everything; without waiting, process exit can drop the unsent tail, e.g.
/// when a container's network namespace goes away.
///
/// If the peer does not close within `timeout` (routes still queued ahead of
/// the NOTIFICATION on a slow link, or a dead peer), the connection is reset:
/// the peer then drops the session at once instead of keeping our routes
/// until its hold timer expires.
async fn finish(
    mut writer: OwnedWriteHalf,
    mut reader: OwnedReadHalf,
    mut control: mpsc::Receiver<Bytes>,
    timeout: Duration,
) {
    let flushed = tokio::time::timeout(timeout, async {
        while let Some(bytes) = control.recv().await {
            writer.write_all(&bytes).await?;
        }
        writer.shutdown().await?;
        // Whatever the peer still sends is of no use now.
        let mut buf = [0u8; 4096];
        while reader.read(&mut buf).await? > 0 {}
        Ok::<(), io::Error>(())
    })
    .await;
    match flushed {
        Ok(Ok(())) => {}
        Ok(Err(err)) => debug!(%err, "connection failed while closing"),
        Err(_) => {
            info!(
                ?timeout,
                "peer did not close after our final messages, resetting the connection"
            );
            reset(writer, Some(reader));
        }
    }
}

/// Closes with a RST (SO_LINGER 0): unsent data is discarded and the peer
/// sees the connection fail at once.
pub(super) fn reset(writer: OwnedWriteHalf, reader: Option<OwnedReadHalf>) {
    let Some(reader) = reader else { return };
    if let Ok(stream) = reader.reunite(writer)
        && let Err(err) = stream.set_zero_linger()
    {
        debug!(%err, "cannot set SO_LINGER for the reset");
    }
}
