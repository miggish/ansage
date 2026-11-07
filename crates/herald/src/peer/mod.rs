//! One tokio task per neighbor: owns the TCP connection and drives the [`Fsm`].
//!
//! Reading, timers and the FSM run in this task; decoded routes go to the
//! RIB, export batches from the RIB are encoded here. Writing happens in a
//! separate task with two queues: control messages (OPEN, KEEPALIVE,
//! NOTIFICATION) always go before route data, so keepalives never wait
//! behind a full table.
//!
//! Backpressure both ways without blocking timers:
//! - towards the RIB: events wait in `pending` and are handed over when the RIB
//!   channel has room; while `pending` is full, the socket is not read, so TCP
//!   slows the peer down;
//! - from the RIB: the next export batch is requested (`Ready`) only once the
//!   data queue has room again.

mod connection;
pub mod crash;
mod link;
pub mod listen;
pub mod sockopt;
pub mod status;

use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsFd,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::config::{Config, Md5Key, Neighbor};
use bytes::{Bytes, BytesMut};
use herald_bgp::{
    session::{Action, DownReason, Event, Fsm, PeerInfo, RejectReason, SessionConfig, State},
    wire::{
        Message, MessageType, Negotiated, Notification, Update, cease_subcode, error_code,
        split_message,
    },
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpSocket, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tracing::{debug, info, warn};

use self::status::{PeerCommand, PeerCounters, Reporter};
use crate::rib::{self, PeerMsg, PeerUp, RibMsg, SourceId};
use connection::Connection;
use link::shared_link;

/// Decoded events waiting for the RIB before we stop reading the socket.
const MAX_PENDING: usize = 64;
/// Control messages waiting for the writer.
const CONTROL_QUEUE: usize = 16;
/// Encoded export batches waiting for the writer.
const DATA_QUEUE: usize = 4;
/// How long shutdown waits for the final NOTIFICATION to be written.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
/// Shutdown text (RFC 9003) of the Cease the panic hook sends.
const CRASH_TEXT: &str = "herald crashed";
/// Shutdown text (RFC 9003) when herald stops.
pub const SHUTDOWN_TEXT: &str = "herald shutting down";

/// How a peer task is asked to end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopRequest {
    /// End the session with this Cease (shutdown, neighbor removed or
    /// changed); a Hard Reset with the N bit.
    Cease(Notification),
    /// `herald restart`: end it so the peer keeps our routes (Graceful
    /// Restart), see [`Event::Restart`].
    Restart,
}

type Connecting = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;

#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// This peer's ID in the RIB.
    pub id: SourceId,
    pub addr: SocketAddr,
    pub session: SessionConfig,
    /// Overrides for the next hop; see `config::Neighbor`.
    pub next_hop_ipv4: Option<Ipv4Addr>,
    pub next_hop_ipv6: Option<Ipv6Addr>,
    pub next_hop_ipv6_link_local: Option<Ipv6Addr>,
    /// TCP-MD5 key for the connection (RFC 2385).
    pub md5_key: Option<Md5Key>,
    /// GTSM hop count (RFC 5082).
    pub ttl_security: Option<u8>,
    pub rib: mpsc::Sender<RibMsg>,
    /// Start disabled (the neighbor was disabled before a config reload
    /// restarted it).
    pub start_disabled: bool,
}

impl PeerConfig {
    /// Everything the peer task for `neighbor` needs.
    pub fn new(
        config: &Config,
        id: SourceId,
        neighbor: &Neighbor,
        rib: mpsc::Sender<RibMsg>,
    ) -> Self {
        Self {
            id,
            addr: neighbor.socket_addr(),
            session: config.session(neighbor),
            next_hop_ipv4: neighbor.next_hop_ipv4,
            next_hop_ipv6: neighbor.next_hop_ipv6,
            next_hop_ipv6_link_local: neighbor.next_hop_ipv6_link_local,
            md5_key: neighbor.password.clone(),
            ttl_security: neighbor.ttl_security,
            rib,
            start_disabled: false,
        }
    }

    /// Our next hops for a session whose TCP connection uses `local`.
    fn next_hops(&self, local: IpAddr) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        let v4 = self.next_hop_ipv4.or(match local {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(addr) => addr.to_ipv4_mapped(),
        });
        // A link-local session address cannot be the (global) MP next hop
        // (RFC 2545 §3); then `next_hop_ipv6` has to be configured.
        let v6 = self.next_hop_ipv6.or(match local {
            IpAddr::V6(addr)
                if addr.to_ipv4_mapped().is_none() && !addr.is_unicast_link_local() =>
            {
                Some(addr)
            }
            _ => None,
        });
        (v4, v6)
    }
}

/// Runs the session until `stop` carries a request (the Cease to end the
/// session with, or a graceful restart), reporting its state
/// and counters through `reporter`. `incoming` delivers connections the
/// listener accepted from this neighbor.
pub async fn run(
    config: PeerConfig,
    mut reporter: Reporter,
    mut incoming: Option<mpsc::Receiver<TcpStream>>,
    mut stop: watch::Receiver<Option<StopRequest>>,
) {
    let id = config.id;
    let counters = reporter.counters.clone();
    let connect_timeout = config.session.connect_retry;
    let mut fsm = Fsm::new(config.session.clone());
    let mut conn: Option<Connection> = None;
    let mut connecting: Option<Connecting> = None;
    let mut last_writer: Option<JoinHandle<()>> = None;
    let mut stopping = false;
    let mut actions = Vec::new();
    // Events for the RIB, in order.
    let mut pending: VecDeque<RibMsg> = VecDeque::new();
    // Messages from the RIB for the current session.
    let mut from_rib: Option<mpsc::Receiver<PeerMsg>> = None;
    // Set while an export waits for room in the data queue (a clone of its
    // sender, so the wait does not borrow `conn`).
    let mut waiting_for_room: Option<mpsc::Sender<Bytes>> = None;
    // The session the panic hook writes its Cease on, while Established.
    let mut _crash_reg: Option<crash::Registration> = None;
    // Set by Action::Retain for the Down that follows.
    let mut retain = None;
    // A connection from the peer until the FSM decides about it.
    let mut parked: Option<TcpStream> = None;
    // Accepting the parked connection failed; tell the FSM.
    let mut accept_failed = false;
    // False once the control side is gone (control socket off).
    let mut commands_open = true;

    let first = if config.start_disabled {
        Event::Disable {
            reason: "disabled by the operator".into(),
        }
    } else {
        Event::Start
    };
    fsm.handle(first, Instant::now(), &mut actions);
    loop {
        // A connection was closed in this batch (for the collision log).
        let mut replaced = false;
        for action in actions.drain(..) {
            match action {
                Action::Connect => {
                    debug!("connecting");
                    status::bump(&counters.connect_attempts);
                    connecting = Some(Box::pin(connect(
                        config.addr,
                        config.md5_key.clone(),
                        config.ttl_security,
                        connect_timeout,
                    )));
                }
                Action::Send(message) => {
                    if let Some(c) = &conn {
                        c.send_control(&message, fsm.negotiated());
                    }
                }
                Action::Close => {
                    // Before the socket can close (see crash::Registration).
                    _crash_reg = None;
                    connecting = None;
                    if let Some(c) = conn.take() {
                        last_writer = Some(c.close());
                        replaced = true;
                    }
                    waiting_for_room = None;
                }
                Action::Up(peer) => {
                    info!(
                        asn = peer.asn,
                        bgp_id = %peer.bgp_id,
                        hold_time = peer.hold_time,
                        families = ?peer.families,
                        "session established"
                    );
                    status::bump(&counters.established);
                    if let Some(c) = &conn {
                        _crash_reg = Some(register_crash(c, &peer, fsm.negotiated()));
                        let (tx, rx) = mpsc::channel(2);
                        let (next_hop_ipv4, next_hop_ipv6) = config.next_hops(c.local.ip());
                        let link = shared_link(c.local, config.addr.ip());
                        let link_local = config
                            .next_hop_ipv6_link_local
                            .or_else(|| next_hop_ipv6.and(link?.link_local));
                        pending.push_back(RibMsg::Up(Box::new(PeerUp {
                            peer: id,
                            info: peer,
                            addr: config.addr.ip(),
                            local_addr: c.local.ip(),
                            next_hop_ipv4,
                            next_hop_ipv6,
                            next_hop_ipv6_link_local: link_local,
                            oif: link.map(|l| l.oif),
                            tx,
                        })));
                        from_rib = Some(rx);
                    }
                }
                Action::Retain(r) => retain = Some(r),
                Action::Down(reason) => {
                    log_down(&reason);
                    reporter.down(&reason);
                    let retain = retain.take();
                    if let Some(r) = &retain {
                        info!(restart_time = ?r.restart_time, families = ?r.families,
                            "keeping the peer's routes as stale (graceful restart)");
                    }
                    // Only sessions the RIB heard about need a Down.
                    if from_rib.take().is_some() {
                        pending.push_back(RibMsg::Down { peer: id, retain });
                    }
                }
                Action::Update(update) => pending.push_back(RibMsg::Update { peer: id, update }),
                Action::RouteRefresh(refresh) => pending.push_back(RibMsg::RouteRefresh {
                    peer: id,
                    afi: refresh.afi,
                    safi: refresh.safi,
                }),
                Action::AcceptParked => {
                    let stream = parked
                        .take()
                        .expect("the FSM accepts only a parked connection");
                    match Connection::new(stream, counters.clone(), FLUSH_TIMEOUT) {
                        Ok(c) => {
                            if replaced {
                                info!("collision: continuing on the peer's connection");
                            }
                            info!(local = %c.local, "using the connection from the peer");
                            status::bump(&counters.incoming_accepted);
                            conn = Some(c);
                        }
                        Err(err) => {
                            warn!(%err, "incoming connection failed");
                            accept_failed = true;
                        }
                    }
                }
                Action::RejectParked { reason } => {
                    if let Some(stream) = parked.take() {
                        status::bump(&counters.incoming_rejected);
                        reject(stream, reason, counters.clone());
                    }
                }
            }
        }
        if std::mem::take(&mut accept_failed) {
            fsm.handle(Event::TcpClosed, Instant::now(), &mut actions);
            continue;
        }
        reporter.sync(&fsm, conn.as_ref().map(|c| c.local));
        if stopping && fsm.state() == State::Idle && pending.is_empty() {
            break;
        }

        let deadline = fsm.next_deadline();
        tokio::select! {
            changed = stop.changed(), if !stopping => {
                let n = match changed {
                    Ok(()) => stop.borrow_and_update().clone(),
                    Err(_) => None,
                };
                // A dropped sender also ends the task.
                if n.is_some() || changed.is_err() {
                    stopping = true;
                    let event = match n {
                        Some(StopRequest::Restart) => Event::Restart,
                        Some(StopRequest::Cease(n)) => Event::Stop(n),
                        None => Event::Stop(Notification::admin_shutdown(SHUTDOWN_TEXT)),
                    };
                    fsm.handle(event, Instant::now(), &mut actions);
                }
            }
            result = async { connecting.as_mut().expect("guarded").await }, if connecting.is_some() => {
                connecting = None;
                match result.and_then(|s| Connection::new(s, counters.clone(), FLUSH_TIMEOUT)) {
                    Ok(c) => {
                        info!(local = %c.local, "connected");
                        conn = Some(c);
                        fsm.handle(Event::TcpConnected, Instant::now(), &mut actions);
                    }
                    Err(err) => {
                        warn!(%err, "connect failed");
                        status::bump(&counters.connect_failures);
                        reporter.error(format_args!("connect: {err}"));
                        fsm.handle(Event::TcpFailed, Instant::now(), &mut actions);
                    }
                }
            }
            _ = sleep_until(deadline), if deadline.is_some() => {
                fsm.on_timeout(Instant::now(), &mut actions);
            }
            result = read(&mut conn), if pending.len() < MAX_PENDING => match result {
                Ok(0) | Err(_) => {
                    if let Err(err) = result {
                        warn!(%err, "read failed");
                        reporter.error(format_args!("read: {err}"));
                    }
                    _crash_reg = None;
                    if let Some(c) = conn.take() {
                        last_writer = Some(c.close());
                    }
                    fsm.handle(Event::TcpClosed, Instant::now(), &mut actions);
                }
                Ok(_) => {
                    let c = conn.as_mut().expect("read returned data");
                    process(&mut c.rbuf, &mut fsm, &counters, &mut actions);
                }
            },
            permit = config.rib.reserve(), if !pending.is_empty() => match permit {
                Ok(permit) => permit.send(pending.pop_front().expect("guarded")),
                Err(_) => {
                    warn!("RIB is gone");
                    pending.clear();
                }
            },
            msg = recv(&mut from_rib) => match msg {
                Some(PeerMsg::Export(batch)) => {
                    if let Some(c) = &conn {
                        match rib::encode_batch(&batch, &fsm.negotiated()) {
                            Ok(bytes) => {
                                let messages = count_messages(&bytes);
                                if c.send_data(bytes) {
                                    count_export(&counters, &batch, messages);
                                }
                                fsm.update_sent(Instant::now());
                            }
                            Err(err) => warn!(%err, "cannot encode routes"),
                        }
                        if c.data.capacity() > 0 {
                            pending.push_back(RibMsg::Ready { peer: id });
                        } else {
                            waiting_for_room = Some(c.data.clone());
                        }
                    }
                }
                Some(PeerMsg::Teardown { notification, retry_after }) => {
                    let event = Event::Teardown { notification, retry_after };
                    fsm.handle(event, Instant::now(), &mut actions);
                }
                None => from_rib = None,
            },
            cmd = reporter.commands.recv(), if commands_open && !stopping => match cmd {
                Some(PeerCommand::Disable { reason }) => {
                    info!(%reason, "disabled by the operator");
                    fsm.handle(Event::Disable { reason }, Instant::now(), &mut actions);
                }
                Some(PeerCommand::Enable) => {
                    info!("enabled by the operator");
                    fsm.handle(Event::Start, Instant::now(), &mut actions);
                }
                Some(PeerCommand::Reset) => {
                    info!("reset by the operator");
                    fsm.handle(Event::Reset, Instant::now(), &mut actions);
                }
                None => commands_open = false,
            },
            stream = recv_incoming(&mut incoming), if !stopping => match stream {
                Some(stream) => {
                    // A newer connection from the peer replaces an undecided one.
                    if parked.replace(stream).is_some() {
                        status::bump(&counters.incoming_rejected);
                    }
                    fsm.handle(Event::Incoming, Instant::now(), &mut actions);
                }
                None => incoming = None,
            },
            room = data_room(&waiting_for_room), if waiting_for_room.is_some() => {
                waiting_for_room = None;
                if room {
                    pending.push_back(RibMsg::Ready { peer: id });
                }
            }
        }
    }

    // The writer bounds itself by FLUSH_TIMEOUT (then resets); this is only
    // a safety net.
    if let Some(writer) = last_writer
        && tokio::time::timeout(FLUSH_TIMEOUT + Duration::from_secs(1), writer)
            .await
            .is_err()
    {
        warn!("timed out flushing the final messages");
    }
}

/// Registers `c` with the panic hook: a Cease that makes the peer drop our
/// routes, a Hard Reset if it has the N bit (RFC 8538).
fn register_crash(c: &Connection, peer: &PeerInfo, neg: Negotiated) -> crash::Registration {
    let n = Notification::admin_shutdown(CRASH_TEXT);
    let n_bit = peer
        .graceful_restart
        .as_ref()
        .is_some_and(|gr| gr.notification);
    let n = if n_bit {
        Notification::hard_reset(&n)
    } else {
        n
    };
    let mut buf = BytesMut::new();
    if let Err(err) = Message::Notification(n).encode(&neg, &mut buf) {
        warn!(%err, "cannot encode the crash Cease");
    }
    crash::register(c.fd, c.write_state.clone(), buf.freeze())
}

/// Decodes all complete messages in `rbuf` and feeds them to the FSM.
fn process(rbuf: &mut BytesMut, fsm: &mut Fsm, counters: &PeerCounters, actions: &mut Vec<Action>) {
    loop {
        let neg = fsm.negotiated();
        let event = match split_message(rbuf, fsm.max_receive_len()) {
            Ok(None) => return,
            Ok(Some((kind, body))) => match Message::decode(kind, body.clone(), &neg) {
                Ok(message) => {
                    counters.messages_in.add(message.kind(), 1);
                    if let Message::Update(update) = &message {
                        if update.treat_as_withdraw.is_some() {
                            status::bump(&counters.malformed_updates);
                        }
                        if !update.discarded.is_empty() {
                            status::bump(&counters.discarded_attributes);
                        }
                        log_malformed(update, &body);
                    }
                    Event::Message(message)
                }
                Err(error) => {
                    status::bump(&counters.decode_errors);
                    Event::Malformed {
                        kind: Some(kind),
                        error,
                    }
                }
            },
            Err(error) => {
                status::bump(&counters.decode_errors);
                Event::Malformed { kind: None, error }
            }
        };
        fsm.handle(event, Instant::now(), actions);
        // The FSM closed the connection; ignore whatever else is buffered.
        if fsm.state() == State::Idle {
            return;
        }
    }
}

/// Connects to `addr`, with TCP-MD5 and GTSM set up before the SYN.
async fn connect(
    addr: SocketAddr,
    md5_key: Option<Md5Key>,
    ttl_security: Option<u8>,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    if let Some(key) = &md5_key {
        sockopt::set_md5(socket.as_fd(), addr.ip(), key.as_bytes())
            .map_err(|err| io::Error::new(err.kind(), format!("setting the TCP-MD5 key: {err}")))?;
    }
    if let Some(hops) = ttl_security {
        sockopt::set_gtsm(socket.as_fd(), addr.is_ipv6(), hops)
            .map_err(|err| io::Error::new(err.kind(), format!("setting up GTSM: {err}")))?;
    }
    match tokio::time::timeout(timeout, socket.connect(addr)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}

async fn read(conn: &mut Option<Connection>) -> io::Result<usize> {
    match conn {
        Some(c) => c.reader.read_buf(&mut c.rbuf).await,
        None => std::future::pending().await,
    }
}

async fn recv_incoming(rx: &mut Option<mpsc::Receiver<TcpStream>>) -> Option<TcpStream> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Turns a connection from the peer away: Cease with Connection Collision
/// Resolution (RFC 4271 §6.8) or Connection Rejected (RFC 4486), then close.
fn reject(stream: TcpStream, reason: RejectReason, counters: Arc<PeerCounters>) {
    let subcode = match reason {
        RejectReason::Established | RejectReason::Collision => {
            cease_subcode::CONNECTION_COLLISION_RESOLUTION
        }
        RejectReason::NotAccepting => cease_subcode::CONNECTION_REJECTED,
    };
    info!(?reason, "rejecting the connection from the peer");
    match Connection::new(stream, counters, FLUSH_TIMEOUT) {
        Ok(c) => {
            let n = Notification::new(error_code::CEASE, subcode, Bytes::new());
            c.send_control(&Message::Notification(n), Negotiated::default());
            // The writer task finishes on its own within the flush timeout.
            drop(c.close());
        }
        Err(err) => debug!(%err, "rejected connection already gone"),
    }
}

async fn recv(rx: &mut Option<mpsc::Receiver<PeerMsg>>) -> Option<PeerMsg> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Waits until the data queue has room; false if the writer is gone.
async fn data_room(data: &Option<mpsc::Sender<Bytes>>) -> bool {
    match data {
        Some(data) => data.reserve().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// Number of BGP messages in `bytes` (each starts with a 16-byte marker
/// and a 2-byte length).
fn count_messages(bytes: &[u8]) -> u64 {
    let mut messages = 0;
    let mut rest = bytes;
    while let Some(len) = rest.get(16..18) {
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        if len < herald_bgp::wire::HEADER_LEN {
            break;
        }
        messages += 1;
        rest = rest.get(len..).unwrap_or_default();
    }
    messages
}

/// Counts the UPDATEs and prefixes of an export batch that was queued.
fn count_export(counters: &PeerCounters, batch: &rib::ExportBatch, messages: u64) {
    counters.messages_out.add(MessageType::Update, messages);
    let announced: usize = batch.announce.iter().map(|a| a.prefixes.len()).sum();
    status::add(&counters.prefixes_announced, announced as u64);
    status::add(&counters.prefixes_withdrawn, batch.withdraw.len() as u64);
}

/// RFC 7606 §6: log the affected routes and the whole malformed UPDATE.
fn log_malformed(update: &Update, body: &Bytes) {
    if update.treat_as_withdraw.is_none() && update.discarded.is_empty() {
        return;
    }
    let routes: Vec<String> = update
        .nlri
        .iter()
        .map(ToString::to_string)
        .chain(
            update
                .mp_reach
                .iter()
                .flat_map(|m| m.nlri.iter().map(ToString::to_string)),
        )
        .collect();
    let hex: String = body.iter().map(|b| format!("{b:02x}")).collect();
    match &update.treat_as_withdraw {
        Some(err) => warn!(%err, discarded = ?update.discarded, ?routes, update = %hex,
            "malformed UPDATE, its routes are treated as withdrawn (RFC 7606)"),
        None => warn!(discarded = ?update.discarded, ?routes, update = %hex,
            "malformed attributes discarded (RFC 7606)"),
    }
}

fn log_down(reason: &DownReason) {
    match reason {
        DownReason::Stopped => info!("session closed (shutdown)"),
        DownReason::Restart => info!("session closed for a graceful restart"),
        DownReason::Admin(n) => info!(notification = %n, "session closed by the operator"),
        DownReason::ConnectionClosed => warn!("session down: connection closed"),
        DownReason::Received(n) => {
            warn!(notification = %n, data = ?n.data, "session down: peer sent NOTIFICATION")
        }
        DownReason::Sent(n) => {
            warn!(notification = %n, data = ?n.data, "session down: sent NOTIFICATION")
        }
    }
}

#[cfg(test)]
mod tests;
