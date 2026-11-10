//! What ansage reports about its peers (control socket, later metrics).
//!
//! Peer tasks write it without locks on the hot path: counters are relaxed
//! atomics, and the session status is a `watch` value that is only written
//! when something changes (state, backoff, a session going down), never per
//! message. Readers take a snapshot and never block a peer task for long.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::config::Config;

use crate::config::ExportPolicy;

use crate::config::ImportPolicy;

use crate::config::Neighbor;

use crate::config::NeighborRole;

use ansage_bgp::session::DownReason;

use ansage_bgp::session::Fsm;

use ansage_bgp::session::State;

use ansage_bgp::wire::Afi;

use ansage_bgp::wire::MessageType;

use ansage_bgp::wire::Notification;

use ansage_bgp::wire::Safi;
use serde::Serialize;
use tokio::sync::{mpsc, watch};

use crate::rib::SourceId;

/// Wall-clock time in milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        Self::from_system(SystemTime::now())
    }

    pub fn from_system(time: SystemTime) -> Self {
        let ms = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis());
        Self(u64::try_from(ms).unwrap_or(u64::MAX))
    }

    /// The wall-clock time of the monotonic instant `at`.
    pub fn from_instant(at: Instant) -> Self {
        let (now, sys) = (Instant::now(), SystemTime::now());
        let time = if at >= now {
            sys.checked_add(at - now)
        } else {
            sys.checked_sub(now - at)
        };
        Self::from_system(time.unwrap_or(sys))
    }
}

/// One counter per message type.
#[derive(Debug, Default)]
pub struct MessageCounters {
    pub open: AtomicU64,
    pub update: AtomicU64,
    pub notification: AtomicU64,
    pub keepalive: AtomicU64,
    pub route_refresh: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MessageCounts {
    pub open: u64,
    pub update: u64,
    pub notification: u64,
    pub keepalive: u64,
    pub route_refresh: u64,
}

impl MessageCounters {
    pub fn add(&self, kind: MessageType, n: u64) {
        let counter = match kind {
            MessageType::Open => &self.open,
            MessageType::Update => &self.update,
            MessageType::Notification => &self.notification,
            MessageType::Keepalive => &self.keepalive,
            MessageType::RouteRefresh => &self.route_refresh,
        };
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MessageCounts {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        MessageCounts {
            open: load(&self.open),
            update: load(&self.update),
            notification: load(&self.notification),
            keepalive: load(&self.keepalive),
            route_refresh: load(&self.route_refresh),
        }
    }
}

/// Counters of one peer since ansage started (not reset per session).
#[derive(Debug, Default)]
pub struct PeerCounters {
    pub messages_in: MessageCounters,
    pub messages_out: MessageCounters,
    /// Prefixes in UPDATEs we sent.
    pub prefixes_announced: AtomicU64,
    pub prefixes_withdrawn: AtomicU64,
    /// UPDATEs whose routes were treated as withdrawn (RFC 7606).
    pub malformed_updates: AtomicU64,
    /// UPDATEs with attributes discarded (RFC 7606).
    pub discarded_attributes: AtomicU64,
    /// Messages that could not be decoded (the session is reset).
    pub decode_errors: AtomicU64,
    /// Messages dropped because a write queue was full.
    pub control_drops: AtomicU64,
    pub data_drops: AtomicU64,
    pub connect_attempts: AtomicU64,
    pub connect_failures: AtomicU64,
    /// Connections from the peer that became the session's connection.
    pub incoming_accepted: AtomicU64,
    /// Connections from the peer that were turned away (collision lost,
    /// already Established, not accepting).
    pub incoming_rejected: AtomicU64,
    /// Sessions that reached Established.
    pub established: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CounterSnapshot {
    pub messages_in: MessageCounts,
    pub messages_out: MessageCounts,
    pub prefixes_announced: u64,
    pub prefixes_withdrawn: u64,
    pub malformed_updates: u64,
    pub discarded_attributes: u64,
    pub decode_errors: u64,
    pub control_drops: u64,
    pub data_drops: u64,
    pub connect_attempts: u64,
    pub connect_failures: u64,
    pub incoming_accepted: u64,
    pub incoming_rejected: u64,
    pub established: u64,
}

impl PeerCounters {
    pub fn snapshot(&self) -> CounterSnapshot {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        CounterSnapshot {
            messages_in: self.messages_in.snapshot(),
            messages_out: self.messages_out.snapshot(),
            prefixes_announced: load(&self.prefixes_announced),
            prefixes_withdrawn: load(&self.prefixes_withdrawn),
            malformed_updates: load(&self.malformed_updates),
            discarded_attributes: load(&self.discarded_attributes),
            decode_errors: load(&self.decode_errors),
            control_drops: load(&self.control_drops),
            data_drops: load(&self.data_drops),
            connect_attempts: load(&self.connect_attempts),
            connect_failures: load(&self.connect_failures),
            incoming_accepted: load(&self.incoming_accepted),
            incoming_rejected: load(&self.incoming_rejected),
            established: load(&self.established),
        }
    }
}

/// Adds 1 to a counter.
pub fn bump(counter: &AtomicU64) {
    add(counter, 1);
}

pub fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

/// The configured side of a neighbor; does not change at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NeighborInfo {
    pub id: SourceId,
    pub address: SocketAddr,
    pub asn: u32,
    pub description: Option<String>,
    pub import: ImportPolicy,
    pub export: ExportPolicy,
    /// What the neighbor is to us (RFC 9234).
    pub role: Option<NeighborRole>,
    /// Gets a default route while a provider session is up.
    pub default_route: bool,
    pub max_prefixes_ipv4: Option<u32>,
    pub max_prefixes_ipv6: Option<u32>,
    /// Whether the session is signed with TCP-MD5 (never the key).
    pub tcp_md5: bool,
    /// GTSM hop count, if enabled.
    pub ttl_security: Option<u8>,
    /// Graceful Restart: the restart time we advertise, if enabled.
    pub graceful_restart: Option<u16>,
}

impl NeighborInfo {
    /// What the status reports about `neighbor`.
    pub fn new(config: &Config, id: SourceId, neighbor: &Neighbor) -> Self {
        Self {
            id,
            address: neighbor.socket_addr(),
            asn: neighbor.asn,
            description: neighbor.description.clone(),
            import: neighbor.import.clone(),
            export: neighbor.export.clone(),
            role: neighbor.role,
            default_route: neighbor.default_route,
            max_prefixes_ipv4: neighbor.max_prefixes_ipv4,
            max_prefixes_ipv6: neighbor.max_prefixes_ipv6,
            tcp_md5: neighbor.password.is_some(),
            ttl_security: neighbor.ttl_security,
            graceful_restart: config.session(neighbor).graceful_restart,
        }
    }
}

/// The session as the peer task sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerStatus {
    pub state: State,
    /// When `state` was entered.
    pub since: Timestamp,
    /// Our end of the TCP connection, while there is one.
    pub local: Option<SocketAddr>,
    /// What was negotiated, while Established.
    pub session: Option<SessionStatus>,
    pub last_down: Option<LastDown>,
    /// Last connect or socket error.
    pub last_error: Option<LastError>,
    /// Reconnect delay after the next failure (before jitter), in ms.
    pub backoff_ms: u64,
    /// When the next connection attempt is due, while waiting for it.
    pub next_connect: Option<Timestamp>,
    /// Disabled by the operator (`ansage peer X disable`).
    pub disabled: bool,
}

impl PeerStatus {
    fn new(backoff: Duration) -> Self {
        Self {
            state: State::Idle,
            since: Timestamp::now(),
            local: None,
            session: None,
            last_down: None,
            last_error: None,
            backoff_ms: millis(backoff),
            next_connect: None,
            disabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionStatus {
    pub asn: u32,
    pub bgp_id: Ipv4Addr,
    /// Negotiated hold time in seconds.
    pub hold_time: u16,
    /// Negotiated families, like "ipv4-unicast".
    pub families: Vec<String>,
    pub route_refresh: bool,
    pub four_octet_as: bool,
    pub extended_message: bool,
    /// RFC 8950 agreed: IPv4 routes may use IPv6 next hops.
    pub extended_next_hop: bool,
    pub ibgp: bool,
    /// The peer's Graceful Restart, if both sides offered it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graceful_restart: Option<GrStatus>,
    /// What the peer offers in its OPEN, also when our graceful restart is
    /// off (would enabling it help?). Always sent, null when not offered:
    /// a missing field means an older ansage that does not know.
    pub peer_graceful_restart: Option<GrStatus>,
    /// The BGP Role the peer sent (RFC 9234), its own: "customer" means it
    /// says it is our customer. Null when it sent none.
    pub peer_role: Option<&'static str>,
}

/// Graceful Restart as negotiated with the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrStatus {
    /// Seconds we keep the peer's routes after losing the session.
    pub restart_time: u16,
    /// N bit on both sides (RFC 8538).
    pub notification: bool,
    /// The peer had just restarted when the session came up (R bit).
    pub restarting: bool,
    /// Families the peer kept its forwarding state for (F bit).
    pub forwarding: Vec<String>,
}

fn gr_status(gr: &ansage_bgp::session::PeerGr) -> GrStatus {
    GrStatus {
        restart_time: gr.restart_time,
        notification: gr.notification,
        restarting: gr.restarting,
        forwarding: gr
            .families
            .iter()
            .filter(|f| f.forwarding)
            .map(|f| family_name(f.afi, f.safi))
            .collect(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastDown {
    pub at: Timestamp,
    /// "stopped", "connection closed", "notification received" or
    /// "notification sent".
    pub reason: &'static str,
    pub notification: Option<NotificationStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotificationStatus {
    pub code: u8,
    pub subcode: u8,
    /// Readable form, like "cease (6/2)".
    pub text: String,
    /// Administrative Shutdown/Reset text (RFC 9003).
    pub shutdown_text: Option<String>,
    /// The data field in hex.
    pub data: String,
}

impl From<&Notification> for NotificationStatus {
    fn from(n: &Notification) -> Self {
        Self {
            code: n.code,
            subcode: n.subcode,
            text: n.to_string(),
            shutdown_text: n.shutdown_text(),
            data: n.data.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastError {
    pub at: Timestamp,
    pub message: String,
}

/// "ipv4-unicast" style name of an address family.
pub fn family_name(afi: Afi, safi: Safi) -> String {
    let afi = match afi {
        Afi::IPV4 => "ipv4".to_string(),
        Afi::IPV6 => "ipv6".to_string(),
        Afi(n) => format!("afi{n}"),
    };
    match safi {
        Safi::UNICAST => format!("{afi}-unicast"),
        Safi(n) => format!("{afi}-safi{n}"),
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What the operator can tell a peer task (over the control socket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCommand {
    /// Close the session with this shutdown text and stay down.
    Disable {
        reason: String,
    },
    Enable,
    /// Cease / Administrative Reset, then reconnect.
    Reset,
}

/// The peer task's end: publishes status changes and owns the counters.
pub struct Reporter {
    tx: watch::Sender<PeerStatus>,
    pub counters: Arc<PeerCounters>,
    /// Commands from the control socket.
    pub commands: mpsc::Receiver<PeerCommand>,
    /// What was last published from the FSM, to publish only changes.
    seen: (State, Duration, Option<Instant>, Option<SocketAddr>, bool),
}

/// The reader's end, for the control socket.
#[derive(Debug, Clone)]
pub struct PeerHandle {
    pub neighbor: NeighborInfo,
    pub status: watch::Receiver<PeerStatus>,
    pub counters: Arc<PeerCounters>,
    pub commands: mpsc::Sender<PeerCommand>,
}

/// Creates both ends for one neighbor; `backoff` is its initial connect retry.
pub fn peer_channel(neighbor: NeighborInfo, backoff: Duration) -> (Reporter, PeerHandle) {
    let (tx, rx) = watch::channel(PeerStatus::new(backoff));
    let (commands_tx, commands) = mpsc::channel(4);
    let counters = Arc::new(PeerCounters::default());
    let reporter = Reporter {
        tx,
        counters: counters.clone(),
        commands,
        seen: (State::Idle, backoff, None, None, false),
    };
    let handle = PeerHandle {
        neighbor,
        status: rx,
        counters,
        commands: commands_tx,
    };
    (reporter, handle)
}

impl Reporter {
    /// Publishes the FSM's state, backoff and next attempt if any of them
    /// (or the local address) changed. Cheap when nothing changed.
    pub fn sync(&mut self, fsm: &Fsm, local: Option<SocketAddr>) {
        let disabled = fsm.disabled();
        let seen = (
            fsm.state(),
            fsm.backoff(),
            fsm.next_connect(),
            local,
            disabled,
        );
        if seen == self.seen {
            return;
        }
        let state_changed = seen.0 != self.seen.0;
        self.seen = seen;
        let (state, backoff, next_connect, local, disabled) = seen;
        self.tx.send_modify(|s| {
            if state_changed {
                s.state = state;
                s.since = Timestamp::now();
            }
            s.local = local;
            s.disabled = disabled;
            s.session = match (state, fsm.peer()) {
                (State::Established, Some(peer)) => Some(SessionStatus {
                    asn: peer.asn,
                    bgp_id: peer.bgp_id,
                    hold_time: peer.hold_time,
                    families: peer
                        .families
                        .iter()
                        .map(|&(afi, safi)| family_name(afi, safi))
                        .collect(),
                    route_refresh: peer.route_refresh,
                    four_octet_as: peer.negotiated.four_octet_as,
                    extended_message: peer.negotiated.extended_message,
                    extended_next_hop: peer.negotiated.extended_next_hop,
                    ibgp: peer.negotiated.ibgp,
                    graceful_restart: peer.graceful_restart.as_ref().map(gr_status),
                    peer_graceful_restart: peer.offered_graceful_restart.as_ref().map(gr_status),
                    peer_role: peer.role.map(|r| r.name().unwrap_or("unknown")),
                }),
                _ => None,
            };
            s.backoff_ms = millis(backoff);
            s.next_connect = next_connect.map(Timestamp::from_instant);
        });
    }

    pub fn down(&self, reason: &DownReason) {
        let (reason, notification) = match reason {
            DownReason::Stopped => ("stopped", None),
            DownReason::Restart => ("graceful restart", None),
            DownReason::Admin(n) => ("administrative", Some(n.into())),
            DownReason::ConnectionClosed => ("connection closed", None),
            DownReason::Received(n) => ("notification received", Some(n.into())),
            DownReason::Sent(n) => ("notification sent", Some(n.into())),
        };
        self.tx.send_modify(|s| {
            s.last_down = Some(LastDown {
                at: Timestamp::now(),
                reason,
                notification,
            });
        });
    }

    pub fn error(&self, message: impl ToString) {
        let message = message.to_string();
        self.tx.send_modify(|s| {
            s.last_error = Some(LastError {
                at: Timestamp::now(),
                message,
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ansage_bgp::{
        session::{Event, SessionConfig},
        wire::{Capability, Message, Open},
    };

    fn neighbor() -> NeighborInfo {
        NeighborInfo {
            id: 1,
            address: "127.0.0.2:179".parse().unwrap(),
            asn: 64501,
            description: None,
            import: ImportPolicy::None,
            export: ExportPolicy::Own,
            role: None,
            default_route: false,
            max_prefixes_ipv4: None,
            max_prefixes_ipv6: None,
            tcp_md5: false,
            ttl_security: None,
            graceful_restart: None,
        }
    }

    fn fsm() -> Fsm {
        Fsm::new(SessionConfig {
            local_asn: 64500,
            router_id: Ipv4Addr::new(203, 0, 113, 1),
            peer_asn: 64501,
            hold_time: 90,
            connect_retry: Duration::from_secs(10),
            max_connect_retry: Duration::from_secs(60),
            jitter: false,
            passive: false,
            graceful_restart: None,
            extended_next_hop: false,
            role: None,
            strict_role: false,
        })
    }

    #[test]
    fn publishes_transitions_session_and_backoff() {
        let (mut reporter, handle) = peer_channel(neighbor(), Duration::from_secs(10));
        let mut rx = handle.status.clone();
        rx.mark_unchanged();
        let mut fsm = fsm();
        let mut out = Vec::new();
        let now = Instant::now();

        // Nothing changed: no new version.
        reporter.sync(&fsm, None);
        assert!(!rx.has_changed().unwrap());

        fsm.handle(Event::Start, now, &mut out);
        reporter.sync(&fsm, None);
        assert_eq!(rx.borrow_and_update().state, State::Connect);

        // A failed connect doubles the backoff and schedules a retry.
        fsm.handle(Event::TcpFailed, now, &mut out);
        reporter.sync(&fsm, None);
        let s = rx.borrow_and_update().clone();
        assert_eq!(s.state, State::Idle);
        assert_eq!(s.backoff_ms, 20_000);
        assert!(s.next_connect.is_some());

        // Up to Established: the negotiated session shows up.
        fsm.on_timeout(now + Duration::from_secs(10), &mut out);
        fsm.handle(Event::TcpConnected, now, &mut out);
        let local = Some("127.0.0.1:40000".parse().unwrap());
        let open = Open::new(
            64501,
            90,
            Ipv4Addr::new(203, 0, 113, 2),
            vec![
                Capability::Multiprotocol {
                    afi: Afi::IPV4,
                    safi: Safi::UNICAST,
                },
                Capability::RouteRefresh,
            ],
        );
        fsm.handle(Event::Message(Message::Open(open)), now, &mut out);
        fsm.handle(Event::Message(Message::Keepalive), now, &mut out);
        reporter.sync(&fsm, local);
        let s = rx.borrow_and_update().clone();
        assert_eq!(s.state, State::Established);
        assert_eq!(s.local, local);
        assert_eq!(s.backoff_ms, 10_000, "Established resets the backoff");
        assert_eq!(s.next_connect, None);
        let session = s.session.expect("session while Established");
        assert_eq!(session.asn, 64501);
        assert_eq!(session.families, ["ipv4-unicast"]);
        assert!(session.route_refresh);

        // Going down records the NOTIFICATION and clears the session.
        let n = Notification::admin_shutdown("maintenance");
        reporter.down(&DownReason::Received(n.clone()));
        fsm.handle(Event::Message(Message::Notification(n)), now, &mut out);
        reporter.sync(&fsm, None);
        let s = rx.borrow_and_update().clone();
        assert_eq!(s.state, State::Idle);
        assert_eq!(s.session, None);
        let down = s.last_down.expect("down recorded");
        assert_eq!(down.reason, "notification received");
        let n = down.notification.unwrap();
        assert_eq!((n.code, n.subcode), (6, 2));
        assert_eq!(n.text, "cease (6/2)");
        assert_eq!(n.shutdown_text.as_deref(), Some("maintenance"));
    }

    #[test]
    fn counters_snapshot() {
        let counters = PeerCounters::default();
        counters.messages_in.add(MessageType::Keepalive, 1);
        counters.messages_out.add(MessageType::Update, 3);
        bump(&counters.connect_attempts);
        let s = counters.snapshot();
        assert_eq!(s.messages_in.keepalive, 1);
        assert_eq!(s.messages_out.update, 3);
        assert_eq!(s.connect_attempts, 1);
        assert_eq!(s.established, 0);
    }

    #[test]
    fn family_names() {
        assert_eq!(family_name(Afi::IPV6, Safi::UNICAST), "ipv6-unicast");
        assert_eq!(family_name(Afi(25), Safi(70)), "afi25-safi70");
    }
}
