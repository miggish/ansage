//! BGP finite state machine (RFC 4271 §8), without I/O.
//!
//! The caller feeds [`Event`]s and the current time in and executes the
//! [`Action`]s that come out. Timers are deadlines kept here; the caller
//! sleeps until [`Fsm::next_deadline`] and then calls [`Fsm::on_timeout`].
//! That keeps every protocol decision testable without sockets or clocks.
//!
//! Connections from the peer (passive listen) arrive as [`Event::Incoming`];
//! the caller keeps such a connection aside ("parked") until the FSM accepts
//! or rejects it. Connection collisions (RFC 4271 §6.8) are resolved here.

use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use bytes::Bytes;

use crate::wire::{
    Afi, Capability, DecodeError, GrFamily, GracefulRestart, MAX_EXTENDED_MESSAGE_LEN,
    MAX_MESSAGE_LEN, Message, MessageType, Negotiated, Notification, Open, RouteRefresh, Safi,
    Update, cease_subcode, error_code,
};

/// Hold time while waiting for the peer's OPEN (RFC 4271 §8.2.2: "4 minutes is
/// suggested").
const OPEN_HOLD_TIME: Duration = Duration::from_secs(240);
/// Shutdown text (RFC 9003) of the Cease sent for `herald restart` to
/// neighbors with the N bit (RFC 8538): not a Hard Reset, so they keep our
/// routes.
pub const RESTART_TEXT: &str = "herald restarting";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum State {
    Idle,
    /// Waiting for the peer to connect (passive neighbors only).
    Active,
    Connect,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub local_asn: u32,
    pub router_id: Ipv4Addr,
    pub peer_asn: u32,
    /// Proposed hold time in seconds.
    pub hold_time: u16,
    /// Delay between connection attempts; also the connect timeout.
    pub connect_retry: Duration,
    /// Upper bound for the reconnect backoff (RFC 4486 §4).
    pub max_connect_retry: Duration,
    /// Randomize the keepalive and connect retry timers by a factor of
    /// 0.75 to 1.0 (RFC 4271 §10). Off only in tests.
    pub jitter: bool,
    /// Never connect; only accept connections from the peer.
    pub passive: bool,
    /// Graceful Restart (RFC 4724) with this restart time in seconds; None:
    /// no Graceful Restart capability.
    pub graceful_restart: Option<u16>,
}

/// What both sides agreed on in the OPEN exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub asn: u32,
    pub bgp_id: Ipv4Addr,
    /// Negotiated hold time in seconds (0: no keepalives).
    pub hold_time: u16,
    pub negotiated: Negotiated,
    /// Address families both sides support.
    pub families: Vec<(Afi, Safi)>,
    pub route_refresh: bool,
    /// The peer's Graceful Restart capability, if both sides sent one.
    pub graceful_restart: Option<PeerGr>,
    /// The peer's Graceful Restart capability, whether we sent ours or
    /// not: shows if enabling it would help with this peer.
    pub offered_graceful_restart: Option<PeerGr>,
}

/// Graceful Restart as the peer offered it (RFC 4724 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerGr {
    /// Seconds the peer wants its routes kept after a session loss.
    pub restart_time: u16,
    /// The peer has just restarted (R bit).
    pub restarting: bool,
    /// Both sides sent the N bit (we always do): Graceful Restart also
    /// covers NOTIFICATIONs other than Hard Reset (RFC 8538).
    pub notification: bool,
    /// Families the peer keeps routes for, with its F bit.
    pub families: Vec<GrFamily>,
}

/// The session ended in a way that keeps the peer's routes (RFC 4724 §4.2):
/// mark them stale for `restart_time` instead of removing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retain {
    pub restart_time: Duration,
    pub families: Vec<(Afi, Safi)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Start connecting, and reconnect after failures.
    Start,
    /// Close the session for good, sending this Cease if a session exists
    /// (shutdown, neighbor removed or changed by a config reload).
    Stop(Notification),
    /// The operator disabled the neighbor: like [`Event::Stop`] with this
    /// shutdown text (RFC 9003); [`Event::Start`] enables it again.
    Disable {
        reason: String,
    },
    /// The operator resets the session: Cease / Administrative Reset, then
    /// reconnect at once. Without a session, connect now.
    Reset,
    /// herald is restarting (`herald restart`): end the session so that a
    /// peer with Graceful Restart keeps our routes. With the N bit Cease /
    /// Administrative Shutdown without Hard Reset, else no NOTIFICATION at
    /// all. Without Graceful Restart like [`Event::Stop`].
    Restart,
    TcpConnected,
    TcpFailed,
    TcpClosed,
    /// The peer opened a connection to us; the caller parked it and waits
    /// for [`Action::AcceptParked`] or [`Action::RejectParked`].
    Incoming,
    Message(Message),
    /// A received message could not be decoded. `kind` is its type, if the
    /// header was valid.
    Malformed {
        kind: Option<MessageType>,
        error: DecodeError,
    },
    /// Close the session with `notification` and reconnect after
    /// `retry_after` instead of the usual connect retry (max-prefix).
    Teardown {
        notification: Notification,
        retry_after: Duration,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Open a TCP connection to the peer; report the outcome as
    /// [`Event::TcpConnected`] or [`Event::TcpFailed`].
    Connect,
    Send(Message),
    /// Close the connection after flushing what was sent before.
    Close,
    /// The session reached Established.
    Up(PeerInfo),
    /// Comes right before the [`Action::Down`] of a session whose routes
    /// the peer wants kept (Graceful Restart helper).
    Retain(Retain),
    /// A session that got past TCP setup ended.
    Down(DownReason),
    /// Routes from the peer.
    Update(Update),
    /// The peer asks us to resend our routes.
    RouteRefresh(RouteRefresh),
    /// The parked connection from the peer becomes the session's
    /// connection (the old one was closed by an earlier [`Action::Close`]);
    /// [`Action::Send`]s that follow go to it.
    AcceptParked,
    /// Send Cease / Connection Collision Resolution (or nothing, if the
    /// FSM is stopped) on the parked connection and close it.
    RejectParked {
        reason: RejectReason,
    },
}

/// Why a connection from the peer was turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// A session is already Established (RFC 4271 §6.8).
    Established,
    /// Our own connection won the collision: our BGP Identifier is higher.
    Collision,
    /// Stopped, or holding off after a max-prefix teardown.
    NotAccepting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownReason {
    Stopped,
    /// Closed for `herald restart`; the peer keeps our routes.
    Restart,
    /// The operator disabled or reset the session; we sent this NOTIFICATION.
    Admin(Notification),
    ConnectionClosed,
    /// The peer sent this NOTIFICATION.
    Received(Notification),
    /// We sent this NOTIFICATION.
    Sent(Notification),
}

pub struct Fsm {
    config: SessionConfig,
    state: State,
    /// Reconnect after failures; cleared by [`Event::Stop`].
    auto_start: bool,
    peer: Option<PeerInfo>,
    hold_time: Duration,
    keepalive_time: Duration,
    connect_retry_at: Option<Instant>,
    hold_at: Option<Instant>,
    keepalive_at: Option<Instant>,
    /// Delay before the next reconnect, if not `backoff`.
    retry_override: Option<Duration>,
    /// Current reconnect delay: doubles on failures, reset when Established.
    backoff: Duration,
    /// State of the jitter random number generator (xorshift).
    rng: u64,
    /// Whether we opened the current connection (false: the peer did).
    outbound: bool,
    /// Set by [`Event::Disable`], cleared by [`Event::Start`].
    disabled: bool,
    /// The caller holds a connection from the peer that is not decided yet.
    parked: bool,
    /// Connections from the peer are refused until then (after a
    /// max-prefix teardown: the peer has to stay away like we do).
    refuse_until: Option<Instant>,
    /// R bit in our Graceful Restart capability: set until the first
    /// session after start is Established (RFC 4724 §3).
    restarting: bool,
}

impl Fsm {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config: config.clone(),
            state: State::Idle,
            auto_start: false,
            peer: None,
            hold_time: Duration::ZERO,
            keepalive_time: Duration::ZERO,
            connect_retry_at: None,
            hold_at: None,
            keepalive_at: None,
            retry_override: None,
            backoff: config.connect_retry,
            // RandomState is seeded from the OS; good enough for jitter.
            rng: RandomState::new().build_hasher().finish() | 1,
            outbound: false,
            disabled: false,
            parked: false,
            refuse_until: None,
            restarting: true,
        }
    }

    /// Disabled by the operator ([`Event::Disable`]) until the next
    /// [`Event::Start`].
    pub fn disabled(&self) -> bool {
        self.disabled
    }

    /// Whether the current connection was opened by us.
    pub fn outbound(&self) -> bool {
        self.outbound
    }

    /// Largest message we accept. We always advertise the Extended Message
    /// capability, so we must take up to 65535 bytes whatever the peer
    /// advertised (RFC 8654 §4); what we send follows the peer's capability.
    pub fn max_receive_len(&self) -> usize {
        MAX_EXTENDED_MESSAGE_LEN
    }

    /// An UPDATE went out: restart the KeepaliveTimer (RFC 4271 §8.2.2).
    pub fn update_sent(&mut self, now: Instant) {
        if self.state == State::Established && !self.hold_time.is_zero() {
            self.keepalive_at = Some(now + self.jittered(self.keepalive_time));
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Known once the peer's OPEN was accepted (OpenConfirm and Established).
    pub fn peer(&self) -> Option<&PeerInfo> {
        self.peer.as_ref()
    }

    /// Encoding parameters for the current connection.
    pub fn negotiated(&self) -> Negotiated {
        self.peer.as_ref().map(|p| p.negotiated).unwrap_or_default()
    }

    /// Reconnect delay after the next failure, before jitter.
    pub fn backoff(&self) -> Duration {
        self.backoff
    }

    /// When the next connection attempt is due, if one is scheduled.
    pub fn next_connect(&self) -> Option<Instant> {
        self.connect_retry_at
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        [self.connect_retry_at, self.hold_at, self.keepalive_at]
            .into_iter()
            .flatten()
            .min()
    }

    pub fn handle(&mut self, event: Event, now: Instant, out: &mut Vec<Action>) {
        match (self.state, event) {
            (_, Event::Stop(n)) => {
                let n = self.outgoing(n);
                self.stop(Some(n), DownReason::Stopped, now, out);
            }
            (_, Event::Disable { reason }) => {
                self.disabled = true;
                let n = self.outgoing(Notification::admin_shutdown(&reason));
                self.stop(Some(n.clone()), DownReason::Admin(n), now, out);
            }
            (_, Event::Restart) => self.restart(now, out),
            (state, Event::Reset) => self.reset(state, now, out),
            (State::Idle, Event::Start) => {
                self.disabled = false;
                self.auto_start = true;
                self.connect(out);
            }
            (_, Event::Start) => {}

            (state, Event::Incoming) => self.incoming(state, now, out),

            (State::Connect, Event::TcpConnected) => {
                self.outbound = true;
                self.send_open(now, out);
            }
            (State::Connect, Event::TcpFailed) => {
                self.state = State::Idle;
                self.schedule_restart(now);
                self.escalate();
            }
            (State::Idle | State::Active | State::Connect, _) => {}

            (_, Event::TcpConnected) => {}
            (_, Event::TcpFailed | Event::TcpClosed) => {
                self.close(DownReason::ConnectionClosed, false, now, out);
            }
            (state, Event::Malformed { kind, error }) => {
                // RFC 4271 §8.2.2: a broken message of a type that is not
                // expected in this state is an FSM error, not a format error.
                let notification = match (state, kind) {
                    (State::OpenSent | State::OpenConfirm, Some(MessageType::Update))
                    | (State::OpenConfirm | State::Established, Some(MessageType::Open)) => {
                        unexpected_message(state, kind.expect("matched"))
                    }
                    _ => error.notification(),
                };
                self.fail(notification, now, out);
            }
            (
                _,
                Event::Teardown {
                    notification,
                    retry_after,
                },
            ) => {
                self.retry_override = Some(retry_after);
                self.fail(notification, now, out);
            }
            // RFC 4271 §6.4: never answer a NOTIFICATION.
            (_, Event::Message(Message::Notification(n))) => {
                // RFC 4486 §4: the peer does not want us now; back off.
                let damp = n.code == error_code::CEASE
                    && matches!(
                        n.subcode,
                        cease_subcode::ADMINISTRATIVE_SHUTDOWN
                            | cease_subcode::PEER_DECONFIGURED
                            | cease_subcode::CONNECTION_REJECTED
                            | cease_subcode::OUT_OF_RESOURCES
                    );
                self.close(DownReason::Received(n), damp, now, out);
            }

            (State::OpenSent, Event::Message(Message::Open(open))) => {
                self.receive_open(open, now, out);
            }
            (State::OpenConfirm, Event::Message(Message::Keepalive)) => {
                self.state = State::Established;
                self.restarting = false;
                self.backoff = self.config.connect_retry;
                self.restart_hold(now);
                let peer = self.peer.clone().expect("peer is set in OpenConfirm");
                out.push(Action::Up(peer));
            }
            (State::Established, Event::Message(Message::Keepalive)) => self.restart_hold(now),
            (State::Established, Event::Message(Message::Update(update))) => {
                self.restart_hold(now);
                out.push(Action::Update(update));
            }
            (State::Established, Event::Message(Message::RouteRefresh(refresh))) => {
                out.push(Action::RouteRefresh(refresh));
            }

            (state, Event::Message(message)) => {
                self.fail(unexpected_message(state, message.kind()), now, out);
            }
        }
    }

    pub fn on_timeout(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.connect_retry_at.is_some_and(|t| t <= now) {
            self.connect_retry_at = None;
            if self.state == State::Idle && self.auto_start {
                self.refuse_until = None;
                self.connect(out);
            }
        }
        if self.hold_at.is_some_and(|t| t <= now) {
            self.fail(Notification::hold_timer_expired(), now, out);
            return;
        }
        if self.keepalive_at.is_some_and(|t| t <= now) {
            out.push(Action::Send(Message::Keepalive));
            self.keepalive_at = Some(now + self.jittered(self.keepalive_time));
        }
    }

    /// `base` times a random factor in [0.75, 1.0] (RFC 4271 §10).
    fn jittered(&mut self, base: Duration) -> Duration {
        if !self.config.jitter {
            return base;
        }
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let unit = (self.rng >> 11) as f64 / (1u64 << 53) as f64;
        base.mul_f64(0.75 + 0.25 * unit)
    }

    fn open(&self) -> Open {
        let mut capabilities = vec![
            Capability::Multiprotocol {
                afi: Afi::IPV4,
                safi: Safi::UNICAST,
            },
            Capability::Multiprotocol {
                afi: Afi::IPV6,
                safi: Safi::UNICAST,
            },
            Capability::RouteRefresh,
            Capability::ExtendedMessage,
        ];
        if let Some(restart_time) = self.config.graceful_restart {
            // F bit always set: herald never forwards. The routes it
            // announces lead to the kernel's forwarding, which a herald
            // restart does not touch.
            let families = [Afi::IPV4, Afi::IPV6]
                .map(|afi| GrFamily {
                    afi,
                    safi: Safi::UNICAST,
                    forwarding: true,
                })
                .to_vec();
            capabilities.push(Capability::GracefulRestart(GracefulRestart {
                restarting: self.restarting,
                notification: true,
                restart_time,
                families,
            }));
        }
        Open::new(
            self.config.local_asn,
            self.config.hold_time,
            self.config.router_id,
            capabilities,
        )
    }

    fn receive_open(&mut self, open: Open, now: Instant, out: &mut Vec<Action>) {
        let asn = open.asn();
        if asn != self.config.peer_asn {
            return self.fail(DecodeError::BadPeerAs(asn).notification(), now, out);
        }
        // RFC 6286 §2.2: identifiers only have to differ within one AS.
        if asn == self.config.local_asn && open.bgp_id == self.config.router_id {
            return self.fail(DecodeError::BadBgpIdentifier.notification(), now, out);
        }

        let ours = self.open().capabilities;
        let theirs = &open.capabilities;
        let has = |cap: &Capability| theirs.contains(cap);

        let peer_families: Vec<_> = theirs
            .iter()
            .filter_map(|c| match c {
                Capability::Multiprotocol { afi, safi } => Some((*afi, *safi)),
                _ => None,
            })
            .collect();
        // RFC 4760 §8: without any Multiprotocol capability, IPv4 unicast is implied.
        let families = ours
            .iter()
            .filter_map(|c| match c {
                Capability::Multiprotocol { afi, safi } => Some((*afi, *safi)),
                _ => None,
            })
            .filter(|f| {
                peer_families.contains(f)
                    || (peer_families.is_empty() && *f == (Afi::IPV4, Safi::UNICAST))
            })
            .collect();

        // RFC 4724 §3: only the last instance counts.
        let offered_graceful_restart = theirs
            .iter()
            .rev()
            .find_map(|c| match c {
                Capability::GracefulRestart(gr) => Some(gr),
                _ => None,
            })
            .map(|gr| PeerGr {
                restart_time: gr.restart_time,
                restarting: gr.restarting,
                notification: gr.notification,
                families: gr.families.clone(),
            });
        let graceful_restart = offered_graceful_restart
            .clone()
            .filter(|_| self.config.graceful_restart.is_some());

        let hold_time = self.config.hold_time.min(open.hold_time);
        self.peer = Some(PeerInfo {
            asn,
            bgp_id: open.bgp_id,
            hold_time,
            negotiated: Negotiated {
                // We always send both capabilities.
                four_octet_as: theirs
                    .iter()
                    .any(|c| matches!(c, Capability::FourOctetAs(_))),
                extended_message: has(&Capability::ExtendedMessage),
                ibgp: asn == self.config.local_asn,
            },
            families,
            route_refresh: has(&Capability::RouteRefresh),
            graceful_restart,
            offered_graceful_restart,
        });

        out.push(Action::Send(Message::Keepalive));
        self.hold_time = Duration::from_secs(hold_time.into());
        self.keepalive_time = self.hold_time / 3;
        self.restart_hold(now);
        self.keepalive_at = if hold_time > 0 {
            Some(now + self.jittered(self.keepalive_time))
        } else {
            None
        };
        self.state = State::OpenConfirm;
        // The peer's connection waited for its BGP Identifier.
        if self.parked {
            self.resolve_collision(now, out);
        }
    }

    fn connect(&mut self, out: &mut Vec<Action>) {
        if self.config.passive {
            self.state = State::Active;
        } else {
            self.state = State::Connect;
            out.push(Action::Connect);
        }
    }

    fn send_open(&mut self, now: Instant, out: &mut Vec<Action>) {
        out.push(Action::Send(Message::Open(self.open())));
        self.hold_at = Some(now + OPEN_HOLD_TIME);
        self.state = State::OpenSent;
    }

    /// A connection from the peer is parked (RFC 4271 §6.8 for collisions).
    fn incoming(&mut self, state: State, now: Instant, out: &mut Vec<Action>) {
        self.parked = true;
        match state {
            State::Idle | State::Active | State::Connect => {
                let refused = self.refuse_until.is_some_and(|t| now < t);
                if !self.auto_start || refused {
                    self.reject_parked(RejectReason::NotAccepting, out);
                    return;
                }
                if state == State::Connect {
                    // Abandon our own attempt; the peer's connection is there.
                    out.push(Action::Close);
                }
                self.accept_parked(now, out);
            }
            // We do not know the peer's BGP Identifier yet: wait for its
            // OPEN on our connection.
            State::OpenSent if self.outbound => {}
            State::OpenConfirm if self.outbound => self.resolve_collision(now, out),
            // The peer opened another connection before finishing the
            // first; it has given up on that one.
            State::OpenSent | State::OpenConfirm => self.switch_to_parked(now, out),
            State::Established => self.reject_parked(RejectReason::Established, out),
        }
    }

    /// Our connection is in OpenConfirm, the peer's is parked: the one
    /// opened by the side with the higher BGP Identifier survives (RFC 4271
    /// §6.8; equal identifiers: the higher AS number, RFC 6286 §2.3).
    fn resolve_collision(&mut self, now: Instant, out: &mut Vec<Action>) {
        let peer = self.peer.as_ref().expect("peer is set in OpenConfirm");
        let ours = (u32::from(self.config.router_id), self.config.local_asn);
        let theirs = (u32::from(peer.bgp_id), peer.asn);
        if ours < theirs {
            self.switch_to_parked(now, out);
        } else {
            self.reject_parked(RejectReason::Collision, out);
        }
    }

    /// Closes the current connection with Cease / Connection Collision
    /// Resolution and continues on the parked one. Not a session failure:
    /// no Down, no backoff.
    fn switch_to_parked(&mut self, now: Instant, out: &mut Vec<Action>) {
        let n = Notification::new(
            error_code::CEASE,
            cease_subcode::CONNECTION_COLLISION_RESOLUTION,
            Bytes::new(),
        );
        out.push(Action::Send(Message::Notification(n)));
        out.push(Action::Close);
        self.peer = None;
        self.hold_time = Duration::ZERO;
        self.keepalive_at = None;
        self.accept_parked(now, out);
    }

    fn accept_parked(&mut self, now: Instant, out: &mut Vec<Action>) {
        out.push(Action::AcceptParked);
        self.parked = false;
        self.outbound = false;
        self.connect_retry_at = None;
        self.send_open(now, out);
    }

    fn reject_parked(&mut self, reason: RejectReason, out: &mut Vec<Action>) {
        out.push(Action::RejectParked { reason });
        self.parked = false;
    }

    fn restart_hold(&mut self, now: Instant) {
        self.hold_at = (!self.hold_time.is_zero()).then(|| now + self.hold_time);
    }

    fn schedule_restart(&mut self, now: Instant) {
        let forced = self.retry_override.take();
        let delay = forced.unwrap_or(self.backoff);
        self.refuse_until = None;
        if self.auto_start {
            let at = now + self.jittered(delay);
            self.connect_retry_at = Some(at);
            if forced.is_some() {
                self.refuse_until = Some(at);
            }
        }
    }

    /// Doubles the reconnect delay for the next attempt, up to the maximum.
    fn escalate(&mut self) {
        self.backoff = (self.backoff * 2).min(self.config.max_connect_retry);
    }

    /// Sends `notification`, then closes. The data is cut so the message
    /// fits 4096 bytes: it is encoded after the session state is gone, and
    /// a NOTIFICATION must never be dropped (RFC 4271 §6, RFC 8654 §5).
    fn fail(&mut self, notification: Notification, now: Instant, out: &mut Vec<Action>) {
        let notification = self.outgoing(notification).truncated(MAX_MESSAGE_LEN);
        out.push(Action::Send(Message::Notification(notification.clone())));
        self.close(DownReason::Sent(notification), false, now, out);
    }

    /// Ends the session. The next attempt uses the current backoff; the
    /// backoff then doubles if the session never got to Established (the
    /// peer closed or rejected us, or we rejected it: retrying at full speed
    /// cannot help) or if the peer asked us to stay away (`damp`, RFC 4486
    /// §4). Established resets it.
    fn close(&mut self, reason: DownReason, damp: bool, now: Instant, out: &mut Vec<Action>) {
        let failed_early = self.state != State::Established && reason != DownReason::Stopped;
        out.push(Action::Close);
        if self.state == State::Established
            && let Some(retain) = self.retain(&reason)
        {
            out.push(Action::Retain(retain));
        }
        out.push(Action::Down(reason));
        self.state = State::Idle;
        self.peer = None;
        self.hold_time = Duration::ZERO;
        self.hold_at = None;
        self.keepalive_at = None;
        self.schedule_restart(now);
        if damp || failed_early {
            self.escalate();
        }
        if self.parked {
            // Our connection failed while the peer's waited: use that one.
            if self.auto_start {
                self.accept_parked(now, out);
            } else {
                self.reject_parked(RejectReason::NotAccepting, out);
            }
        } else if self.config.passive && self.auto_start && self.refuse_until.is_none() {
            // Nothing to wait for: the peer reconnects when it wants to.
            self.connect_retry_at = None;
            self.state = State::Active;
        }
    }

    fn reset(&mut self, state: State, now: Instant, out: &mut Vec<Action>) {
        if !self.auto_start {
            return;
        }
        match state {
            State::OpenSent | State::OpenConfirm | State::Established => {
                let n = self.outgoing(Notification::new(
                    error_code::CEASE,
                    cease_subcode::ADMINISTRATIVE_RESET,
                    Bytes::new(),
                ));
                out.push(Action::Send(Message::Notification(n.clone())));
                self.close(DownReason::Admin(n), false, now, out);
                // A reset is not a failure: start over at once.
                self.backoff = self.config.connect_retry;
                if self.state == State::Idle {
                    self.connect_retry_at = Some(now);
                }
            }
            // Waiting to reconnect: do it now.
            State::Idle => {
                self.refuse_until = None;
                self.connect_retry_at = None;
                self.connect(out);
            }
            State::Active | State::Connect => {}
        }
    }

    /// Ends the session for good, with `notification` if there is a
    /// session (and a notification).
    fn stop(
        &mut self,
        notification: Option<Notification>,
        reason: DownReason,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        self.auto_start = false;
        self.connect_retry_at = None;
        if self.parked {
            self.reject_parked(RejectReason::NotAccepting, out);
        }
        match self.state {
            State::Idle => {}
            State::Active => self.state = State::Idle,
            // Connection attempt in flight: just abandon it.
            State::Connect => {
                out.push(Action::Close);
                self.state = State::Idle;
            }
            State::OpenSent | State::OpenConfirm | State::Established => {
                if let Some(n) = notification {
                    out.push(Action::Send(Message::Notification(n)));
                }
                self.close(reason, false, now, out);
            }
        }
    }

    /// Ends the session so that a peer with Graceful Restart keeps our
    /// routes: no Hard Reset (RFC 8538) or, without the N bit, no
    /// NOTIFICATION at all (RFC 4724).
    fn restart(&mut self, now: Instant, out: &mut Vec<Action>) {
        let gr = self.peer.as_ref().and_then(|p| p.graceful_restart.as_ref());
        match gr {
            Some(gr) if self.state == State::Established => {
                let n = gr
                    .notification
                    .then(|| Notification::admin_shutdown(RESTART_TEXT));
                self.stop(n, DownReason::Restart, now, out);
            }
            _ => {
                let n = self.outgoing(Notification::admin_shutdown(RESTART_TEXT));
                self.stop(Some(n), DownReason::Stopped, now, out);
            }
        }
    }

    /// RFC 8538 §5: with the N bit, a Cease that ends the session on purpose
    /// (max prefixes, shutdown, de-configured, reset) goes out as Hard
    /// Reset, so the peer drops our routes at once. Every other NOTIFICATION
    /// lets it keep them.
    fn outgoing(&self, n: Notification) -> Notification {
        let n_bit = self
            .peer
            .as_ref()
            .and_then(|p| p.graceful_restart.as_ref())
            .is_some_and(|gr| gr.notification);
        let hard = n.code == error_code::CEASE
            && matches!(
                n.subcode,
                cease_subcode::MAX_PREFIXES_REACHED
                    | cease_subcode::ADMINISTRATIVE_SHUTDOWN
                    | cease_subcode::PEER_DECONFIGURED
                    | cease_subcode::ADMINISTRATIVE_RESET
            );
        if n_bit && hard {
            Notification::hard_reset(&n)
        } else {
            n
        }
    }

    /// Whether the peer's routes outlive this session end (RFC 4724 §4.2):
    /// the connection was lost without a NOTIFICATION, or, with the N bit,
    /// with any NOTIFICATION but Hard Reset (RFC 8538 §4). Closing on
    /// purpose (stop, disable) drops them.
    fn retain(&self, reason: &DownReason) -> Option<Retain> {
        let peer = self.peer.as_ref()?;
        let gr = peer.graceful_restart.as_ref()?;
        let graceful = match reason {
            DownReason::ConnectionClosed => true,
            DownReason::Sent(n) | DownReason::Received(n) => gr.notification && !n.is_hard_reset(),
            DownReason::Stopped | DownReason::Restart | DownReason::Admin(_) => false,
        };
        let families: Vec<(Afi, Safi)> = gr
            .families
            .iter()
            .map(|f| (f.afi, f.safi))
            .filter(|f| peer.families.contains(f))
            .collect();
        (graceful && gr.restart_time > 0 && !families.is_empty()).then(|| Retain {
            restart_time: Duration::from_secs(gr.restart_time.into()),
            families,
        })
    }
}

/// RFC 6608: FSM Error with the state as subcode and the type of the
/// unexpected message as data.
fn unexpected_message(state: State, kind: MessageType) -> Notification {
    let subcode = match state {
        State::OpenSent => 1,
        State::OpenConfirm => 2,
        _ => 3,
    };
    Notification::new(
        error_code::FSM,
        subcode,
        Bytes::copy_from_slice(&[kind as u8]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOLD: u16 = 90;

    fn config() -> SessionConfig {
        SessionConfig {
            local_asn: 64500,
            router_id: Ipv4Addr::new(203, 0, 113, 1),
            peer_asn: 64501,
            hold_time: HOLD,
            connect_retry: Duration::from_secs(10),
            max_connect_retry: Duration::from_secs(60),
            jitter: false,
            passive: false,
            graceful_restart: None,
        }
    }

    #[test]
    fn reconnects_back_off_and_reset_when_established() {
        let mut h = Harness::new();
        h.event(Event::Start);
        let mut delays = Vec::new();
        for _ in 0..5 {
            h.event(Event::TcpFailed);
            let delay = h.fsm.next_deadline().unwrap() - h.now;
            delays.push(delay.as_secs());
            h.advance(delay);
        }
        assert_eq!(delays, [10, 20, 40, 60, 60]);

        // Established resets the backoff.
        h.event(Event::TcpConnected);
        h.event(Event::Message(peer_open(64501, HOLD, dual_stack())));
        h.event(Event::Message(Message::Keepalive));
        assert_eq!(h.fsm.state(), State::Established);
        // The peer shuts us down administratively: next try after 10 s, then 20 s.
        let n = Notification::admin_shutdown("maintenance");
        h.event(Event::Message(Message::Notification(n)));
        assert_eq!(h.fsm.next_deadline(), Some(h.now + Duration::from_secs(10)));
        h.advance(Duration::from_secs(10));
        h.event(Event::TcpFailed);
        assert_eq!(h.fsm.next_deadline(), Some(h.now + Duration::from_secs(20)));
    }

    /// Delays before the next connect after each of five failed attempts,
    /// where `fail` makes the attempt (already connecting) fail.
    fn delays_after(fail: impl Fn(&mut Harness)) -> Vec<u64> {
        let mut h = Harness::new();
        h.event(Event::Start);
        let mut delays = Vec::new();
        for _ in 0..5 {
            fail(&mut h);
            assert_eq!(h.fsm.state(), State::Idle);
            let delay = h.fsm.next_deadline().unwrap() - h.now;
            delays.push(delay.as_secs());
            assert_eq!(h.advance(delay), [Action::Connect]);
        }
        delays
    }

    #[test]
    fn peer_closing_before_established_backs_off() {
        // An FRR neighbor in shutdown accepts TCP and closes.
        let delays = delays_after(|h| {
            h.event(Event::TcpConnected);
            h.event(Event::TcpClosed);
        });
        assert_eq!(delays, [10, 20, 40, 60, 60]);
    }

    #[test]
    fn our_notification_before_established_backs_off() {
        // Wrong AS configured, we send Bad Peer AS each time.
        let delays = delays_after(|h| {
            h.event(Event::TcpConnected);
            let out = h.event(Event::Message(peer_open(64999, HOLD, dual_stack())));
            assert!(out.contains(&Action::Down(DownReason::Sent(
                DecodeError::BadPeerAs(64999).notification()
            ))));
        });
        assert_eq!(delays, [10, 20, 40, 60, 60]);
    }

    #[test]
    fn damping_cease_before_established_doubles_once() {
        // Both reasons apply; the delay must double, not quadruple.
        let delays = delays_after(|h| {
            h.event(Event::TcpConnected);
            let n = Notification::admin_shutdown("not now");
            h.event(Event::Message(Message::Notification(n)));
        });
        assert_eq!(delays, [10, 20, 40, 60, 60]);
    }

    #[test]
    fn session_lost_after_established_retries_at_connect_retry() {
        let mut h = Harness::new();
        h.establish(HOLD);
        h.event(Event::TcpClosed);
        assert_eq!(h.fsm.next_deadline(), Some(h.now + Duration::from_secs(10)));
        // Not damped: a single loss does not slow the next session down.
        assert_eq!(h.fsm.backoff(), Duration::from_secs(10));
    }

    fn peer_open(asn: u32, hold_time: u16, capabilities: Vec<Capability>) -> Message {
        Message::Open(Open::new(
            asn,
            hold_time,
            Ipv4Addr::new(203, 0, 113, 2),
            capabilities,
        ))
    }

    fn dual_stack() -> Vec<Capability> {
        vec![
            Capability::Multiprotocol {
                afi: Afi::IPV4,
                safi: Safi::UNICAST,
            },
            Capability::Multiprotocol {
                afi: Afi::IPV6,
                safi: Safi::UNICAST,
            },
            Capability::RouteRefresh,
        ]
    }

    struct Harness {
        fsm: Fsm,
        now: Instant,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                fsm: Fsm::new(config()),
                now: Instant::now(),
            }
        }

        fn event(&mut self, event: Event) -> Vec<Action> {
            let mut out = Vec::new();
            self.fsm.handle(event, self.now, &mut out);
            out
        }

        fn advance(&mut self, by: Duration) -> Vec<Action> {
            self.now += by;
            let mut out = Vec::new();
            self.fsm.on_timeout(self.now, &mut out);
            out
        }

        /// Drives the session to Established with a dual-stack peer.
        fn establish(&mut self, peer_hold: u16) -> PeerInfo {
            assert_eq!(self.event(Event::Start), [Action::Connect]);
            let out = self.event(Event::TcpConnected);
            assert!(matches!(&out[..], [Action::Send(Message::Open(_))]));
            assert_eq!(self.fsm.state(), State::OpenSent);
            let out = self.event(Event::Message(peer_open(64501, peer_hold, dual_stack())));
            assert_eq!(out, [Action::Send(Message::Keepalive)]);
            assert_eq!(self.fsm.state(), State::OpenConfirm);
            let mut out = self.event(Event::Message(Message::Keepalive));
            assert_eq!(self.fsm.state(), State::Established);
            let Some(Action::Up(info)) = out.pop() else {
                panic!("expected Up, got {out:?}");
            };
            info
        }
    }

    fn sent_notification(out: &[Action]) -> Option<(u8, u8)> {
        out.iter().find_map(|a| match a {
            Action::Send(Message::Notification(n)) => Some((n.code, n.subcode)),
            _ => None,
        })
    }

    #[test]
    fn our_open() {
        let mut h = Harness::new();
        h.event(Event::Start);
        let out = h.event(Event::TcpConnected);
        let [Action::Send(Message::Open(open))] = &out[..] else {
            panic!("expected OPEN, got {out:?}");
        };
        assert_eq!(open.asn(), 64500);
        assert_eq!(open.hold_time, HOLD);
        assert!(open.capabilities.contains(&Capability::FourOctetAs(64500)));
    }

    #[test]
    fn establishes_and_negotiates() {
        let mut h = Harness::new();
        let info = h.establish(30);
        assert_eq!(info.asn, 64501);
        assert_eq!(info.hold_time, 30, "smaller hold time wins");
        assert!(info.negotiated.four_octet_as);
        assert!(!info.negotiated.extended_message, "peer did not offer it");
        assert!(info.route_refresh);
        assert_eq!(
            info.families,
            [(Afi::IPV4, Safi::UNICAST), (Afi::IPV6, Safi::UNICAST)]
        );
    }

    #[test]
    fn keepalives_and_hold_timer() {
        let mut h = Harness::new();
        h.establish(30);

        // Keepalive every hold/3 = 10 s.
        assert_eq!(
            h.advance(Duration::from_secs(10)),
            [Action::Send(Message::Keepalive)]
        );
        assert_eq!(
            h.advance(Duration::from_secs(10)),
            [Action::Send(Message::Keepalive)]
        );

        // A received keepalive restarts the hold timer.
        h.event(Event::Message(Message::Keepalive));
        h.advance(Duration::from_secs(10));
        h.advance(Duration::from_secs(10));
        assert_eq!(h.fsm.state(), State::Established);

        // 30 s since the last received keepalive.
        let out = h.advance(Duration::from_secs(10));
        assert_eq!(
            sent_notification(&out),
            Some((error_code::HOLD_TIMER_EXPIRED, 0))
        );
        assert!(out.contains(&Action::Close));
        assert_eq!(h.fsm.state(), State::Idle);
    }

    #[test]
    fn hold_time_zero_disables_timers() {
        let mut h = Harness::new();
        h.establish(0);
        assert_eq!(h.fsm.next_deadline(), None);
    }

    #[test]
    fn wrong_peer_as_then_retry() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        let out = h.event(Event::Message(peer_open(64999, HOLD, dual_stack())));
        assert_eq!(sent_notification(&out), Some((error_code::OPEN_MESSAGE, 2)));
        assert!(out.contains(&Action::Close));
        assert_eq!(h.fsm.state(), State::Idle);

        assert_eq!(h.fsm.next_deadline(), Some(h.now + Duration::from_secs(10)));
        assert_eq!(h.advance(Duration::from_secs(10)), [Action::Connect]);
    }

    #[test]
    fn connect_failure_retries() {
        let mut h = Harness::new();
        h.event(Event::Start);
        assert_eq!(h.event(Event::TcpFailed), []);
        assert_eq!(h.fsm.state(), State::Idle);
        assert_eq!(h.advance(Duration::from_secs(9)), []);
        assert_eq!(h.advance(Duration::from_secs(1)), [Action::Connect]);
    }

    #[test]
    fn stop_sends_cease_and_stays_down() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let out = h.event(Event::Stop(Notification::admin_shutdown(
            "herald shutting down",
        )));
        assert_eq!(
            sent_notification(&out),
            Some((error_code::CEASE, cease_subcode::ADMINISTRATIVE_SHUTDOWN))
        );
        assert!(out.contains(&Action::Down(DownReason::Stopped)));
        assert_eq!(h.fsm.next_deadline(), None, "no reconnect after stop");
    }

    fn sent_data(out: &[Action]) -> Bytes {
        out.iter()
            .find_map(|a| match a {
                Action::Send(Message::Notification(n)) => Some(n.data.clone()),
                _ => None,
            })
            .expect("a NOTIFICATION was sent")
    }

    #[test]
    fn unexpected_message_is_fsm_error() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        let out = h.event(Event::Message(Message::Update(Update::default())));
        assert_eq!(sent_notification(&out), Some((error_code::FSM, 1)));
        // RFC 6608: the data is the type of the unexpected message.
        assert_eq!(&sent_data(&out)[..], &[MessageType::Update as u8]);
    }

    #[test]
    fn broken_message_of_unexpected_type_is_fsm_error() {
        // RFC 4271 §8.2.2: UpdateMsgErr in OpenSent.
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        let out = h.event(Event::Malformed {
            kind: Some(MessageType::Update),
            error: DecodeError::MalformedAttributeList,
        });
        assert_eq!(sent_notification(&out), Some((error_code::FSM, 1)));
        assert_eq!(&sent_data(&out)[..], &[2]);

        // BGPOpenMsgErr in Established.
        let mut h = Harness::new();
        h.establish(HOLD);
        let out = h.event(Event::Malformed {
            kind: Some(MessageType::Open),
            error: DecodeError::UnsupportedVersion(3),
        });
        assert_eq!(sent_notification(&out), Some((error_code::FSM, 3)));
        assert_eq!(&sent_data(&out)[..], &[1]);

        // A broken UPDATE in Established keeps its own error code.
        let mut h = Harness::new();
        h.establish(HOLD);
        let out = h.event(Event::Malformed {
            kind: Some(MessageType::Update),
            error: DecodeError::MalformedAttributeList,
        });
        assert_eq!(
            sent_notification(&out),
            Some((error_code::UPDATE_MESSAGE, 1))
        );
    }

    #[test]
    fn oversized_notification_is_truncated_not_dropped() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let attr = Bytes::from(vec![0u8; 5000]);
        let out = h.event(Event::Malformed {
            kind: Some(MessageType::Update),
            error: DecodeError::AttributeLength(attr),
        });
        // 19 header + 2 code/subcode + data <= 4096 (RFC 8654 §5).
        assert_eq!(sent_data(&out).len(), 4096 - 21);
    }

    #[test]
    fn sending_an_update_restarts_the_keepalive_timer() {
        let mut h = Harness::new();
        h.establish(30);
        h.advance(Duration::from_secs(5));
        h.fsm.update_sent(h.now);
        // The keepalive is now due 10 s after the UPDATE, not after Established.
        assert_eq!(h.advance(Duration::from_secs(5)), []);
        assert_eq!(
            h.advance(Duration::from_secs(5)),
            [Action::Send(Message::Keepalive)]
        );
    }

    #[test]
    fn jitter_shortens_timers_by_up_to_a_quarter() {
        for _ in 0..50 {
            let mut fsm = Fsm::new(SessionConfig {
                jitter: true,
                ..config()
            });
            let now = Instant::now();
            let mut out = Vec::new();
            fsm.handle(Event::Start, now, &mut out);
            fsm.handle(Event::TcpFailed, now, &mut out);
            let delay = fsm.next_deadline().unwrap() - now;
            assert!(delay >= Duration::from_millis(7500) && delay <= Duration::from_secs(10));
        }
    }

    #[test]
    fn peer_notification_is_not_answered() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let n = Notification::admin_shutdown("bye");
        let out = h.event(Event::Message(Message::Notification(n.clone())));
        assert_eq!(out, [Action::Close, Action::Down(DownReason::Received(n))]);
    }

    #[test]
    fn ipv4_only_peer() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        // No Multiprotocol capability at all: IPv4 unicast implied.
        h.event(Event::Message(peer_open(64501, HOLD, vec![])));
        assert_eq!(h.fsm.peer().unwrap().families, [(Afi::IPV4, Safi::UNICAST)]);
    }

    #[test]
    fn teardown_uses_its_own_retry_delay() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let n = Notification::new(
            error_code::CEASE,
            cease_subcode::MAX_PREFIXES_REACHED,
            Bytes::new(),
        );
        let out = h.event(Event::Teardown {
            notification: n.clone(),
            retry_after: Duration::from_secs(300),
        });
        assert_eq!(out[0], Action::Send(Message::Notification(n)));
        assert_eq!(
            h.fsm.next_deadline(),
            Some(h.now + Duration::from_secs(300))
        );
        // The override is used once; the next failure uses connect_retry again.
        h.advance(Duration::from_secs(300));
        h.event(Event::TcpFailed);
        assert_eq!(h.fsm.next_deadline(), Some(h.now + Duration::from_secs(10)));
    }

    #[test]
    fn updates_are_passed_up() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let update = Update::end_of_rib(Afi::IPV6, Safi::UNICAST);
        let out = h.event(Event::Message(Message::Update(update.clone())));
        assert_eq!(out, [Action::Update(update)]);
    }

    // --- incoming connections (passive listen, RFC 4271 §6.8) ---------------

    fn open_from(bgp_id: Ipv4Addr) -> Message {
        Message::Open(Open::new(64501, HOLD, bgp_id, dual_stack()))
    }

    /// Our router ID is 203.0.113.1: a peer above it wins collisions.
    const HIGHER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
    const LOWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn cease_collision() -> Action {
        Action::Send(Message::Notification(Notification::new(
            error_code::CEASE,
            cease_subcode::CONNECTION_COLLISION_RESOLUTION,
            Bytes::new(),
        )))
    }

    fn is_open(action: &Action) -> bool {
        matches!(action, Action::Send(Message::Open(_)))
    }

    #[test]
    fn passive_waits_in_active_and_accepts() {
        let mut h = Harness::new();
        h.fsm = Fsm::new(SessionConfig {
            passive: true,
            ..config()
        });
        assert_eq!(h.event(Event::Start), []);
        assert_eq!(h.fsm.state(), State::Active);
        assert_eq!(h.fsm.next_deadline(), None, "no connect timer");

        let out = h.event(Event::Incoming);
        assert_eq!(out[0], Action::AcceptParked);
        assert!(is_open(&out[1]));
        assert_eq!(h.fsm.state(), State::OpenSent);
        assert!(!h.fsm.outbound());

        // The session fails: back to Active at once, no timer.
        h.event(Event::TcpClosed);
        assert_eq!(h.fsm.state(), State::Active);
        assert_eq!(h.fsm.next_connect(), None);
    }

    #[test]
    fn incoming_while_connecting_replaces_our_attempt() {
        let mut h = Harness::new();
        h.event(Event::Start);
        assert_eq!(h.fsm.state(), State::Connect);
        let out = h.event(Event::Incoming);
        assert_eq!(out[..2], [Action::Close, Action::AcceptParked]);
        assert!(is_open(&out[2]));
        assert_eq!(h.fsm.state(), State::OpenSent);
    }

    #[test]
    fn incoming_while_waiting_to_reconnect_is_accepted() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpFailed);
        assert_eq!(h.fsm.state(), State::Idle);
        let out = h.event(Event::Incoming);
        assert_eq!(out[0], Action::AcceptParked);
        assert_eq!(h.fsm.next_connect(), None, "the retry timer is cancelled");
    }

    #[test]
    fn collision_peer_with_higher_id_wins() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        // Parked until we know the peer's BGP Identifier.
        assert_eq!(h.event(Event::Incoming), []);
        let out = h.event(Event::Message(open_from(HIGHER)));
        assert_eq!(out[0], Action::Send(Message::Keepalive));
        assert_eq!(
            out[1..4],
            [cease_collision(), Action::Close, Action::AcceptParked]
        );
        assert!(is_open(&out[4]));
        assert!(
            !out.iter().any(|a| matches!(a, Action::Down(_))),
            "no session went down"
        );
        assert_eq!(h.fsm.state(), State::OpenSent);
        assert!(!h.fsm.outbound());
        assert_eq!(h.fsm.backoff(), config().connect_retry, "no backoff");

        // The handshake finishes on the peer's connection.
        h.event(Event::Message(open_from(HIGHER)));
        let out = h.event(Event::Message(Message::Keepalive));
        assert!(matches!(out[..], [Action::Up(_)]));
    }

    #[test]
    fn collision_we_win_with_higher_id() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        h.event(Event::Message(open_from(LOWER)));
        assert_eq!(h.fsm.state(), State::OpenConfirm);
        // Decided at once: we already know the identifier.
        let out = h.event(Event::Incoming);
        assert_eq!(
            out,
            [Action::RejectParked {
                reason: RejectReason::Collision
            }]
        );
        assert_eq!(h.fsm.state(), State::OpenConfirm);
        assert!(h.fsm.outbound());
        let out = h.event(Event::Message(Message::Keepalive));
        assert!(matches!(out[..], [Action::Up(_)]));
    }

    #[test]
    fn equal_ids_compare_as_numbers() {
        // RFC 6286 §2.3: eBGP peers may share an identifier; the higher AS wins.
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        h.event(Event::Message(open_from(config().router_id)));
        let out = h.event(Event::Incoming);
        assert_eq!(
            out[..2],
            [cease_collision(), Action::Close],
            "64501 > 64500"
        );
    }

    #[test]
    fn established_rejects_incoming() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let out = h.event(Event::Incoming);
        assert_eq!(
            out,
            [Action::RejectParked {
                reason: RejectReason::Established
            }]
        );
        assert_eq!(h.fsm.state(), State::Established);
    }

    #[test]
    fn our_connection_fails_while_the_peers_waits() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        h.event(Event::Incoming);
        let out = h.event(Event::TcpClosed);
        let accept = out.iter().position(|a| *a == Action::AcceptParked);
        let close = out.iter().position(|a| *a == Action::Close);
        assert!(close < accept && accept.is_some(), "{out:?}");
        assert!(is_open(out.last().unwrap()));
        assert_eq!(h.fsm.state(), State::OpenSent);
        assert_eq!(h.fsm.next_connect(), None);
    }

    #[test]
    fn second_incoming_replaces_the_first() {
        let mut h = Harness::new();
        h.fsm = Fsm::new(SessionConfig {
            passive: true,
            ..config()
        });
        h.event(Event::Start);
        h.event(Event::Incoming);
        let out = h.event(Event::Incoming);
        assert_eq!(
            out[..3],
            [cease_collision(), Action::Close, Action::AcceptParked]
        );
    }

    #[test]
    fn stop_rejects_parked() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        h.event(Event::Incoming);
        let out = h.event(Event::Stop(Notification::admin_shutdown(
            "herald shutting down",
        )));
        assert_eq!(
            out[0],
            Action::RejectParked {
                reason: RejectReason::NotAccepting
            }
        );
        assert!(!out.contains(&Action::AcceptParked));
        assert_eq!(h.fsm.state(), State::Idle);
        let out = h.event(Event::Incoming);
        assert!(matches!(out[..], [Action::RejectParked { .. }]));
    }

    #[test]
    fn max_prefix_teardown_refuses_incoming_until_the_restart() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let retry = Duration::from_secs(300);
        h.event(Event::Teardown {
            notification: Notification::new(error_code::CEASE, 1, Bytes::new()),
            retry_after: retry,
        });
        let out = h.event(Event::Incoming);
        assert_eq!(
            out,
            [Action::RejectParked {
                reason: RejectReason::NotAccepting
            }]
        );
        let out = h.advance(retry);
        assert_eq!(out, [Action::Connect]);
        let out = h.event(Event::Incoming);
        assert_eq!(out[..2], [Action::Close, Action::AcceptParked]);
    }

    // --- operator commands ---------------------------------------------------

    #[test]
    fn disable_sends_the_reason_and_stays_down_until_enabled() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let out = h.event(Event::Disable {
            reason: "maintenance".into(),
        });
        let n = Notification::admin_shutdown("maintenance");
        assert_eq!(out[0], Action::Send(Message::Notification(n.clone())));
        assert!(out.contains(&Action::Down(DownReason::Admin(n))));
        assert!(h.fsm.disabled());
        assert_eq!(h.fsm.state(), State::Idle);
        assert_eq!(h.fsm.next_deadline(), None, "no reconnect");
        assert_eq!(h.advance(Duration::from_secs(3600)), []);
        // Incoming connections are refused while disabled.
        assert!(matches!(
            h.event(Event::Incoming)[..],
            [Action::RejectParked { .. }]
        ));

        assert_eq!(h.event(Event::Start), [Action::Connect]);
        assert!(!h.fsm.disabled());
    }

    #[test]
    fn reset_reconnects_at_once_without_backoff() {
        let mut h = Harness::new();
        h.establish(HOLD);
        let out = h.event(Event::Reset);
        assert_eq!(sent_notification(&out), Some((6, 4)));
        assert!(matches!(
            out.last(),
            Some(Action::Down(DownReason::Admin(_)))
        ));
        assert_eq!(h.fsm.next_deadline(), Some(h.now));
        assert_eq!(h.advance(Duration::ZERO), [Action::Connect]);
        assert_eq!(h.fsm.backoff(), config().connect_retry);
        assert!(!h.fsm.disabled());
    }

    #[test]
    fn reset_while_waiting_connects_now() {
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpFailed);
        h.event(Event::TcpConnected); // ignored in Idle
        assert_eq!(h.event(Event::Reset), [Action::Connect]);
        // Disabled peers stay down.
        h.event(Event::Disable { reason: "x".into() });
        assert_eq!(h.event(Event::Reset), []);
    }

    #[test]
    fn reset_on_a_passive_neighbor_waits_for_it() {
        let mut h = Harness::new();
        h.fsm = Fsm::new(SessionConfig {
            passive: true,
            ..config()
        });
        h.event(Event::Start);
        h.event(Event::Incoming);
        h.event(Event::Message(open_from(HIGHER)));
        h.event(Event::Message(Message::Keepalive));
        assert_eq!(h.fsm.state(), State::Established);
        let out = h.event(Event::Reset);
        assert_eq!(sent_notification(&out), Some((6, 4)));
        assert_eq!(h.fsm.state(), State::Active);
        assert_eq!(h.fsm.next_deadline(), None);
    }

    fn gr_cap(notification: bool, forwarding: bool) -> Capability {
        Capability::GracefulRestart(GracefulRestart {
            restarting: false,
            notification,
            restart_time: 120,
            families: [Afi::IPV4, Afi::IPV6]
                .map(|afi| GrFamily {
                    afi,
                    safi: Safi::UNICAST,
                    forwarding,
                })
                .to_vec(),
        })
    }

    /// Established with Graceful Restart on our side (30 s) and the peer
    /// sending `peer_caps` on top of the dual-stack ones.
    fn gr_established(peer_caps: Vec<Capability>) -> (Harness, PeerInfo) {
        let mut h = Harness::new();
        h.fsm = Fsm::new(SessionConfig {
            graceful_restart: Some(30),
            ..config()
        });
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        let mut caps = dual_stack();
        caps.extend(peer_caps);
        h.event(Event::Message(peer_open(64501, HOLD, caps)));
        let mut out = h.event(Event::Message(Message::Keepalive));
        let Some(Action::Up(info)) = out.pop() else {
            panic!("expected Up, got {out:?}");
        };
        (h, info)
    }

    fn our_gr(open: &Message) -> Option<GracefulRestart> {
        let Message::Open(open) = open else {
            panic!("not an OPEN: {open:?}");
        };
        open.capabilities.iter().find_map(|c| match c {
            Capability::GracefulRestart(gr) => Some(gr.clone()),
            _ => None,
        })
    }

    fn sent(out: &[Action]) -> Option<&Notification> {
        out.iter().find_map(|a| match a {
            Action::Send(Message::Notification(n)) => Some(n),
            _ => None,
        })
    }

    fn retained(out: &[Action]) -> Option<&Retain> {
        out.iter().find_map(|a| match a {
            Action::Retain(r) => Some(r),
            _ => None,
        })
    }

    #[test]
    fn graceful_restart_capability_and_r_bit() {
        // Off: no capability.
        let mut h = Harness::new();
        h.event(Event::Start);
        let out = h.event(Event::TcpConnected);
        let [Action::Send(open)] = &out[..] else {
            panic!("{out:?}")
        };
        assert_eq!(our_gr(open), None);

        // On: R set until the first session is up, N always, F for both families.
        let (mut h, info) = gr_established(vec![gr_cap(true, true)]);
        let gr = info.graceful_restart.expect("negotiated");
        assert_eq!(gr.restart_time, 120);
        assert!(gr.notification);
        h.event(Event::TcpClosed);
        let out = h.advance(Duration::from_secs(10));
        assert_eq!(out, [Action::Connect]);
        let out = h.event(Event::TcpConnected);
        let [Action::Send(open)] = &out[..] else {
            panic!("{out:?}")
        };
        let ours = our_gr(open).expect("sent");
        assert!(!ours.restarting, "R only before the first session");
        assert!(ours.notification);
        assert_eq!(ours.restart_time, 30);
        assert!(ours.families.iter().all(|f| f.forwarding));
        assert_eq!(ours.families.len(), 2);

        let mut fresh = Fsm::new(SessionConfig {
            graceful_restart: Some(30),
            ..config()
        });
        let mut out = Vec::new();
        let now = Instant::now();
        fresh.handle(Event::Start, now, &mut out);
        out.clear();
        fresh.handle(Event::TcpConnected, now, &mut out);
        assert!(
            our_gr(match &out[0] {
                Action::Send(m) => m,
                other => panic!("{other:?}"),
            })
            .unwrap()
            .restarting
        );

        // The peer without it, or we without it: not negotiated.
        let (_, info) = gr_established(vec![]);
        assert_eq!(info.graceful_restart, None);
        let mut h = Harness::new();
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        let mut caps = dual_stack();
        caps.push(gr_cap(true, true));
        h.event(Event::Message(peer_open(64501, HOLD, caps)));
        let mut out = h.event(Event::Message(Message::Keepalive));
        let Some(Action::Up(info)) = out.pop() else {
            panic!()
        };
        assert_eq!(info.graceful_restart, None);
        // What the peer offers is known anyway.
        let offered = info.offered_graceful_restart.expect("recorded");
        assert_eq!(offered.restart_time, 120);
        assert!(offered.notification);
    }

    #[test]
    fn lost_connection_keeps_the_peers_routes() {
        let (mut h, _) = gr_established(vec![gr_cap(false, true)]);
        let out = h.event(Event::TcpClosed);
        let retain = retained(&out).expect("kept");
        assert_eq!(retain.restart_time, Duration::from_secs(120));
        assert_eq!(
            retain.families,
            [(Afi::IPV4, Safi::UNICAST), (Afi::IPV6, Safi::UNICAST)]
        );
        // Retain comes right before Down.
        let i = out
            .iter()
            .position(|a| matches!(a, Action::Retain(_)))
            .unwrap();
        assert_eq!(out[i + 1], Action::Down(DownReason::ConnectionClosed));

        // Without the N bit any NOTIFICATION ends Graceful Restart (RFC 4724).
        let (mut h, _) = gr_established(vec![gr_cap(false, true)]);
        let n = Notification::new(
            error_code::CEASE,
            cease_subcode::OUT_OF_RESOURCES,
            Bytes::new(),
        );
        let out = h.event(Event::Message(Message::Notification(n)));
        assert_eq!(retained(&out), None);
        let (mut h, _) = gr_established(vec![gr_cap(false, true)]);
        let out = h.advance(Duration::from_secs(u64::from(HOLD)));
        assert_eq!(
            sent_notification(&out),
            Some((error_code::HOLD_TIMER_EXPIRED, 0))
        );
        assert_eq!(retained(&out), None);

        // Families only the peer keeps routes for: our negotiated ones only.
        let mut h = Harness::new();
        h.fsm = Fsm::new(SessionConfig {
            graceful_restart: Some(30),
            ..config()
        });
        h.event(Event::Start);
        h.event(Event::TcpConnected);
        let caps = vec![
            Capability::Multiprotocol {
                afi: Afi::IPV4,
                safi: Safi::UNICAST,
            },
            gr_cap(false, true),
        ];
        h.event(Event::Message(peer_open(64501, HOLD, caps)));
        h.event(Event::Message(Message::Keepalive));
        let out = h.event(Event::TcpClosed);
        assert_eq!(
            retained(&out).unwrap().families,
            [(Afi::IPV4, Safi::UNICAST)]
        );
    }

    #[test]
    fn n_bit_keeps_routes_except_on_hard_reset() {
        // RFC 8538: any NOTIFICATION but Hard Reset keeps them, both ways.
        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let n = Notification::admin_shutdown("peer restarting");
        let out = h.event(Event::Message(Message::Notification(n)));
        assert!(retained(&out).is_some());

        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let out = h.advance(Duration::from_secs(u64::from(HOLD)));
        assert!(
            retained(&out).is_some(),
            "hold timer expiry is graceful with N"
        );

        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let hard = Notification::hard_reset(&Notification::admin_shutdown("bye"));
        let out = h.event(Event::Message(Message::Notification(hard)));
        assert_eq!(retained(&out), None);
    }

    #[test]
    fn stopping_sends_hard_reset_with_the_n_bit() {
        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let out = h.event(Event::Stop(Notification::admin_shutdown(
            "herald shutting down",
        )));
        let n = sent(&out).unwrap();
        assert!(n.is_hard_reset());
        assert_eq!(n.shutdown_text().as_deref(), Some("herald shutting down"));
        assert_eq!(retained(&out), None, "stopping drops the peer's routes");

        // Disable, reset and max-prefix too; other Ceases stay graceful.
        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let out = h.event(Event::Disable {
            reason: "maintenance".into(),
        });
        assert!(sent(&out).unwrap().is_hard_reset());
        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let out = h.event(Event::Reset);
        assert_eq!(
            sent(&out).unwrap().hard_reset_inner().map(|n| n.subcode),
            Some(cease_subcode::ADMINISTRATIVE_RESET)
        );
        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let max = Notification::new(
            error_code::CEASE,
            cease_subcode::MAX_PREFIXES_REACHED,
            Bytes::new(),
        );
        let out = h.event(Event::Teardown {
            notification: max,
            retry_after: Duration::from_secs(60),
        });
        assert!(sent(&out).unwrap().is_hard_reset());
        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let change = Notification::new(
            error_code::CEASE,
            cease_subcode::OTHER_CONFIGURATION_CHANGE,
            Bytes::new(),
        );
        let out = h.event(Event::Stop(change.clone()));
        assert_eq!(sent(&out), Some(&change));

        // Without the N bit a plain Cease.
        let (mut h, _) = gr_established(vec![gr_cap(false, true)]);
        let out = h.event(Event::Stop(Notification::admin_shutdown("x")));
        assert_eq!(sent_notification(&out), Some((6, 2)));
    }

    #[test]
    fn restart_lets_the_peer_keep_our_routes() {
        // N bit: Administrative Shutdown, not a Hard Reset.
        let (mut h, _) = gr_established(vec![gr_cap(true, true)]);
        let out = h.event(Event::Restart);
        let n = sent(&out).unwrap();
        assert!(!n.is_hard_reset());
        assert_eq!(n.shutdown_text().as_deref(), Some(RESTART_TEXT));
        assert!(out.contains(&Action::Down(DownReason::Restart)));
        assert_eq!(h.fsm.state(), State::Idle);
        assert_eq!(h.fsm.next_deadline(), None, "no reconnect");

        // Graceful Restart without N: no NOTIFICATION at all.
        let (mut h, _) = gr_established(vec![gr_cap(false, true)]);
        let out = h.event(Event::Restart);
        assert_eq!(sent(&out), None);
        assert!(out.contains(&Action::Close));
        assert!(out.contains(&Action::Down(DownReason::Restart)));

        // No Graceful Restart with this peer: like a stop.
        let (mut h, _) = gr_established(vec![]);
        let out = h.event(Event::Restart);
        assert_eq!(sent_notification(&out), Some((6, 2)));
        assert!(out.contains(&Action::Down(DownReason::Stopped)));
    }
}
