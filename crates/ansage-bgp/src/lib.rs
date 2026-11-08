//! BGP-4 (RFC 4271) without I/O: the wire format and the session state
//! machine.
//!
//! - [`wire`] decodes and encodes messages (OPEN, UPDATE, NOTIFICATION,
//!   KEEPALIVE, ROUTE-REFRESH) for IPv4 and IPv6 unicast, with 4-octet AS
//!   numbers, extended messages, graceful restart and RFC 7606 error handling.
//! - [`session`] is the finite state machine: events and the current time go
//!   in, actions come out. Sockets and timers stay with the caller.
//!
//! The optional `serde` feature derives `Serialize` for the session state.
//!
//! # Building and reading an UPDATE
//!
//! ```
//! use std::net::Ipv4Addr;
//!
//! use ansage_bgp::wire::{self, AsPath, Message, Negotiated, NextHop, Origin, PathAttr, Prefix};
//! use bytes::BytesMut;
//!
//! let neg = Negotiated {
//!     four_octet_as: true,
//!     ..Negotiated::default()
//! };
//! let attrs = [
//!     PathAttr::Origin(Origin::Igp),
//!     PathAttr::AsPath(AsPath::sequence([64500])),
//! ];
//! let next_hop = NextHop::V4(Ipv4Addr::new(192, 0, 2, 1));
//! let prefixes: Vec<Prefix> = vec!["198.51.100.0/24".parse()?, "203.0.113.0/24".parse()?];
//!
//! // As few UPDATEs as fit the negotiated message size.
//! let mut buf = BytesMut::new();
//! let messages = wire::pack::announce(&mut buf, &neg, &attrs, Some(&next_hop), &prefixes)?;
//! assert_eq!(messages, 1);
//!
//! // What a receiver does with the bytes from its socket.
//! while let Some((kind, body)) = wire::split_message(&mut buf, neg.max_message_len())? {
//!     let Message::Update(update) = Message::decode(kind, body, &neg)? else {
//!         panic!("not an UPDATE");
//!     };
//!     assert_eq!(update.nlri.len(), 2);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Driving a session
//!
//! ```
//! use std::time::{Duration, Instant};
//!
//! use ansage_bgp::session::{Action, Event, Fsm, SessionConfig, State};
//!
//! let mut fsm = Fsm::new(SessionConfig {
//!     local_asn: 64500,
//!     router_id: "192.0.2.1".parse()?,
//!     peer_asn: 64501,
//!     hold_time: 90,
//!     connect_retry: Duration::from_secs(5),
//!     max_connect_retry: Duration::from_secs(120),
//!     jitter: true,
//!     passive: false,
//!     graceful_restart: None,
//! });
//! let mut actions = Vec::new();
//! fsm.handle(Event::Start, Instant::now(), &mut actions);
//! // The caller opens the TCP connection and reports back with
//! // `Event::TcpConnected` or `Event::TcpFailed`; the FSM then asks to send
//! // its OPEN. Timers: sleep until `fsm.next_deadline()`, then call
//! // `fsm.on_timeout(now, &mut actions)`.
//! assert!(actions.iter().any(|a| matches!(a, Action::Connect)));
//! assert_eq!(fsm.state(), State::Connect);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod session;
pub mod wire;
