//! What goes in and out of the RIB: messages, settings and query answers.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use crate::config::Config;

use crate::config::ExportPolicy;

use crate::config::ImportPolicy;

use crate::config::Kernel;

use crate::config::Neighbor;

use ansage_bgp::session::PeerInfo;

use ansage_bgp::session::Retain;

use ansage_bgp::wire::Afi;

use ansage_bgp::wire::NextHop;

use ansage_bgp::wire::Notification;

use ansage_bgp::wire::PathAttr;

use ansage_bgp::wire::Prefix;

use ansage_bgp::wire::Safi;

use ansage_bgp::wire::Update;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use super::table::SourceId;
use crate::fib::Gateway;

/// From a peer task to the RIB; in order per peer.
// Update is the common case; boxing it would cost an allocation per UPDATE
// to save about 200 KB in a 1024-slot channel.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RibMsg {
    Up(Box<PeerUp>),
    Update {
        peer: SourceId,
        update: Update,
    },
    RouteRefresh {
        peer: SourceId,
        afi: Afi,
        safi: Safi,
    },
    /// The peer can take another export batch.
    Ready {
        peer: SourceId,
    },
    Down {
        peer: SourceId,
        /// Keep the peer's routes of these families as stale.
        retain: Option<Retain>,
    },
    /// From the control socket.
    Query(Query),
    /// Settings for a peer ID (config reload); None forgets them. Sent
    /// before the peer task starts, so they apply from its first session.
    PeerSettings {
        peer: SourceId,
        settings: Option<PeerSettings>,
    },
    /// New `max_prefix_restart` (config reload).
    MaxPrefixRestart(Duration),
    /// Our own prefixes changed at runtime (control socket).
    Own {
        /// true: announce, false: withdraw.
        announce: bool,
        prefixes: Vec<Prefix>,
        reply: oneshot::Sender<OwnChange>,
    },
    /// Start (true) or end a drain (RFC 8326): our own routes go out with
    /// GRACEFUL_SHUTDOWN, LOCAL_PREF 0 on iBGP and `drain_prepend` extra
    /// prepends on eBGP, so neighbors move traffic elsewhere first.
    Drain {
        drained: bool,
        reply: oneshot::Sender<DrainChange>,
    },
    /// The FIB task can take another batch.
    FibReady,
    /// Which families go into the kernel (config reload): `[ipv4, ipv6]`.
    InstallFamilies([bool; 2]),
    /// From the FIB task: these next hops became unreachable (false) or
    /// reachable again (true).
    NextHops(Vec<(Gateway, bool)>),
}

/// What a drain or undrain did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainChange {
    /// false: it already was in that state.
    pub changed: bool,
    /// When the current drain began; None when not drained.
    pub since: Option<Instant>,
}

/// What a runtime announce or withdraw did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnChange {
    pub changed: Vec<Prefix>,
    /// Already announced (announce) or not announced (withdraw).
    pub unchanged: Vec<Prefix>,
}

#[derive(Debug)]
pub struct PeerUp {
    pub peer: SourceId,
    pub info: PeerInfo,
    pub addr: IpAddr,
    /// Our address on the session.
    pub local_addr: IpAddr,
    /// Our next hops for this session (configured, or our local address).
    pub next_hop_ipv4: Option<Ipv4Addr>,
    pub next_hop_ipv6: Option<Ipv6Addr>,
    /// Sent with the global IPv6 next hop when set (RFC 2545 §3).
    pub next_hop_ipv6_link_local: Option<Ipv6Addr>,
    /// Interface of the session when the neighbor is on a shared link: its
    /// link-local next hops are reached through it.
    pub oif: Option<u32>,
    pub tx: mpsc::Sender<PeerMsg>,
}

/// From the RIB to one peer task.
#[derive(Debug, PartialEq, Eq)]
pub enum PeerMsg {
    Export(ExportBatch),
    /// Close the session with `notification`, reconnect after `retry_after`.
    Teardown {
        notification: Notification,
        retry_after: Duration,
    },
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExportBatch {
    pub announce: Vec<Announce>,
    pub withdraw: Vec<Prefix>,
    /// Families whose initial table is complete with this batch.
    pub end_of_rib: Vec<Afi>,
}

impl ExportBatch {
    pub(super) fn is_empty(&self) -> bool {
        self.announce.is_empty() && self.withdraw.is_empty() && self.end_of_rib.is_empty()
    }
}

/// Prefixes that share the same outgoing attributes.
#[derive(Debug, PartialEq, Eq)]
pub struct Announce {
    /// Sorted by type code; carries NEXT_HOP when there are IPv4 prefixes.
    pub attrs: Vec<PathAttr>,
    /// For IPv6 prefixes (MP_REACH).
    pub next_hop: Option<NextHop>,
    pub prefixes: Vec<Prefix>,
}

#[derive(Debug, Clone)]
pub struct RibConfig {
    pub local_asn: u32,
    pub announce: Vec<Prefix>,
    pub max_prefix_restart: Duration,
    pub peers: HashMap<SourceId, PeerSettings>,
    /// Families installed into the kernel (`[ipv4, ipv6]`) once a FIB task
    /// is attached.
    pub install_families: [bool; 2],
}

impl RibConfig {
    pub fn new(config: &Config) -> Self {
        Self {
            local_asn: config.asn,
            announce: config.announce.clone(),
            max_prefix_restart: Duration::from_secs(config.max_prefix_restart),
            // Neighbors in config order, starting at 1 (0 is our own
            // prefixes); the daemon numbers its peer tasks the same way.
            peers: (1..)
                .zip(&config.neighbors)
                .map(|(id, n)| (id, PeerSettings::new(config, n)))
                .collect(),
            install_families: config
                .kernel
                .as_ref()
                .map_or([false; 2], Kernel::install_families),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerSettings {
    pub import: ImportPolicy,
    pub export: ExportPolicy,
    pub max_prefixes_ipv4: Option<u32>,
    pub max_prefixes_ipv6: Option<u32>,
    /// Extra prepends of our AS on our own routes while drained (eBGP).
    pub drain_prepend: u8,
    /// This neighbor's best routes go into the kernel (with `[kernel]`).
    pub install: bool,
}

impl PeerSettings {
    /// What the RIB needs to know about `neighbor`.
    pub fn new(config: &Config, neighbor: &Neighbor) -> Self {
        Self {
            import: neighbor.import,
            export: neighbor.export,
            max_prefixes_ipv4: neighbor.max_prefixes_ipv4,
            max_prefixes_ipv6: neighbor.max_prefixes_ipv6,
            drain_prepend: neighbor.drain_prepend,
            install: config.kernel.is_some() && neighbor.install.unwrap_or(true),
        }
    }
}

/// Questions about the RIB; each carries the channel for its answer.
#[derive(Debug)]
pub enum Query {
    Summary(oneshot::Sender<RibSummary>),
    /// All candidates of exactly this prefix, the best first.
    Prefix {
        prefix: Prefix,
        reply: oneshot::Sender<Vec<RouteInfo>>,
    },
    /// All candidates of the longest prefix containing `addr`.
    Longest {
        addr: IpAddr,
        reply: oneshot::Sender<Vec<RouteInfo>>,
    },
    /// Up to `limit` best routes of a family. The tables are hash maps, so
    /// this is a sample sorted by prefix, not a page of a stable order.
    Routes {
        afi: Afi,
        limit: usize,
        reply: oneshot::Sender<RoutePage>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RibSummary {
    pub stats: Stats,
    /// Our own prefixes.
    pub own: Vec<Prefix>,
    /// Peers with a session, by ID.
    pub peers: Vec<PeerRibStatus>,
    /// Since when we are drained (RFC 8326), if we are.
    pub drained: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PeerRibStatus {
    pub peer: SourceId,
    /// Routes stored from this peer.
    pub received_ipv4: u32,
    pub received_ipv6: u32,
    /// Adj-RIB-Out: prefixes we announced to this peer.
    pub advertised_ipv4: usize,
    pub advertised_ipv6: usize,
    /// Prefixes waiting to be (re)evaluated for this peer.
    pub pending: usize,
    /// End-of-RIB sent for every negotiated family.
    pub initial_sync_done: bool,
    /// Teardown for max-prefix sent, waiting for the session to go down.
    pub torn_down: bool,
    /// Routes kept through a Graceful Restart and not sent again yet.
    pub stale: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInfo {
    pub prefix: Prefix,
    /// The peer it came from; [`LOCAL`](super::LOCAL) for our own prefixes.
    pub source: SourceId,
    pub best: bool,
    pub attrs: Vec<PathAttr>,
    /// The MP_REACH next hop (IPv6 routes).
    pub mp_next_hop: Option<NextHop>,
    /// The kernel cannot reach its next hop (with `[kernel]`).
    pub unreachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePage {
    /// Best routes of the family in the RIB.
    pub total: usize,
    pub routes: Vec<RouteInfo>,
}

/// Route counts, for logs, tests and the control socket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub prefixes_ipv4: usize,
    pub prefixes_ipv6: usize,
    pub attr_sets: usize,
}
