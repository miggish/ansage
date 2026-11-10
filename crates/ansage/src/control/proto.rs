//! The control socket's line protocol: one JSON request per line, one JSON
//! reply per line, `{"ok": ...}` or `{"error": "..."}`.
//!
//! ```text
//! {"cmd":"summary"}
//! {"cmd":"peers"}                         every neighbor
//! {"cmd":"peers","peer":"10.0.0.1"}       by ID, address or address:port
//! {"cmd":"rib","prefix":"192.0.2.0/24"}   all candidates, best first
//! {"cmd":"rib","prefix":"192.0.2.77"}     the same for the longest match
//! {"cmd":"fib"}                           kernel routes ([kernel])
//! {"cmd":"rib","family":"ipv6","limit":50}
//! {"cmd":"rib","out":"10.0.0.1"}        what that neighbor was sent
//! {"cmd":"announce","prefixes":["192.0.2.0/24"]}   own prefixes, at runtime
//! {"cmd":"withdraw","prefixes":["192.0.2.0/24"]}
//! {"cmd":"peer","peer":"10.0.0.1","action":"disable","reason":"maintenance"}
//! {"cmd":"peer","peer":"10.0.0.1","action":"enable"}      also "reset"
//! {"cmd":"reload"}                       re-read the config file
//! {"cmd":"restart","dry_run":true}       what a restart would do per neighbor
//! {"cmd":"restart","force":false}        end the sessions so neighbors with
//!                                         Graceful Restart keep our routes, exit 75
//! {"cmd":"test","target":"203.0.113.0/24","from":"198.51.100.2","as_path":[64510]}
//!                                         what ansage would do with that route
//! {"cmd":"test","target":"192.0.2.77"}   the same for the route it has
//! ```
//! `"v":1` may be given; other versions are refused.
//!
//! Runtime changes are not written to the config: a restart (and a config
//! reload) goes back to what the file says.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ansage_bgp::session::State;

use ansage_bgp::wire::NextHop;

use ansage_bgp::wire::Origin;

use ansage_bgp::wire::PathAttr;

use ansage_bgp::wire::Prefix;

use ansage_bgp::wire::SegmentType;
use serde::{Deserialize, Serialize};

use crate::{
    config::{Community, LargeCommunityValue, NeighborRole},
    peer::status::{CounterSnapshot, NeighborInfo, PeerStatus, Timestamp},
    rib::{LOCAL, PeerRibStatus, RouteInfo, SourceId, Stats, TestQuery, TestRoute, Trace},
};

/// Protocol version spoken by this build.
pub const VERSION: u32 = 1;

/// A request line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(default = "version")]
    pub v: u32,
    #[serde(flatten)]
    pub request: Request,
}

fn version() -> u32 {
    VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum Request {
    Summary,
    Peers {
        /// Only neighbors matching this ID, address or address:port.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer: Option<String>,
    },
    Rib {
        /// All candidates of exactly this prefix, or of the longest prefix
        /// containing this address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        /// Best routes of one family; both when neither this nor `prefix`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        family: Option<Family>,
        /// At most this many routes per family (default 1000).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
        /// What this neighbor (ID, address or address:port) was sent, with
        /// the attributes it got, instead of the best routes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        out: Option<String>,
    },
    /// What ansage installed in the kernel.
    Fib,
    /// Announce our own prefixes.
    Announce {
        prefixes: Vec<String>,
    },
    /// Stop announcing our own prefixes.
    Withdraw {
        prefixes: Vec<String>,
    },
    /// Our own routes go out with GRACEFUL_SHUTDOWN (RFC 8326) until
    /// `undrain` or a restart.
    Drain,
    /// End a drain.
    Undrain,
    /// Re-read the config file and apply what changed.
    Reload,
    /// Exit for a restart (status 75) so that neighbors with Graceful
    /// Restart keep our routes. Refused when an Established neighbor would
    /// drop them (no Graceful Restart) or nothing would start ansage again
    /// (not under systemd), unless `force`.
    Restart {
        #[serde(default)]
        force: bool,
        /// Only report what would happen.
        #[serde(default)]
        dry_run: bool,
    },
    /// Panics, to test the panic hook (e2e); only when ansage runs with
    /// ANSAGE_CRASH_TEST=1 in its environment.
    Crash,

    /// What ansage does with one route, step by step (`ansage test`).
    Test(TestRequest),

    /// Disable, enable or reset one neighbor.
    Peer {
        /// ID, address or address:port; must match exactly one neighbor.
        peer: String,
        action: PeerAction,
        /// Shutdown text for `disable` (RFC 9003).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// `ansage test`: with `from`, a route that neighbor could send for the
/// prefix `target`; without, the route ansage has for `target` (a prefix, or
/// an address: the longest prefix containing it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestRequest {
    pub target: String,
    /// Neighbor address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Default: the neighbor's AS (empty over iBGP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_path: Option<Vec<u32>>,
    /// "asn:value".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub communities: Vec<String>,
    /// "global:data1:data2".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub large_communities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub med: Option<u32>,
    /// Default: the neighbor's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<String>,
    /// RFC 9234 Only-To-Customer, the AS that set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otc: Option<u32>,
}

impl TestRequest {
    /// The RIB's form of the request.
    pub fn query(&self) -> Result<TestQuery, String> {
        let target = self.target.trim();
        let Some(from) = &self.from else {
            if let Ok(prefix) = target.parse::<Prefix>() {
                return Ok(TestQuery::Prefix(prefix));
            }
            return match target.parse::<IpAddr>() {
                Ok(addr) => Ok(TestQuery::Address(addr)),
                Err(_) => Err(format!("{target:?} is neither a prefix nor an address")),
            };
        };
        let prefix = target
            .parse::<Prefix>()
            .map_err(|err| format!("prefix {target:?}: {err}"))?;
        let from = from
            .parse::<IpAddr>()
            .map_err(|_| format!("from: {from:?} is not an address"))?;
        let next_hop = match &self.next_hop {
            Some(addr) => Some(
                addr.parse::<IpAddr>()
                    .map_err(|_| format!("next hop {addr:?} is not an address"))?,
            ),
            None => None,
        };
        let communities = self
            .communities
            .iter()
            .map(|c| Community::try_from(c.clone()).map(|c| c.0))
            .collect::<Result<_, _>>()?;
        let large_communities = self
            .large_communities
            .iter()
            .map(|c| LargeCommunityValue::try_from(c.clone()).map(|c| c.0))
            .collect::<Result<_, _>>()?;
        Ok(TestQuery::Route(TestRoute {
            from: Some(from),
            prefix: Some(prefix),
            as_path: self.as_path.clone(),
            communities,
            large_communities,
            med: self.med,
            next_hop,
            otc: self.otc,
        }))
    }
}

/// Reply to `test`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceJson {
    pub prefix: String,
    /// The tested route as the neighbor sends it.
    pub tested: Option<RouteJson>,
    pub import: Option<ImportJson>,
    /// Every route of the prefix (with the tested one in place), best first.
    pub routes: Vec<RouteJson>,
    pub tested_is_best: Option<bool>,
    pub kernel: KernelJson,
    pub exports: Vec<ExportJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportJson {
    pub accepted: bool,
    pub reason: &'static str,
    pub filter: Option<String>,
    /// The rule that decided, from 1.
    pub rule: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelJson {
    pub installed: bool,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportJson {
    pub id: SourceId,
    pub neighbor: String,
    pub role: Option<NeighborRole>,
    /// Session up; otherwise both families and next hops are assumed.
    pub up: bool,
    pub sent: bool,
    pub reason: &'static str,
    pub filter: Option<String>,
    /// The rule that decided, from 1.
    pub rule: Option<usize>,
    /// What goes out, without the next hop (the session's own address).
    pub route: Option<RouteJson>,
}

impl TraceJson {
    /// `name` names the neighbor a route came from.
    pub fn new(trace: &Trace, name: impl Fn(SourceId) -> String) -> Self {
        let rule = |r: Option<usize>| r.map(|i| i + 1);
        Self {
            prefix: trace.prefix.to_string(),
            tested: trace.tested.as_ref().map(|r| RouteJson::new(r, &name)),
            import: trace.import.as_ref().map(|i| ImportJson {
                accepted: i.accepted,
                reason: i.reason,
                filter: i.filter.clone(),
                rule: rule(i.rule),
            }),
            routes: trace
                .candidates
                .iter()
                .map(|r| RouteJson::new(r, &name))
                .collect(),
            tested_is_best: trace.tested_is_best,
            kernel: KernelJson {
                installed: trace.kernel.installed,
                reason: trace.kernel.reason,
            },
            exports: trace
                .exports
                .iter()
                .map(|e| ExportJson {
                    id: e.peer,
                    neighbor: name(e.peer),
                    role: e.role,
                    up: e.up,
                    sent: e.sent,
                    reason: e.reason,
                    filter: e.filter.clone(),
                    rule: rule(e.rule),
                    route: e.sent.then(|| {
                        let info = RouteInfo {
                            prefix: trace.prefix,
                            source: LOCAL,
                            best: false,
                            attrs: e.attrs.clone(),
                            mp_next_hop: None,
                            unreachable: false,
                        };
                        RouteJson::new(&info, &name)
                    }),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerAction {
    Disable,
    Enable,
    Reset,
}

/// Reply to `announce` / `withdraw`.
#[derive(Debug, Clone, Serialize)]
pub struct OwnReply {
    /// Prefixes whose state changed.
    pub changed: Vec<String>,
    /// Already announced (announce) or not announced (withdraw).
    pub unchanged: Vec<String>,
    /// All our prefixes now.
    pub announce: Vec<String>,
}

/// Reply to `drain` / `undrain`.
#[derive(Debug, Clone, Serialize)]
pub struct DrainReply {
    /// false: it already was in that state.
    pub changed: bool,
    /// Since when we are drained; null when not drained.
    pub drained: Option<Timestamp>,
    pub now: Timestamp,
}

/// Reply to `peer`.
#[derive(Debug, Clone, Serialize)]
pub struct PeerActionReply {
    pub id: SourceId,
    pub address: SocketAddr,
    pub action: PeerAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

/// A reply line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reply {
    Ok(serde_json::Value),
    Error(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// ansage version.
    pub version: &'static str,
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub started: Timestamp,
    pub now: Timestamp,
    pub rib: Stats,
    /// Our own prefixes.
    pub announce: Vec<String>,
    /// Since when we are drained (RFC 8326); null when not drained.
    pub drained: Option<Timestamp>,
    pub peers: Vec<PeerBrief>,
}

/// One line per neighbor in the summary.
#[derive(Debug, Clone, Serialize)]
pub struct PeerBrief {
    pub id: SourceId,
    pub address: SocketAddr,
    pub asn: u32,
    pub description: Option<String>,
    pub state: State,
    pub since: Timestamp,
    /// Zero while the session is down.
    pub received_ipv4: u32,
    pub received_ipv6: u32,
    pub advertised_ipv4: usize,
    pub advertised_ipv6: usize,
}

impl PeerBrief {
    pub fn new(neighbor: &NeighborInfo, status: &PeerStatus, rib: Option<&PeerRibStatus>) -> Self {
        Self {
            id: neighbor.id,
            address: neighbor.address,
            asn: neighbor.asn,
            description: neighbor.description.clone(),
            state: status.state,
            since: status.since,
            received_ipv4: rib.map_or(0, |r| r.received_ipv4),
            received_ipv6: rib.map_or(0, |r| r.received_ipv6),
            advertised_ipv4: rib.map_or(0, |r| r.advertised_ipv4),
            advertised_ipv6: rib.map_or(0, |r| r.advertised_ipv6),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerDetail {
    pub neighbor: NeighborInfo,
    pub status: PeerStatus,
    pub counters: CounterSnapshot,
    /// The RIB's view; null while the session is down.
    pub rib: Option<PeerRibStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RibReply {
    /// Best routes in the RIB of the requested families (not with `prefix`).
    pub total: Option<usize>,
    pub routes: Vec<RouteJson>,
    /// With `prefix` and `[kernel]`: what the kernel has for it, state
    /// "absent" when ansage did not install it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<serde_json::Value>,
    /// With `out`: the neighbor the routes went to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteJson {
    pub prefix: String,
    /// "local" for our own prefixes, else the neighbor's address.
    pub source: String,
    pub source_id: SourceId,
    pub best: bool,
    pub origin: Option<&'static str>,
    pub as_path: Vec<Segment>,
    /// NEXT_HOP or the global MP_REACH next hop. Our own routes have none:
    /// theirs is set per neighbor on export.
    pub next_hop: Option<String>,
    pub next_hop_link_local: Option<Ipv6Addr>,
    /// The kernel cannot reach the next hop: the route is not used.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unreachable: bool,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub atomic_aggregate: bool,
    pub aggregator: Option<AggregatorJson>,
    /// "asn:value".
    pub communities: Vec<String>,
    /// "global:data1:data2".
    pub large_communities: Vec<String>,
    /// RFC 9234 OTC: the AS that limited the route to customers.
    pub only_to_customer: Option<u32>,
    /// Only from 2-octet peers before merging; usually empty.
    pub as4_path: Vec<Segment>,
    pub unknown: Vec<UnknownAttr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Segment {
    /// "sequence", "set", "confed-sequence" or "confed-set".
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub asns: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AggregatorJson {
    pub asn: u32,
    pub address: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownAttr {
    pub code: u8,
    pub flags: u8,
    /// Value in hex.
    pub value: String,
}

impl RouteJson {
    /// `source` names the neighbor a route came from.
    pub fn new(route: &RouteInfo, source: impl Fn(SourceId) -> String) -> Self {
        let mut json = Self {
            prefix: route.prefix.to_string(),
            source: if route.source == LOCAL {
                "local".to_string()
            } else {
                source(route.source)
            },
            source_id: route.source,
            best: route.best,
            origin: None,
            as_path: Vec::new(),
            next_hop: None,
            next_hop_link_local: None,
            unreachable: route.unreachable,
            med: None,
            local_pref: None,
            atomic_aggregate: false,
            aggregator: None,
            communities: Vec::new(),
            large_communities: Vec::new(),
            only_to_customer: None,
            as4_path: Vec::new(),
            unknown: Vec::new(),
        };
        for attr in &route.attrs {
            match attr {
                PathAttr::Origin(origin) => {
                    json.origin = Some(match origin {
                        Origin::Igp => "igp",
                        Origin::Egp => "egp",
                        Origin::Incomplete => "incomplete",
                    })
                }
                PathAttr::AsPath(path) => json.as_path = segments(&path.segments),
                PathAttr::NextHop(addr) => json.next_hop = Some(addr.to_string()),
                PathAttr::MultiExitDisc(med) => json.med = Some(*med),
                PathAttr::LocalPref(pref) => json.local_pref = Some(*pref),
                PathAttr::AtomicAggregate => json.atomic_aggregate = true,
                PathAttr::Aggregator(a) | PathAttr::As4Aggregator(a) => {
                    json.aggregator = Some(AggregatorJson {
                        asn: a.asn,
                        address: a.addr,
                    })
                }
                PathAttr::Communities(list) => {
                    json.communities = list
                        .iter()
                        .map(|c| format!("{}:{}", c >> 16, c & 0xffff))
                        .collect()
                }
                PathAttr::As4Path(path) => json.as4_path = segments(&path.segments),
                PathAttr::LargeCommunities(list) => {
                    json.large_communities = list
                        .iter()
                        .map(|c| {
                            format!("{}:{}:{}", c.global_admin, c.local_data_1, c.local_data_2)
                        })
                        .collect()
                }
                PathAttr::OnlyToCustomer(asn) => json.only_to_customer = Some(*asn),
                PathAttr::Unknown { flags, code, value } => json.unknown.push(UnknownAttr {
                    code: *code,
                    flags: *flags,
                    value: value.iter().map(|b| format!("{b:02x}")).collect(),
                }),
            }
        }
        match route.mp_next_hop {
            Some(NextHop::V6 { global, link_local }) => {
                json.next_hop = Some(global.to_string());
                json.next_hop_link_local = link_local;
            }
            Some(NextHop::V4(addr)) => json.next_hop = Some(addr.to_string()),
            None => {}
        }
        json
    }
}

fn segments(segments: &[ansage_bgp::wire::AsSegment]) -> Vec<Segment> {
    segments
        .iter()
        .map(|s| Segment {
            kind: match s.kind {
                SegmentType::Sequence => "sequence",
                SegmentType::Set => "set",
                SegmentType::ConfedSequence => "confed-sequence",
                SegmentType::ConfedSet => "confed-set",
            },
            asns: s.asns.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ansage_bgp::wire::{AsPath, LargeCommunity};

    #[test]
    fn parses_requests() {
        let parse = |s: &str| serde_json::from_str::<Envelope>(s);
        assert_eq!(
            parse(r#"{"cmd":"summary"}"#).unwrap().request,
            Request::Summary
        );
        assert_eq!(parse(r#"{"v":1,"cmd":"summary"}"#).unwrap().v, 1);
        assert_eq!(
            parse(r#"{"cmd":"peers","peer":"10.0.0.1"}"#)
                .unwrap()
                .request,
            Request::Peers {
                peer: Some("10.0.0.1".into())
            }
        );
        assert_eq!(
            parse(r#"{"cmd":"rib","family":"ipv6","limit":5}"#)
                .unwrap()
                .request,
            Request::Rib {
                prefix: None,
                family: Some(Family::Ipv6),
                limit: Some(5),
                out: None,
            }
        );
        assert!(parse(r#"{"cmd":"reboot"}"#).is_err());
        assert!(parse(r#"{"cmd":"rib","family":"ipx"}"#).is_err());
        assert!(parse("not json").is_err());

        // What the client sends round-trips.
        let request = Envelope {
            v: VERSION,
            request: Request::Peers { peer: None },
        };
        let line = serde_json::to_string(&request).unwrap();
        assert_eq!(line, r#"{"v":1,"cmd":"peers"}"#);
        assert_eq!(parse(&line).unwrap(), request);
    }

    #[test]
    fn reply_shape() {
        let ok = serde_json::to_string(&Reply::Ok(serde_json::json!([1]))).unwrap();
        assert_eq!(ok, r#"{"ok":[1]}"#);
        let err = serde_json::to_string(&Reply::Error("no".into())).unwrap();
        assert_eq!(err, r#"{"error":"no"}"#);
    }

    #[test]
    fn route_json() {
        let route = RouteInfo {
            prefix: "2001:db8:2::/48".parse().unwrap(),
            source: 2,
            best: true,
            attrs: vec![
                PathAttr::Origin(Origin::Incomplete),
                PathAttr::AsPath(AsPath::sequence(vec![64502, 64999])),
                PathAttr::Communities(vec![(64502 << 16) | 7]),
                PathAttr::LargeCommunities(vec![LargeCommunity {
                    global_admin: 64502,
                    local_data_1: 1,
                    local_data_2: 2,
                }]),
            ],
            mp_next_hop: Some(NextHop::V6 {
                global: "2001:db8::2".parse().unwrap(),
                link_local: None,
            }),
            unreachable: false,
        };
        let json = RouteJson::new(&route, |id| format!("peer{id}"));
        assert_eq!(json.source, "peer2");
        assert_eq!(json.origin, Some("incomplete"));
        assert_eq!(json.as_path[0].kind, "sequence");
        assert_eq!(json.as_path[0].asns, [64502, 64999]);
        assert_eq!(json.next_hop.as_deref(), Some("2001:db8::2"));
        assert_eq!(json.communities, ["64502:7"]);
        assert_eq!(json.large_communities, ["64502:1:2"]);

        let own = RouteInfo {
            source: LOCAL,
            mp_next_hop: None,
            ..route
        };
        let json = RouteJson::new(&own, |_| unreachable!());
        assert_eq!((json.source.as_str(), json.next_hop), ("local", None));
    }
}
