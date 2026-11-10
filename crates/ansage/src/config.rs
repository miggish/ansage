use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use ansage_bgp::session::SessionConfig;

use ansage_bgp::wire::{LargeCommunity, Prefix, Role};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

/// ansage configuration file (TOML).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Our AS number.
    pub asn: u32,
    /// BGP identifier, conventionally one of our IPv4 addresses.
    pub router_id: Ipv4Addr,
    /// Hold time we propose in seconds; the session uses the smaller of
    /// ours and the peer's. 0 disables keepalives, otherwise at least 3.
    #[serde(default = "default_hold_time")]
    pub hold_time: u16,
    /// Seconds between connection attempts.
    #[serde(default = "default_connect_retry")]
    pub connect_retry: u64,
    /// Upper bound in seconds for the reconnect backoff: the delay doubles
    /// after failed connects and after the peer shut the session down
    /// (RFC 4486 §4), and resets once a session is established.
    #[serde(default = "default_max_connect_retry")]
    pub max_connect_retry: u64,
    /// Our prefixes, announced to every neighbor.
    #[serde(default, deserialize_with = "prefixes")]
    pub announce: Vec<Prefix>,
    /// Seconds before reconnecting to a neighbor that exceeded its prefix
    /// limit.
    #[serde(default = "default_max_prefix_restart")]
    pub max_prefix_restart: u64,
    /// Unix socket for `ansage show`. An empty string turns it off.
    #[serde(default = "default_control_socket")]
    pub control_socket: PathBuf,
    /// Addresses to accept BGP connections on, e.g. ["0.0.0.0:179",
    /// "\[::\]:179"]; only configured neighbors get through. Empty (default):
    /// ansage only connects. Port 179 needs CAP_NET_BIND_SERVICE.
    #[serde(default)]
    pub listen: Vec<SocketAddr>,
    /// Graceful Restart (RFC 4724, RFC 8538): neighbors keep our routes for
    /// `restart_time` seconds when the session is lost without a Hard Reset
    /// (`ansage upgrade`, a crash), and we keep theirs. Off by default.
    #[serde(default)]
    pub graceful_restart: bool,
    /// Seconds a neighbor keeps our routes after losing the session, 1 to
    /// 4095 (advertised in the Graceful Restart capability).
    #[serde(default = "default_restart_time")]
    pub restart_time: u16,
    /// Seconds to stay drained (RFC 8326 GRACEFUL_SHUTDOWN on our routes)
    /// on SIGTERM/SIGINT before the sessions are closed, so traffic moves
    /// to other sites first. 0 (default): close at once.
    #[serde(default)]
    pub drain_time: u64,
    /// Serve Prometheus metrics at http://ADDR/metrics, e.g. "127.0.0.1:9179".
    /// Off by default.
    pub metrics_listen: Option<SocketAddr>,
    /// Install the best routes learned from neighbors into the kernel's
    /// routing table. Off without this section; needs CAP_NET_ADMIN.
    pub kernel: Option<Kernel>,
    #[serde(default, rename = "neighbor")]
    pub neighbors: Vec<Neighbor>,
    /// Named filters for a neighbor's `import` and `export`.
    #[serde(default, rename = "filter")]
    pub filters: BTreeMap<String, Filter>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Neighbor {
    /// The neighbor's address: ansage connects to it, and with `listen`
    /// accepts connections only from configured addresses.
    pub address: IpAddr,
    /// The neighbor's TCP port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// The neighbor's AS number; equal to `asn` makes the session iBGP.
    pub asn: u32,
    /// Overrides the global hold time for this neighbor.
    pub hold_time: Option<u16>,
    /// Free text shown by `ansage show` and in the metrics; a change needs
    /// no reconnect.
    pub description: Option<String>,
    /// Next hop for IPv4 routes. Default: our local address of the session,
    /// if the session runs over IPv4.
    pub next_hop_ipv4: Option<Ipv4Addr>,
    /// Next hop for IPv6 routes. Default: our local address of the session,
    /// if the session runs over IPv6 with a global address.
    pub next_hop_ipv6: Option<Ipv6Addr>,
    /// Our link-local address on the link shared with this neighbor; sent
    /// together with the global IPv6 next hop (RFC 2545 §3).
    pub next_hop_ipv6_link_local: Option<Ipv6Addr>,
    /// Offer extended next hop (RFC 8950): IPv4 routes may use an IPv6
    /// next hop, both ways. When the neighbor agrees and there is no IPv4
    /// next hop (an IPv6 session without `next_hop_ipv4`), our IPv4 prefixes
    /// go out with the IPv6 next hop. A change reconnects the session.
    #[serde(default)]
    pub extended_next_hop: bool,
    /// Which learned routes are kept: "none" (default, RFC 8212), "all", or
    /// the name of a filter.
    #[serde(default)]
    pub import: ImportPolicy,
    /// Close the session when the neighbor sends more IPv4 prefixes.
    pub max_prefixes_ipv4: Option<u32>,
    /// Close the session when the neighbor sends more IPv6 prefixes.
    pub max_prefixes_ipv6: Option<u32>,
    /// Which routes this neighbor gets: "own" (default, our prefixes),
    /// "none" (nothing, e.g. to take its routes for a shadow test), or the
    /// name of a filter. A filter that can pass learned routes on needs
    /// `role`.
    #[serde(default)]
    pub export: ExportPolicy,
    /// What the neighbor is to us (RFC 9234): "provider" (we buy transit
    /// from it), "customer" (it buys transit from us), "peer" or "rs" (an
    /// IXP route server). Routes learned from providers, peers and route
    /// servers only ever go to customers. Sent as our BGP Role in the OPEN
    /// (the opposite one) and checked against the neighbor's. eBGP only; a
    /// change reconnects the session.
    pub role: Option<NeighborRole>,
    /// With `role`: refuse a neighbor that sends no BGP Role (RFC 9234
    /// strict mode). A change reconnects the session.
    #[serde(default)]
    pub strict_role: bool,
    /// Announce a default route (0.0.0.0/0, ::/0) to this neighbor while a
    /// neighbor with role "provider" is up, whatever `export` says.
    #[serde(default)]
    pub default_route: bool,
    /// TCP-MD5 key shared with the neighbor (RFC 2385).
    #[serde(default, deserialize_with = "md5_key")]
    pub password: Option<Md5Key>,
    /// File holding the TCP-MD5 key instead of `password`; one trailing
    /// newline is ignored. Relative paths start at the config file.
    pub password_file: Option<PathBuf>,
    /// GTSM (RFC 5082): the neighbor is at most this many hops away
    /// (1 = directly connected). Packets with a lower TTL are dropped.
    pub ttl_security: Option<u8>,
    /// Overrides the global `graceful_restart` for this neighbor.
    pub graceful_restart: Option<bool>,
    /// Overrides the global `restart_time` for this neighbor.
    pub restart_time: Option<u16>,
    /// Never connect to this neighbor, wait for it to connect (needs `listen`).
    #[serde(default)]
    pub passive: bool,
    /// While drained, prepend our AS this many extra times on our routes
    /// to this (eBGP) neighbor, for neighbors that ignore GRACEFUL_SHUTDOWN.
    #[serde(default)]
    pub drain_prepend: u8,
    /// Install this neighbor's routes into the kernel when they are the
    /// best ones. Default: true with \[kernel\] (which it needs).
    pub install: Option<bool>,
}

/// Which routes a neighbor gets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
pub enum ExportPolicy {
    /// Only our own prefixes. Learned routes are never passed on, so ansage
    /// cannot accidentally become a transit AS.
    #[default]
    Own,
    /// Nothing: the session only receives (End-of-RIB is still sent).
    None,
    /// The routes the named filter accepts.
    Filter(String),
}

impl From<String> for ExportPolicy {
    fn from(name: String) -> Self {
        match name.as_str() {
            "own" => Self::Own,
            "none" => Self::None,
            _ => Self::Filter(name),
        }
    }
}

impl From<ExportPolicy> for String {
    fn from(policy: ExportPolicy) -> Self {
        match policy {
            ExportPolicy::Own => "own".into(),
            ExportPolicy::None => "none".into(),
            ExportPolicy::Filter(name) => name,
        }
    }
}

/// Which learned routes are kept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
pub enum ImportPolicy {
    /// Nothing is stored. RFC 8212 §3: routes from a neighbor take part in
    /// best path selection only with an explicit import policy.
    #[default]
    None,
    /// Every valid route is stored and used.
    All,
    /// The routes the named filter accepts.
    Filter(String),
}

impl From<String> for ImportPolicy {
    fn from(name: String) -> Self {
        match name.as_str() {
            "none" => Self::None,
            "all" => Self::All,
            _ => Self::Filter(name),
        }
    }
}

impl From<ImportPolicy> for String {
    fn from(policy: ImportPolicy) -> Self {
        match policy {
            ImportPolicy::None => "none".into(),
            ImportPolicy::All => "all".into(),
            ImportPolicy::Filter(name) => name,
        }
    }
}

/// Names `import` and `export` use themselves.
const RESERVED_FILTER_NAMES: [&str; 3] = ["none", "own", "all"];

/// What a neighbor is to us (RFC 9234 roles, seen from our side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NeighborRole {
    Provider,
    Customer,
    Peer,
    /// An IXP route server.
    Rs,
}

impl NeighborRole {
    /// Our role on the session, as sent in the OPEN.
    pub fn local(self) -> Role {
        match self {
            Self::Provider => Role::CUSTOMER,
            Self::Customer => Role::PROVIDER,
            Self::Peer => Role::PEER,
            Self::Rs => Role::RS_CLIENT,
        }
    }
}

/// `[filter.NAME]`: rules tried in order; the first one that matches
/// decides. A route no rule matches is rejected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

/// `[[filter.NAME.rule]]`: conditions (all given ones must hold; a list
/// matches if any element does), then what happens to the route.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// "own" (our `announce` prefixes) or "learned" (from neighbors).
    pub source: Option<RouteSource>,
    /// Learned from a neighbor with one of these roles.
    #[serde(default)]
    pub from_role: Vec<NeighborRole>,
    /// Learned from one of these neighbor addresses.
    #[serde(default)]
    pub from_neighbor: Vec<IpAddr>,
    /// Prefix ranges, e.g. "203.0.113.0/24" (exactly), "10.0.0.0/8 le 24"
    /// (/8 to /24 inside 10.0.0.0/8), "::/0 ge 49" (longer than /48).
    #[serde(default)]
    pub prefixes: Vec<PrefixRange>,
    /// The last AS in the AS path (who originated the route).
    #[serde(default)]
    pub origin_as: Vec<u32>,
    /// One of these AS numbers anywhere in the AS path.
    #[serde(default)]
    pub as_path_contains: Vec<u32>,
    /// At most this many AS numbers in the AS path.
    pub as_path_max_len: Option<u32>,
    /// Carries one of these communities, e.g. "64500:200".
    #[serde(default)]
    pub communities: Vec<Community>,
    /// Carries one of these large communities, e.g. "64500:1:2".
    #[serde(default)]
    pub large_communities: Vec<LargeCommunityValue>,
    /// "accept" or "reject".
    pub action: Action,
    /// Export only: prepend our AS this many extra times.
    #[serde(default)]
    pub prepend: u8,
    #[serde(default)]
    pub add_communities: Vec<Community>,
    #[serde(default)]
    pub remove_communities: Vec<Community>,
    #[serde(default)]
    pub add_large_communities: Vec<LargeCommunityValue>,
    #[serde(default)]
    pub remove_large_communities: Vec<LargeCommunityValue>,
    /// Set the MED.
    pub med: Option<u32>,
    /// Import only: set LOCAL_PREF (higher wins in best path selection).
    pub local_pref: Option<u32>,
}

impl Rule {
    /// The rule changes the route it accepts.
    pub fn changes(&self) -> bool {
        self.prepend > 0
            || !self.add_communities.is_empty()
            || !self.remove_communities.is_empty()
            || !self.add_large_communities.is_empty()
            || !self.remove_large_communities.is_empty()
            || self.med.is_some()
            || self.local_pref.is_some()
    }

    /// The rule can accept a learned route (not only our own).
    pub fn accepts_learned(&self) -> bool {
        self.action == Action::Accept && self.source != Some(RouteSource::Own)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteSource {
    Own,
    Learned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Reject,
}

/// A prefix and the range of lengths that match inside it, written like
/// FRR/Cisco prefix lists: "10.0.0.0/8", "10.0.0.0/8 le 24",
/// "10.0.0.0/8 ge 16", "10.0.0.0/8 ge 16 le 24".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PrefixRange {
    pub prefix: Prefix,
    pub min_len: u8,
    pub max_len: u8,
}

impl PrefixRange {
    pub fn contains(&self, prefix: &Prefix) -> bool {
        let len = prefix.prefix_len();
        if len < self.min_len || len > self.max_len {
            return false;
        }
        match (self.prefix, prefix) {
            (Prefix::V4(range), Prefix::V4(p)) => {
                let shift = 32 - u32::from(range.prefix_len());
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                u32::from(p.addr()) & mask == u32::from(range.addr())
            }
            (Prefix::V6(range), Prefix::V6(p)) => {
                let shift = 128 - u32::from(range.prefix_len());
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                u128::from(p.addr()) & mask == u128::from(range.addr())
            }
            _ => false,
        }
    }
}

impl TryFrom<String> for PrefixRange {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let mut words = text.split_whitespace();
        let prefix: Prefix = words
            .next()
            .ok_or_else(|| "empty prefix range".to_string())?
            .parse()
            .map_err(|err| format!("prefix range {text:?}: {err}"))?;
        let len = prefix.prefix_len();
        let max = match prefix {
            Prefix::V4(_) => 32,
            Prefix::V6(_) => 128,
        };
        let (mut ge, mut le) = (None, None);
        while let Some(word) = words.next() {
            let value = words
                .next()
                .and_then(|v| v.parse::<u8>().ok())
                .ok_or_else(|| format!("prefix range {text:?}: {word} needs a length"))?;
            let slot = match word {
                "ge" => &mut ge,
                "le" => &mut le,
                _ => {
                    return Err(format!(
                        "prefix range {text:?}: expected ge or le, got {word}"
                    ));
                }
            };
            if slot.replace(value).is_some() {
                return Err(format!("prefix range {text:?}: {word} given twice"));
            }
        }
        let (min_len, max_len) = match (ge, le) {
            (None, None) => (len, len),
            (ge, le) => (ge.unwrap_or(len), le.unwrap_or(max)),
        };
        if min_len < len || min_len > max_len || max_len > max {
            return Err(format!(
                "prefix range {text:?}: needs {len} <= ge <= le <= {max}"
            ));
        }
        Ok(Self {
            prefix,
            min_len,
            max_len,
        })
    }
}

/// A community (RFC 1997) written as "asn:value".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Community(pub u32);

impl TryFrom<String> for Community {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let parsed = text
            .split_once(':')
            .and_then(|(high, low)| Some((high.parse::<u16>().ok()?, low.parse::<u16>().ok()?)));
        let (high, low) = parsed.ok_or_else(|| {
            format!("community {text:?}: expected two numbers 0-65535 like 64500:200")
        })?;
        Ok(Self(u32::from(high) << 16 | u32::from(low)))
    }
}

/// A large community (RFC 8092) written as "global:data1:data2".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct LargeCommunityValue(pub LargeCommunity);

impl TryFrom<String> for LargeCommunityValue {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let parts: Vec<Option<u32>> = text.split(':').map(|p| p.parse().ok()).collect();
        match parts[..] {
            [Some(global_admin), Some(local_data_1), Some(local_data_2)] => {
                Ok(Self(LargeCommunity {
                    global_admin,
                    local_data_1,
                    local_data_2,
                }))
            }
            _ => Err(format!(
                "large community {text:?}: expected three numbers like 64500:1:2"
            )),
        }
    }
}

/// Longest TCP-MD5 key Linux accepts.
pub const MD5_MAX_KEY_LEN: usize = libc::TCP_MD5SIG_MAXKEYLEN;

/// A TCP-MD5 key. Debug output never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Md5Key(std::sync::Arc<[u8]>);

impl Md5Key {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self(key.as_ref().into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Md5Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Md5Key(..)")
    }
}

/// `[kernel]`: where ansage's routes go.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    /// Routing table, by number: 254 (default) is main.
    #[serde(default = "default_kernel_table")]
    pub table: u32,
    /// Metric of ansage's routes; another route for the same prefix with a
    /// lower metric wins. Default 20 (FRR's for eBGP).
    #[serde(default = "default_kernel_metric")]
    pub metric: u32,
    /// Families to install, default both.
    #[serde(default = "default_kernel_families")]
    pub families: Vec<Family>,
    /// A BGP next hop whose only route in the kernel is the default route
    /// counts as reachable (e.g. multihop to a router behind the default
    /// gateway). Off by default, like FRR: usually such a route is broken.
    #[serde(default)]
    pub resolve_via_default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Kernel {
    /// `[ipv4, ipv6]`.
    pub fn install_families(&self) -> [bool; 2] {
        [Family::Ipv4, Family::Ipv6].map(|f| self.families.contains(&f))
    }
}

fn default_kernel_table() -> u32 {
    ansage_netlink::RT_TABLE_MAIN
}

fn default_kernel_metric() -> u32 {
    20
}

fn default_kernel_families() -> Vec<Family> {
    vec![Family::Ipv4, Family::Ipv6]
}

fn md5_key<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Md5Key>, D::Error> {
    Ok(Some(Md5Key::new(String::deserialize(deserializer)?)))
}

/// Prefixes as strings, parsed strictly (host bits set is an error).
fn prefixes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Prefix>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|err| D::Error::custom(format!("prefix {s:?}: {err}")))
        })
        .collect()
}

fn default_hold_time() -> u16 {
    90
}

fn default_connect_retry() -> u64 {
    30
}

fn default_port() -> u16 {
    179
}

fn default_max_prefix_restart() -> u64 {
    300
}

fn default_max_connect_retry() -> u64 {
    600
}

fn default_restart_time() -> u16 {
    30
}

/// Where `ansage show` looks by default.
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/ansage/ansage.sock";

/// The RIB numbers neighbors with a u16; 0 is our own prefixes.
pub const MAX_NEIGHBORS: usize = u16::MAX as usize - 1;

/// Upper bound for `drain_time`: a stop that waits longer is a mistake.
const MAX_DRAIN_TIME: u64 = 3600;

/// Upper bound for `drain_prepend`; a few prepends already lose against
/// any other path.
const MAX_DRAIN_PREPEND: u8 = 10;

/// Upper bound for a filter rule's `prepend`, for the same reason.
const MAX_PREPEND: u8 = 10;

/// Longest unix socket path (Linux sun_path minus the NUL).
const MAX_SOCKET_PATH: usize = 107;

fn default_control_socket() -> PathBuf {
    DEFAULT_CONTROL_SOCKET.into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let mut config: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        config.read_password_files(path.parent().unwrap_or(Path::new(".")))?;
        config.validate()?;
        Ok(config)
    }

    /// Replaces each `password_file` with the key read from it.
    fn read_password_files(&mut self, base: &Path) -> Result<(), ConfigError> {
        for n in &mut self.neighbors {
            let Some(file) = &n.password_file else {
                continue;
            };
            if n.password.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "neighbor {}: password and password_file are both set",
                    n.address
                )));
            }
            let path = base.join(file);
            let text = std::fs::read(&path).map_err(|source| ConfigError::Read {
                path: path.clone(),
                source,
            })?;
            let key = text
                .strip_suffix(b"\n")
                .map(|k| k.strip_suffix(b"\r").unwrap_or(k))
                .unwrap_or(&text);
            n.password = Some(Md5Key::new(key));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        if self.asn == 0 {
            return invalid("asn must not be 0".into());
        }
        if self.router_id.is_unspecified() {
            return invalid("router_id must not be 0.0.0.0".into());
        }
        if self.connect_retry == 0 {
            return invalid("connect_retry must be at least 1 second".into());
        }
        if self.max_connect_retry < self.connect_retry {
            return invalid("max_connect_retry must not be below connect_retry".into());
        }
        check_hold_time("hold_time", self.hold_time)?;
        if self.drain_time > MAX_DRAIN_TIME {
            return invalid(format!(
                "drain_time must be at most {MAX_DRAIN_TIME} seconds, got {}",
                self.drain_time
            ));
        }
        check_restart_time("restart_time", self.restart_time)?;
        // sun_path is 108 bytes with the terminating NUL; longer paths fail
        // only at bind, and ansage would run without its control socket.
        if self.control_socket.as_os_str().len() > MAX_SOCKET_PATH {
            return invalid(format!(
                "control_socket is longer than {MAX_SOCKET_PATH} bytes (a unix socket limit): {}",
                self.control_socket.display()
            ));
        }

        let mut announced = HashSet::new();
        for prefix in &self.announce {
            if !announced.insert(prefix) {
                return invalid(format!("prefix {prefix} is announced twice"));
            }
        }

        if let Some(kernel) = &self.kernel {
            // 0 is "unspecified", 253 default and 255 local belong to the
            // kernel's own routing.
            if matches!(kernel.table, 0 | 253 | 255) {
                return invalid(format!(
                    "[kernel] table {} is reserved; use 254 (main) or a table of your own",
                    kernel.table
                ));
            }
            if kernel.families.is_empty() {
                return invalid("[kernel] families must name ipv4, ipv6 or both".into());
            }
            if kernel.families.len() != kernel.families.iter().collect::<HashSet<_>>().len() {
                return invalid("[kernel] families names a family twice".into());
            }
        }

        if self.neighbors.len() > MAX_NEIGHBORS {
            return invalid(format!("at most {MAX_NEIGHBORS} neighbors"));
        }
        let mut listen = HashSet::new();
        for addr in &self.listen {
            if !listen.insert(addr) {
                return invalid(format!("listen address {addr} is given twice"));
            }
        }
        self.validate_filters()?;
        let mut seen = HashSet::new();
        let mut addresses = HashSet::new();
        for n in &self.neighbors {
            if n.passive && self.listen.is_empty() {
                return invalid(format!(
                    "neighbor {}: passive needs a listen address",
                    n.address
                ));
            }
            // Incoming connections are matched by address only.
            if !self.listen.is_empty() && !addresses.insert(n.address) {
                return invalid(format!(
                    "neighbor {}: with listen, each neighbor address may appear only once",
                    n.address
                ));
            }
            if n.asn == 0 {
                return invalid(format!("neighbor {}: asn must not be 0", n.address));
            }
            if let Some(hold) = n.hold_time {
                check_hold_time(&format!("neighbor {}: hold_time", n.address), hold)?;
            }
            if n.drain_prepend > MAX_DRAIN_PREPEND {
                return invalid(format!(
                    "neighbor {}: drain_prepend must be at most {MAX_DRAIN_PREPEND}, got {}",
                    n.address, n.drain_prepend
                ));
            }
            if let Some(time) = n.restart_time {
                check_restart_time(&format!("neighbor {}: restart_time", n.address), time)?;
            }
            // RFC 4271 §5.1.3: never the peer's own address as next hop.
            if n.next_hop_ipv4.map(IpAddr::V4) == Some(n.address)
                || n.next_hop_ipv6.map(IpAddr::V6) == Some(n.address)
            {
                return invalid(format!(
                    "neighbor {}: next hop is the neighbor itself",
                    n.address
                ));
            }
            if n.next_hop_ipv6_link_local
                .is_some_and(|a| !a.is_unicast_link_local())
            {
                return invalid(format!(
                    "neighbor {}: next_hop_ipv6_link_local must be in fe80::/10",
                    n.address
                ));
            }
            // RFC 2545 §3: the MP next hop field carries a global address.
            if n.next_hop_ipv6.is_some_and(|a| a.is_unicast_link_local()) {
                return invalid(format!(
                    "neighbor {}: next_hop_ipv6 must be a global address, not link-local",
                    n.address
                ));
            }
            if let Some(key) = &n.password {
                let len = key.as_bytes().len();
                if len == 0 || len > MD5_MAX_KEY_LEN {
                    return invalid(format!(
                        "neighbor {}: the TCP-MD5 password must be 1 to {MD5_MAX_KEY_LEN} bytes, got {len}",
                        n.address
                    ));
                }
            }
            if n.ttl_security.is_some_and(|hops| hops == 0 || hops == 255) {
                return invalid(format!(
                    "neighbor {}: ttl_security is the number of hops to the neighbor, 1 to 254",
                    n.address
                ));
            }
            self.validate_policy(n)?;
            if n.install == Some(true) && self.kernel.is_none() {
                return invalid(format!(
                    "neighbor {}: install needs a [kernel] section",
                    n.address
                ));
            }
            if !seen.insert(n.socket_addr()) {
                return invalid(format!("neighbor {} is configured twice", n.socket_addr()));
            }
        }
        Ok(())
    }

    fn validate_filters(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        for (name, filter) in &self.filters {
            if RESERVED_FILTER_NAMES.contains(&name.as_str()) {
                return invalid(format!(
                    "filter {name:?}: none, own and all are reserved names"
                ));
            }
            for (i, rule) in filter.rules.iter().enumerate() {
                let at = format!("filter {name:?} rule {}", i + 1);
                if rule.action == Action::Reject && rule.changes() {
                    return invalid(format!("{at}: a rejecting rule cannot change the route"));
                }
                if rule.prepend > MAX_PREPEND {
                    return invalid(format!("{at}: prepend must be at most {MAX_PREPEND}"));
                }
                let learned_only = !rule.from_role.is_empty() || !rule.from_neighbor.is_empty();
                if rule.source == Some(RouteSource::Own) && learned_only {
                    return invalid(format!(
                        "{at}: source = \"own\" never matches from_role / from_neighbor"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Import and export of one neighbor: filters exist, fit their use, and
    /// learned routes only go to neighbors with a role.
    fn validate_policy(&self, n: &Neighbor) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        let ibgp = n.asn == self.asn;
        if n.role.is_some() && ibgp {
            return invalid(format!(
                "neighbor {}: role is for eBGP sessions only (RFC 9234)",
                n.address
            ));
        }
        if n.strict_role && n.role.is_none() {
            return invalid(format!("neighbor {}: strict_role needs role", n.address));
        }
        if n.default_route
            && !self
                .neighbors
                .iter()
                .any(|o| o.role == Some(NeighborRole::Provider))
        {
            return invalid(format!(
                "neighbor {}: default_route needs a neighbor with role = \"provider\"",
                n.address
            ));
        }
        let filter = |field: &str, name: &str, builtin: &str| {
            self.filters.get(name).ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "neighbor {}: {field} = {name:?}: no filter of that name ({builtin})",
                    n.address
                ))
            })
        };
        if let ImportPolicy::Filter(name) = &n.import {
            let f = filter("import", name, "built in: none, all")?;
            if f.rules.iter().any(|r| r.prepend > 0) {
                return invalid(format!(
                    "neighbor {}: import filter {name:?} uses prepend, which only works on export",
                    n.address
                ));
            }
        }
        if let ExportPolicy::Filter(name) = &n.export {
            let f = filter("export", name, "built in: own, none")?;
            if f.rules.iter().any(|r| r.local_pref.is_some()) {
                return invalid(format!(
                    "neighbor {}: export filter {name:?} sets local_pref, which only works on import",
                    n.address
                ));
            }
            if n.role.is_none() && f.rules.iter().any(Rule::accepts_learned) {
                return invalid(format!(
                    "neighbor {}: export filter {name:?} can pass learned routes on; that needs \
                     a role (or limit its accepting rules to source = \"own\")",
                    n.address
                ));
            }
        }
        Ok(())
    }

    /// Session parameters for one neighbor.
    pub fn session(&self, neighbor: &Neighbor) -> SessionConfig {
        SessionConfig {
            local_asn: self.asn,
            router_id: self.router_id,
            peer_asn: neighbor.asn,
            hold_time: neighbor.hold_time.unwrap_or(self.hold_time),
            connect_retry: Duration::from_secs(self.connect_retry),
            max_connect_retry: Duration::from_secs(self.max_connect_retry),
            jitter: true,
            passive: neighbor.passive,
            graceful_restart: neighbor
                .graceful_restart
                .unwrap_or(self.graceful_restart)
                .then(|| neighbor.restart_time.unwrap_or(self.restart_time)),
            extended_next_hop: neighbor.extended_next_hop,
            role: neighbor.role.map(NeighborRole::local),
            strict_role: neighbor.strict_role,
        }
    }
}

impl Neighbor {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// The Restart Time field has 12 bits (RFC 4724 §3); 0 would mean "do not
/// keep my routes", which is Graceful Restart off.
fn check_restart_time(what: &str, time: u16) -> Result<(), ConfigError> {
    if time == 0 || time > ansage_bgp::wire::GracefulRestart::MAX_RESTART_TIME {
        return Err(ConfigError::Invalid(format!(
            "{what} must be 1 to {}, got {time}",
            ansage_bgp::wire::GracefulRestart::MAX_RESTART_TIME
        )));
    }
    Ok(())
}

/// RFC 4271 §4.2: 0, or at least 3 seconds.
fn check_hold_time(what: &str, hold: u16) -> Result<(), ConfigError> {
    if hold == 1 || hold == 2 {
        return Err(ConfigError::Invalid(format!(
            "{what} must be 0 or at least 3, got {hold}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        parse_in(text, Path::new("/nonexistent"))
    }

    fn parse_in(text: &str, base: &Path) -> Result<Config, ConfigError> {
        let mut config: Config = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: "test.toml".into(),
            source,
        })?;
        config.read_password_files(base)?;
        config.validate()?;
        Ok(config)
    }

    const BASE: &str = "asn = 64500\nrouter_id = \"203.0.113.1\"\n";

    fn neighbor_with(extra: &str) -> String {
        format!("{BASE}[[neighbor]]\naddress = \"192.0.2.2\"\nasn = 64501\n{extra}\n")
    }

    #[test]
    fn drain_settings() {
        let config = parse(&format!(
            "drain_time = 60\n{}",
            neighbor_with("drain_prepend = 3")
        ))
        .unwrap();
        assert_eq!(config.drain_time, 60);
        assert_eq!(config.neighbors[0].drain_prepend, 3);
        let defaults = parse(&neighbor_with("")).unwrap();
        assert_eq!(defaults.drain_time, 0);
        assert_eq!(defaults.neighbors[0].drain_prepend, 0);

        let err = parse(&neighbor_with("drain_prepend = 11")).unwrap_err();
        assert!(err.to_string().contains("drain_prepend must be at most 10"));
        let err = parse(&format!("drain_time = 3601\n{}", neighbor_with(""))).unwrap_err();
        assert!(err.to_string().contains("drain_time must be at most 3600"));
    }

    #[test]
    fn md5_and_gtsm() {
        let config = parse(&neighbor_with(
            "password = \"e2e-secret\"\nttl_security = 1",
        ))
        .unwrap();
        let n = &config.neighbors[0];
        assert_eq!(n.password.as_ref().unwrap().as_bytes(), b"e2e-secret");
        assert!(
            !format!("{config:?}").contains("e2e-secret"),
            "the key never shows up in Debug"
        );
        assert_eq!(n.ttl_security, Some(1));

        assert!(parse(&neighbor_with("password = \"\"")).is_err());
        assert!(
            parse(&neighbor_with(&format!(
                "password = \"{}\"",
                "x".repeat(81)
            )))
            .is_err()
        );
        parse(&neighbor_with(&format!(
            "password = \"{}\"",
            "x".repeat(80)
        )))
        .unwrap();
        assert!(parse(&neighbor_with("ttl_security = 0")).is_err());
        assert!(parse(&neighbor_with("ttl_security = 255")).is_err());
        assert!(parse(&neighbor_with("ttl_security = 256")).is_err());
        parse(&neighbor_with("ttl_security = 254")).unwrap();
    }

    #[test]
    fn graceful_restart() {
        // Off by default.
        let config = parse(&neighbor_with("")).unwrap();
        assert_eq!(config.session(&config.neighbors[0]).graceful_restart, None);

        let on = format!("graceful_restart = true\n{}", neighbor_with(""));
        let config = parse(&on).unwrap();
        assert_eq!(
            config.session(&config.neighbors[0]).graceful_restart,
            Some(30)
        );

        // Per neighbor: on, off, other restart time.
        let config = parse(&neighbor_with(
            "graceful_restart = true\nrestart_time = 120",
        ))
        .unwrap();
        assert_eq!(
            config.session(&config.neighbors[0]).graceful_restart,
            Some(120)
        );
        let off = format!(
            "graceful_restart = true\n{}",
            neighbor_with("graceful_restart = false")
        );
        let config = parse(&off).unwrap();
        assert_eq!(config.session(&config.neighbors[0]).graceful_restart, None);

        assert!(parse(&format!("{BASE}restart_time = 0")).is_err());
        assert!(parse(&format!("{BASE}restart_time = 4096")).is_err());
        parse(&format!("{BASE}restart_time = 4095")).unwrap();
        assert!(parse(&neighbor_with("restart_time = 0")).is_err());
    }

    #[test]
    fn extended_next_hop() {
        let config = parse(&neighbor_with("")).unwrap();
        assert!(!config.session(&config.neighbors[0]).extended_next_hop);
        let config = parse(&neighbor_with("extended_next_hop = true")).unwrap();
        assert!(config.session(&config.neighbors[0]).extended_next_hop);
    }

    #[test]
    fn listen_and_passive() {
        let listen = "listen = [\"0.0.0.0:179\", \"[::]:179\"]\n";
        let config = parse(&format!("{listen}{}", neighbor_with("passive = true"))).unwrap();
        assert_eq!(config.listen.len(), 2);
        assert!(config.session(&config.neighbors[0]).passive);

        // Passive without a listener could never come up.
        let err = parse(&neighbor_with("passive = true")).unwrap_err();
        assert!(err.to_string().contains("listen"), "{err}");
        assert!(
            parse(
                "listen = [\"0.0.0.0:179\", \"0.0.0.0:179\"]\nasn = 1\nrouter_id = \"192.0.2.1\""
            )
            .is_err()
        );
        // Incoming connections are matched by address: ports cannot tell
        // two neighbors apart.
        let two_ports = format!(
            "{listen}{}[[neighbor]]\naddress = \"192.0.2.2\"\nport = 1179\nasn = 64502\n",
            neighbor_with("")
        );
        assert!(parse(&two_ports).is_err());
        let without_listen = two_ports.replacen(listen, "", 1);
        parse(&without_listen).unwrap();
    }

    #[test]
    fn password_file() {
        let dir = std::env::temp_dir().join(format!("ansage-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("r1.key"), "from-file\n").unwrap();
        std::fs::write(dir.join("empty.key"), "\n").unwrap();

        let config = parse_in(&neighbor_with("password_file = \"r1.key\""), &dir).unwrap();
        let key = config.neighbors[0].password.as_ref().unwrap();
        assert_eq!(
            key.as_bytes(),
            b"from-file",
            "relative to the config, newline dropped"
        );

        let abs = dir.join("r1.key");
        let text = neighbor_with(&format!("password_file = {:?}", abs.to_str().unwrap()));
        parse(&text).unwrap();

        let both = neighbor_with("password = \"x\"\npassword_file = \"r1.key\"");
        assert!(
            parse_in(&both, &dir)
                .unwrap_err()
                .to_string()
                .contains("both set")
        );
        assert!(matches!(
            parse_in(&neighbor_with("password_file = \"missing.key\""), &dir),
            Err(ConfigError::Read { .. })
        ));
        assert!(parse_in(&neighbor_with("password_file = \"empty.key\""), &dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn full_config() {
        let config = parse(
            r#"
            asn = 64500
            router_id = "203.0.113.1"
            hold_time = 30
            announce = ["192.0.2.0/24", "2001:db8:1::/48"]

            [[neighbor]]
            address = "127.0.0.2"
            asn = 64501
            description = "BIRD"
            next_hop_ipv6 = "2001:db8:1::1"
            max_prefixes_ipv4 = 1100000
            export = "own"

            [[neighbor]]
            address = "2001:db8::2"
            port = 1179
            asn = 64502
            hold_time = 9
            "#,
        )
        .unwrap();
        assert_eq!(config.connect_retry, 30);
        assert_eq!(config.control_socket, Path::new(DEFAULT_CONTROL_SOCKET));
        assert_eq!(config.neighbors.len(), 2);
        assert_eq!(config.neighbors[0].port, 179);
        assert_eq!(config.session(&config.neighbors[0]).hold_time, 30);
        assert_eq!(config.session(&config.neighbors[1]).hold_time, 9);
        assert_eq!(config.announce.len(), 2);
        assert_eq!(config.neighbors[0].max_prefixes_ipv4, Some(1_100_000));
        assert_eq!(config.neighbors[1].max_prefixes_ipv4, None);
        assert_eq!(config.max_prefix_restart, 300);
        assert_eq!(
            config.neighbors[0].next_hop_ipv6,
            Some("2001:db8:1::1".parse().unwrap())
        );
    }

    #[test]
    fn rejects_bad_values() {
        let base = "asn = 64500\nrouter_id = \"203.0.113.1\"\n";
        assert!(parse(&format!("{base}hold_time = 2")).is_err());
        assert!(
            parse(&format!("{base}typo = 1")).is_err(),
            "unknown keys are errors"
        );
        let twice = "[[neighbor]]\naddress = \"127.0.0.2\"\nasn = 64501\n";
        assert!(parse(&format!("{base}{twice}{twice}")).is_err());
        assert!(parse("asn = 0\nrouter_id = \"203.0.113.1\"").is_err());
        let long = format!(
            "{base}control_socket = \"/{}\"",
            "x".repeat(MAX_SOCKET_PATH)
        );
        assert!(
            parse(&long)
                .unwrap_err()
                .to_string()
                .contains("unix socket limit")
        );
        let fits = format!(
            "{base}control_socket = \"/{}\"",
            "x".repeat(MAX_SOCKET_PATH - 1)
        );
        parse(&fits).unwrap();

        let err = parse(&format!("{base}announce = [\"192.0.2.1/24\"]")).unwrap_err();
        assert!(
            err.to_string().contains("did you mean 192.0.2.0/24"),
            "{err}"
        );
        assert!(
            parse(&format!(
                "{base}announce = [\"192.0.2.0/24\", \"192.0.2.0/24\"]"
            ))
            .is_err()
        );
        let self_hop =
            "[[neighbor]]\naddress = \"192.0.2.2\"\nasn = 64501\nnext_hop_ipv4 = \"192.0.2.2\"\n";
        assert!(parse(&format!("{base}{self_hop}")).is_err());
        let link_local =
            "[[neighbor]]\naddress = \"192.0.2.2\"\nasn = 64501\nnext_hop_ipv6 = \"fe80::1\"\n";
        assert!(parse(&format!("{base}{link_local}")).is_err());
        let none = "[[neighbor]]\naddress = \"127.0.0.2\"\nasn = 64501\nexport = \"none\"\n";
        let config = parse(&format!("{base}{none}")).unwrap();
        assert_eq!(config.neighbors[0].export, ExportPolicy::None);
        let all = "[[neighbor]]\naddress = \"127.0.0.2\"\nasn = 64501\nexport = \"all\"\n";
        assert!(
            parse(&format!("{base}{all}")).is_err(),
            "re-export is not implemented"
        );
    }

    #[test]
    fn kernel_section() {
        let config = parse(&neighbor_with("")).unwrap();
        assert!(config.kernel.is_none());

        let text = format!("{}[kernel]\n", neighbor_with(""));
        let config = parse(&text).unwrap();
        let kernel = config.kernel.as_ref().unwrap();
        assert_eq!((kernel.table, kernel.metric), (254, 20));
        assert_eq!(kernel.install_families(), [true, true]);

        let text = format!(
            "{}[kernel]\ntable = 100\nmetric = 32\nfamilies = [\"ipv6\"]\n",
            neighbor_with("install = false")
        );
        let config = parse(&text).unwrap();
        let kernel = config.kernel.as_ref().unwrap();
        assert_eq!(kernel.table, 100);
        assert_eq!(kernel.install_families(), [false, true]);
        assert_eq!(config.neighbors[0].install, Some(false));

        for (kernel, error) in [
            ("table = 255", "reserved"),
            ("table = 0", "reserved"),
            ("families = []", "must name"),
            ("families = [\"ipv4\", \"ipv4\"]", "twice"),
        ] {
            let err = parse(&format!("{BASE}[kernel]\n{kernel}\n")).unwrap_err();
            assert!(err.to_string().contains(error), "{kernel}: {err}");
        }
        let err = parse(&neighbor_with("install = true")).unwrap_err();
        assert!(err.to_string().contains("needs a [kernel]"), "{err}");
    }

    #[test]
    fn prefix_ranges() {
        let range = |s: &str| PrefixRange::try_from(s.to_string());
        let r = range("10.0.0.0/8 le 24").unwrap();
        assert_eq!((r.min_len, r.max_len), (8, 24));
        assert!(r.contains(&"10.1.0.0/16".parse().unwrap()));
        assert!(r.contains(&"10.0.0.0/8".parse().unwrap()));
        assert!(!r.contains(&"10.1.1.0/25".parse().unwrap()));
        assert!(!r.contains(&"11.0.0.0/16".parse().unwrap()));
        assert!(!r.contains(&"2001:db8::/32".parse().unwrap()));
        let exact = range("203.0.113.0/24").unwrap();
        assert!(exact.contains(&"203.0.113.0/24".parse().unwrap()));
        assert!(!exact.contains(&"203.0.113.0/25".parse().unwrap()));
        let r = range("::/0 ge 49").unwrap();
        assert_eq!((r.min_len, r.max_len), (49, 128));
        assert!(r.contains(&"2001:db8:1:8000::/49".parse().unwrap()));
        assert!(!r.contains(&"2001:db8::/48".parse().unwrap()));
        let r = range("0.0.0.0/0 ge 8 le 24").unwrap();
        assert_eq!((r.min_len, r.max_len), (8, 24));
        for bad in [
            "10.0.0.0/8 le 4",
            "10.0.0.0/8 ge 25 le 24",
            "10.0.0.0/8 le 33",
            "10.0.0.0/8 le",
            "10.0.0.0/8 eq 9",
            "10.0.0.0/8 le 9 le 10",
            "10.0.0.1/8",
        ] {
            assert!(range(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn communities() {
        assert_eq!(
            Community::try_from("64500:200".to_string()),
            Ok(Community(64500 << 16 | 200))
        );
        assert!(Community::try_from("70000:1".to_string()).is_err());
        let large = LargeCommunityValue::try_from("4200000000:1:2".to_string()).unwrap();
        assert_eq!(large.0.global_admin, 4_200_000_000);
        assert!(LargeCommunityValue::try_from("1:2".to_string()).is_err());
    }

    const PROVIDER: &str =
        "[[neighbor]]\naddress = \"192.0.2.9\"\nasn = 64509\nrole = \"provider\"\n";

    #[test]
    fn roles_and_filters() {
        let text = format!(
            r#"{BASE}{PROVIDER}
            [[neighbor]]
            address = "192.0.2.2"
            asn = 64510
            role = "customer"
            strict_role = true
            default_route = true
            import = "in"
            export = "out"

            [filter.in]
            [[filter.in.rule]]
            prefixes = ["203.0.113.0/24 le 24"]
            action = "accept"
            local_pref = 200

            [filter.out]
            [[filter.out.rule]]
            action = "accept"
            prepend = 1
            "#
        );
        let config = parse(&text).unwrap();
        let n = &config.neighbors[1];
        assert_eq!(n.role, Some(NeighborRole::Customer));
        assert_eq!(n.import, ImportPolicy::Filter("in".into()));
        assert_eq!(n.export, ExportPolicy::Filter("out".into()));
        let session = config.session(n);
        assert_eq!(
            session.role,
            Some(Role::PROVIDER),
            "our role is the opposite"
        );
        assert!(session.strict_role);
        assert_eq!(config.filters["in"].rules[0].local_pref, Some(200));
    }

    #[test]
    fn invalid_roles_and_filters() {
        let cases = [
            ("role = \"rs-client\"", "unknown variant"),
            ("strict_role = true", "strict_role needs role"),
            ("default_route = true", "needs a neighbor with role"),
            (
                "import = \"missing\"",
                "import = \"missing\": no filter of that name",
            ),
            (
                "export = \"all-out\"",
                "can pass learned routes on; that needs",
            ),
            (
                "role = \"customer\"\nimport = \"all-out\"",
                "prepend, which only works on export",
            ),
            (
                "role = \"customer\"\nexport = \"set-pref\"",
                "local_pref, which only works on import",
            ),
        ];
        let filters = r#"
            [filter.all-out]
            [[filter.all-out.rule]]
            action = "accept"
            prepend = 1
            [filter.set-pref]
            [[filter.set-pref.rule]]
            action = "accept"
            local_pref = 10
        "#;
        for (extra, expected) in cases {
            let err = parse(&format!("{}{filters}", neighbor_with(extra))).unwrap_err();
            assert!(err.to_string().contains(expected), "{extra}: {err}");
        }
        // Role on iBGP.
        let ibgp =
            format!("{BASE}[[neighbor]]\naddress = \"192.0.2.2\"\nasn = 64500\nrole = \"peer\"\n");
        assert!(
            parse(&ibgp)
                .unwrap_err()
                .to_string()
                .contains("eBGP sessions only")
        );
        // An export filter limited to our own routes needs no role.
        let own_only = r#"
            [filter.own]
            [[filter.own.rule]]
            action = "accept"
        "#;
        let err = parse(&format!("{}{own_only}", neighbor_with(""))).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
        let own_only = r#"
            [filter.mine]
            [[filter.mine.rule]]
            source = "own"
            action = "accept"
        "#;
        parse(&format!("{}{own_only}", neighbor_with("export = \"mine\""))).unwrap();
        // Rules that make no sense.
        for rule in [
            "action = \"reject\"\nmed = 1",
            "action = \"accept\"\nprepend = 11",
            "action = \"accept\"\nsource = \"own\"\nfrom_role = [\"peer\"]",
        ] {
            let text = format!(
                "{}[filter.x]\n[[filter.x.rule]]\n{rule}\n",
                neighbor_with("")
            );
            assert!(parse(&text).is_err(), "{rule}");
        }
    }
}
