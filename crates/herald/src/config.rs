use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use herald_bgp::session::SessionConfig;

use herald_bgp::wire::Prefix;

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

/// herald configuration file (TOML).
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
    /// Unix socket for `herald show`. An empty string turns it off.
    #[serde(default = "default_control_socket")]
    pub control_socket: PathBuf,
    /// Addresses to accept BGP connections on, e.g. ["0.0.0.0:179",
    /// "\[::\]:179"]; only configured neighbors get through. Empty (default):
    /// herald only connects. Port 179 needs CAP_NET_BIND_SERVICE.
    #[serde(default)]
    pub listen: Vec<SocketAddr>,
    /// Graceful Restart (RFC 4724, RFC 8538): neighbors keep our routes for
    /// `restart_time` seconds when the session is lost without a Hard Reset
    /// (`herald upgrade`, a crash), and we keep theirs. Off by default.
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
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Neighbor {
    /// The neighbor's address: herald connects to it, and with `listen`
    /// accepts connections only from configured addresses.
    pub address: IpAddr,
    /// The neighbor's TCP port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// The neighbor's AS number; equal to `asn` makes the session iBGP.
    pub asn: u32,
    /// Overrides the global hold time for this neighbor.
    pub hold_time: Option<u16>,
    /// Free text shown by `herald show` and in the metrics; a change needs
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
    /// Which learned routes are kept: "none" (default, RFC 8212) or "all".
    #[serde(default)]
    pub import: ImportPolicy,
    /// Close the session when the neighbor sends more IPv4 prefixes.
    pub max_prefixes_ipv4: Option<u32>,
    /// Close the session when the neighbor sends more IPv6 prefixes.
    pub max_prefixes_ipv6: Option<u32>,
    /// Which routes this neighbor gets. Only "own" (our prefixes) for now.
    #[serde(default)]
    pub export: ExportPolicy,
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

/// `[kernel]`: where herald's routes go.
/// Which routes a neighbor gets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportPolicy {
    /// Only our own prefixes. Learned routes are never passed on, so herald
    /// cannot accidentally become a transit AS.
    #[default]
    Own,
}

/// Which learned routes are kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportPolicy {
    /// Nothing is stored. RFC 8212 §3: routes from a neighbor take part in
    /// best path selection only with an explicit import policy.
    #[default]
    None,
    /// Every valid route is stored and used.
    All,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    /// Routing table, by number: 254 (default) is main.
    #[serde(default = "default_kernel_table")]
    pub table: u32,
    /// Metric of herald's routes; another route for the same prefix with a
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
    herald_netlink::RT_TABLE_MAIN
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

/// Where `herald show` looks by default.
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/herald/herald.sock";

/// The RIB numbers neighbors with a u16; 0 is our own prefixes.
pub const MAX_NEIGHBORS: usize = u16::MAX as usize - 1;

/// Upper bound for `drain_time`: a stop that waits longer is a mistake.
const MAX_DRAIN_TIME: u64 = 3600;

/// Upper bound for `drain_prepend`; a few prepends already lose against
/// any other path.
const MAX_DRAIN_PREPEND: u8 = 10;

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
        // only at bind, and herald would run without its control socket.
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
    if time == 0 || time > herald_bgp::wire::GracefulRestart::MAX_RESTART_TIME {
        return Err(ConfigError::Invalid(format!(
            "{what} must be 1 to {}, got {time}",
            herald_bgp::wire::GracefulRestart::MAX_RESTART_TIME
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
        let dir = std::env::temp_dir().join(format!("herald-config-test-{}", std::process::id()));
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
}
