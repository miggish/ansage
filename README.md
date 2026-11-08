# ansage

BGP speaker that announces your own prefixes (anycast services, a VPS's IPv6
range) to one or more routers. It never re-exports routes; with `[kernel]` it
installs the best routes it learns into the Linux routing table.

## Running

```
ansage --config /etc/ansage/ansage.toml [--log-format text|json]
```

A minimal config:

```toml
asn = 64500
router_id = "203.0.113.1"
announce = ["192.0.2.0/24", "2001:db8:1::/48"]

[[neighbor]]
address = "10.0.0.1"
asn = 64501
```

The doc comments in `crates/ansage/src/config.rs` describe every setting. Some of them:

| setting | where | meaning |
|---|---|---|
| `password` / `password_file` | neighbor | TCP-MD5 key (RFC 2385); the file is read at (re)load, relative to the config |
| `ttl_security = 1` | neighbor | GTSM (RFC 5082): the neighbor is at most this many hops away |
| `listen = ["0.0.0.0:179", "[::]:179"]` | global | accept connections from configured neighbors (needs CAP_NET_BIND_SERVICE for 179) |
| `passive = true` | neighbor | never connect, wait for the neighbor (needs `listen`) |
| `metrics_listen = "127.0.0.1:9179"` | global | Prometheus metrics at `/metrics`; read-only JSON at `/api/summary`, `/api/peers` (`?peer=`), `/api/rib` (`?prefix=` or `?family=ipv4&limit=N`), `/api/fib`: the same as `ansage show ... --json`, for a dashboard; live updates at `/api/events` (Server-Sent Events: `summary` at once and every 5 s, `peer` on every session change). It includes session details and routes, so bind it to an address only trusted hosts reach. |
| `drain_time = 30` | global | on SIGTERM/SIGINT, drain this many seconds before closing the sessions (default 0) |
| `drain_prepend = 2` | neighbor | while drained, prepend our AS this many extra times (eBGP; for neighbors that ignore GRACEFUL_SHUTDOWN) |
| `control_socket` | global | unix socket for the CLI, default `/run/ansage/ansage.sock` (empty: off) |
| `[kernel]` | section | install learned best routes into the kernel: `table` (254), `metric` (20), `families` (both), `resolve_via_default` (false) |
| `install = false` | neighbor | keep this neighbor's routes out of the kernel (default true with `[kernel]`) |

### Operating it

```
ansage show summary | peers | peer NEIGHBOR | rib [PREFIX]
ansage announce PREFIX...        # at runtime, until restart
ansage withdraw PREFIX...
ansage peer NEIGHBOR disable [--reason TEXT] | enable | reset
ansage drain [--wait SECONDS]    # move traffic away, sessions stay up
ansage undrain
ansage reload                    # or SIGHUP / systemctl reload ansage
```

All client commands take `--json` and `-s SOCKET` (or `-c CONFIG` to find its
socket).

- **Health checks** live outside ansage: a script or timer that calls
  `ansage withdraw` when the service fails and `ansage announce` when it is back
  (with its own rise/fall counts against flapping).
- **Drain** (RFC 8326) takes a server out of an anycast set without a hard
  withdraw: our routes go out again with the GRACEFUL_SHUTDOWN community
  65535:0, LOCAL_PREF 0 on iBGP and `drain_prepend` extra prepends on eBGP, so
  routers move traffic to the other sites while this one still answers. FRR
  lowers such routes to LOCAL_PREF 0 by itself; BIRD needs a filter
  (`if (65535, 0) ~ bgp_community then bgp_local_pref = 0;`) or
  `drain_prepend`. `ansage drain --wait 30 && systemctl stop ansage` drains for
  30 s, then withdraws; `drain_time` does the same on every stop (a second
  SIGTERM ends the wait). The drain lasts until `ansage undrain`, survives a
  reload and ends with a restart or upgrade.
- **Reload** re-reads the file and applies only what changed: added
  neighbors connect, removed ones get Cease 6/3, changed ones reconnect with
  Cease 6/6, a new description changes nothing on the wire. Own prefixes follow
  the difference between the old and new file, so a prefix withdrawn at runtime
  stays withdrawn. `asn`, `router_id`, `listen`, `control_socket` and
  `metrics_listen` need a restart; a reload that changes them is refused as a
  whole, like an invalid file.

### Kernel routes (`[kernel]`)

With a `[kernel]` section, the best route of every prefix learned from a
neighbor with `import = "all"` goes into the kernel's routing table (protocol
`bgp`, `ip route show proto bgp`). Each BGP next hop is one kernel nexthop
object (ids from 3120562176 = 0xBA000000, `ip nexthop show`), so a next hop
that moves is one change, not one per route. Linux 5.3 or newer.

- A next hop is resolved through the kernel's own route to it: connected, or
  through that route's gateway (iBGP, multihop; for an ECMP route or a
  nexthop group, its first leg that is up). Routes learned by BGP and
  the default route do not count (`resolve_via_default = true` allows the
  latter). An IPv6 link-local next hop (RFC 2545) from a neighbor on a
  shared link goes out of the session's interface: used when the neighbor
  sends only a link-local next hop, and when its global one does not
  resolve. ansage watches interfaces, addresses and routes: when a next hop
  becomes unreachable its routes leave the kernel at once and the next best
  path takes over; what the kernel refuses is tried again every 30 s.
- Our own prefixes (`announce`, also after a runtime withdraw) never go in.
- `ansage show fib` lists the counts and every next hop (reachable through
  which gateway and interface, or not); `ansage show rib ADDRESS` shows the
  longest matching prefix and whether it is in the kernel. Metrics:
  `ansage_fib_routes`, `ansage_fib_next_hops`, `ansage_fib_errors_total`,
  `ansage_fib_adopted_routes`.
- `ansage` needs CAP_NET_ADMIN and netlink: the installer enables them in the
  unit when the config has `[kernel]`; otherwise ansage refuses to start and
  says what is missing.
- A stop removes ansage's routes. `ansage upgrade` and a crash leave them:
  the next start keeps them forwarding, replaces each as its neighbor sends
  it again, and removes the rest once every installing neighbor has sent
  End-of-RIB (at most 6 minutes). A reload moves the routes to a new `table`
  or `metric` without a gap; adding or removing `[kernel]` needs a restart.

### Upgrades without dropping routes (graceful restart)

With `graceful_restart = true` (off by default; `restart_time`, default 30 s,
also per neighbor), ansage and its neighbors use Graceful Restart (RFC 4724)
with the N bit (RFC 8538). How ansage goes away then decides what the
neighbors do with our routes:

| Event | ansage sends | Neighbors |
|---|---|---|
| `ansage upgrade` | Cease 6/2 "ansage restarting" (N bit) or nothing | keep our routes as stale, then refresh them |
| `systemctl stop` / SIGTERM, `peer disable` | Hard Reset (N bit) or Cease (after `drain_time`) | withdraw at once |
| ansage panics | Hard Reset / Cease from the panic hook | withdraw at once |
| kill -9, OOM kill | nothing | keep the routes for `restart_time` |

Deploying a new binary:

```sh
ansage upgrade --dry-run                  # per neighbor: keeps or withdraws our routes
install -m 0755 ansage /usr/local/bin/ansage.new
mv -f /usr/local/bin/ansage.new /usr/local/bin/ansage   # atomic; the running one is unaffected
ansage upgrade --binary /usr/local/bin/ansage || rollback
```

`ansage upgrade` checks the binary
(`--version`, `check` against the running config) before anything happens.
It refuses if an Established neighbor has no graceful restart (it would
withdraw) or if nothing would start ansage again (not under systemd), unless
`--force`. Then it exits ansage with status 75, which the unit restarts at
once, and waits until every neighbor is back with our full table. Exit 0 only
then, so a deploy script can roll back. `ansage check -c FILE` validates a
config on its own.

### Installing (systemd)

```sh
curl -fsSL https://github.com/miggish/ansage/releases/latest/download/install.sh \
  | sudo sh -s -- --config ./ansage.toml --operator "$USER"
```

The installer downloads the static binary for the machine (x86_64 or aarch64,
checked against `SHA256SUMS`), creates the system user and group `ansage`,
and installs `/usr/local/bin/ansage`, `/etc/ansage` (root:ansage, files 0640:
they may hold TCP-MD5 keys) and `dist/ansage.service`. Then it enables the
service and starts it once a config exists. `--operator USER` adds USER to
group `ansage`, which may use the control socket (`ansage show`, ...).

Running it again is safe: only changed files are replaced (the old ones are
kept as `.bak.<time>`), and a new config is checked with the new binary and
applied with a reload. A running ansage keeps the old binary until
`ansage upgrade`, or until you pass `--restart`, which runs it for you.
`ANSAGE_VERSION=v0.1.0` pins a release and `ANSAGE_BASE_URL` downloads from
another server. `--binary PATH` installs a local build instead. Releases
come from `.github/workflows/release.yml` on a `vX.Y.Z` tag.
`just install-test` runs the installer against systemd 252 and 255 in
(unprivileged) containers.

`dist/ansage.service` runs ansage as user `ansage` with `Type=notify-reload`
(readiness and reloads are reported to systemd; the installer switches to
`Type=notify` before systemd 253) and a hardened sandbox.

## Crates

| crate | what |
|---|---|
| `crates/ansage` | the daemon and its CLI (not published) |
| `crates/ansage-bgp` | BGP-4 messages and the session state machine, without I/O |
| `crates/ansage-netlink` | Linux rtnetlink messages for routes, nexthops, links and addresses |

## End-to-end tests

`test/e2e/` holds a container network in which ansage announces anycast
prefixes to real routers (FRR and BIRD), and test users send real traffic
(HTTP, ping, traceroute) through them. Scenarios assert on traffic and paths, on the
routers' view and on ansage's own view (its control socket).

```
 user1 --[u1]-- r1 (FRR) ----[core]---- r2 (BIRD) --[u2]-- user2
                 |              |              |
                [a]           srv-c           [b]
                 |                             |
               srv-a                         srv-b
```

Requirements: Docker with Compose, `just`, the Rust musl target
(`rustup target add x86_64-unknown-linux-musl`). podman is refused: it puts a
macvlan network without a parent on the host's LAN interface. All networks
are internal macvlan networks on a Docker dummy link, so nothing reaches the
host's LAN.

```sh
just e2e-up          # build ansage + the rogue peer, start the copies
just e2e             # default tier
just e2e-full        # everything (~5.5 min on 4 copies)
just e2e F4 R        # single scenarios or groups
test/e2e/run.sh -l   # list the scenarios
just e2e-sh r1       # shell in a container (copy 1)
just e2e-down
```

`E2E_JOBS` (default 4) sets how many identical copies of the network run side
by side; the scenarios are spread over them. `E2E_JOBS=1 test/e2e/run.sh ...` uses
copy 1 only and prints every scenario's output. Results, logs and state dumps
of failed scenarios go to `test/e2e/out/<run>/`.

Every pull request runs the default tier on GitHub Actions
(`.github/workflows/e2e.yml`, results as the `e2e-results` artifact); a
manual run of the workflow can choose the full tier or single scenarios.

M11 replays a fuzz corpus, which is not in git. Build it once with
`just fuzz decode -max_total_time=120 -max_len=4200` (cargo-fuzz on nightly);
without it M11 is skipped.

## License

MIT, see [LICENSE](LICENSE).
