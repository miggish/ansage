# ansage

ansage is a BGP router for Linux, written in Rust. It is growing into a
replacement for BIRD and FRR, and is safe by default: a new config sends only
your own prefixes and accepts nothing.

Today it announces your own prefixes (anycast services, a VPS's IPv6 range) to
one or more routers. With roles (RFC 9234) and filters it passes routes on to
customers; with `[kernel]` it installs the best routes it learns into the Linux
routing table.

- Runtime `ansage announce` / `ansage withdraw`, for health checks
- Drain (RFC 8326) before maintenance, upgrades without dropping routes (Graceful Restart)
- Filters and BGP roles that block route leaks; `ansage test` shows what happens to a route
- TCP-MD5, GTSM, Prometheus metrics, JSON API and live events
- Tested end to end against FRR and BIRD with real traffic

## Quickstart

```toml
# ansage.toml
asn = 64500
router_id = "203.0.113.1"
announce = ["192.0.2.0/24", "2001:db8:1::/48"]

[[neighbor]]
address = "10.0.0.1"
asn = 64501
```

```sh
curl -fsSL https://github.com/miggish/ansage/releases/latest/download/install.sh \
  | sudo sh -s -- --config ./ansage.toml --operator "$USER"
ansage show summary
```

## Docs

The docs are in [`docs/`](docs/) and published as a website
(`website/`):

- [Install](docs/01-getting-started/01-install.mdx) and [first session](docs/01-getting-started/02-first-session.mdx); [how ansage works](docs/02-concepts/01-how-it-works.mdx)
- Guides: [anycast](docs/03-guides/01-anycast.mdx), [router configs (FRR, BIRD)](docs/03-guides/02-router-config.mdx), [next hops](docs/03-guides/03-next-hops.mdx), [health checks](docs/03-guides/04-health-checks.mdx), [drain](docs/03-guides/05-drain.mdx), [one neighbor down](docs/03-guides/06-peer-maintenance.mdx), [reload](docs/03-guides/07-reload.mdx), [upgrades](docs/03-guides/08-upgrades.mdx), [learn routes](docs/03-guides/09-learn-routes.mdx), [transit and filters](docs/03-guides/10-transit.mdx), [test and shadow test](docs/03-guides/11-test.mdx), [kernel routes](docs/03-guides/12-kernel-routes.mdx), [metrics and API](docs/03-guides/13-metrics-api.mdx), [security](docs/03-guides/14-security.mdx), [without systemd](docs/03-guides/15-without-systemd.mdx), [troubleshooting](docs/03-guides/16-troubleshooting.mdx)
- Reference: [config](docs/04-reference/01-config.mdx) (generated from the doc comments in `crates/ansage/src/config.rs`), [CLI](docs/04-reference/02-cli.mdx), [HTTP API](docs/04-reference/03-http-api.mdx), [metrics](docs/04-reference/04-metrics.mdx), [signals, exit codes, files](docs/04-reference/05-runtime.mdx), [standards](docs/04-reference/06-standards.mdx)
- Development: [crates](docs/05-development/01-crates.mdx), [end-to-end tests](docs/05-development/02-e2e.mdx)

## Crates

| crate | what |
|---|---|
| `crates/ansage` | the daemon and its CLI (not published) |
| `crates/ansage-bgp` | BGP-4 messages and the session state machine, without I/O |
| `crates/ansage-netlink` | Linux rtnetlink messages for routes, nexthops, links and addresses |

## License

MIT, see [LICENSE](LICENSE).
