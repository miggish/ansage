# herald-netlink

Linux rtnetlink (`NETLINK_ROUTE`) without a C library, from the
[herald](https://github.com/miggish/herald) BGP speaker: the subset needed
to install routes and to watch interfaces and addresses.

- Build requests into a `Batch` (several per buffer, one `send`): routes,
  nexthop objects and groups (ECMP), route lookups, dumps of links,
  addresses, routes and nexthops.
- Read replies and multicast events with `parse`.
- `socket::Socket` does the system calls (blocking).

Message building and parsing is pure code over byte buffers and is fuzzed.
Prefixes use the types of `herald-bgp`.

## Example

`examples/netlink.rs` reads the host's state (`netlink routes`,
`netlink lookup 1.1.1.1`) and has a demo that installs, moves and removes
routes in a throwaway network namespace.

## License

MIT, see [LICENSE](LICENSE).
