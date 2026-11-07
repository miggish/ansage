# herald-bgp

BGP-4 (RFC 4271) without I/O, from the [herald](https://github.com/miggish/herald)
BGP speaker:

- `wire`: decode and encode OPEN, UPDATE, NOTIFICATION, KEEPALIVE and
  ROUTE-REFRESH for IPv4 and IPv6 unicast. 4-octet AS numbers (RFC 6793),
  extended messages (RFC 8654), graceful restart (RFC 4724), revised error
  handling (RFC 7606). Decoding is zero-copy over `bytes::Bytes`; `pack`
  fits many prefixes into as few UPDATEs as possible.
- `session`: the finite state machine (RFC 4271 §8). Events and the current
  time go in, actions come out (connect, send, close, routes up/down).
  Sockets and timers stay with you, so it runs on tokio, std or a simulation,
  and every protocol decision can be tested without a network.

Unicast only: no VPN, flowspec or other address families.

## Features

- `serde`: `Serialize` for the session state.

## Examples

The crate documentation builds and reads an UPDATE and starts a session.
`examples/replay.rs` replays a full table from an MRT dump over BGP,
`examples/rogue.rs` is a misbehaving peer for tests.

## License

MIT, see [LICENSE](LICENSE).
