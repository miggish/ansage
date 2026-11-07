//! Replays one peer's full table from an MRT dump (TABLE_DUMP_V2, RFC 6396,
//! as published by RIPE RIS and RouteViews) over BGP, for load tests.
//!
//! ```text
//! zcat latest-bview.gz | cargo run --release --example replay -- list
//! zcat latest-bview.gz | cargo run --release --example replay -- serve --peer 3 --listen 127.0.0.3:179
//! ```
//!
//! `serve` loads the routes of one peer, then accepts BGP sessions (any
//! number, any peer AS) and sends each client the whole table followed by
//! End-of-RIB, pretending to be that peer (its AS and BGP identifier).
//! With `REPLAY_GRACEFUL_RESTART=SECS` it offers graceful restart (RFC 4724)
//! with that restart time, to load-test herald as a helper.

use std::{
    collections::HashMap,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use clap::{Parser, Subcommand};
use herald_bgp::{
    session::{Action, Event, Fsm, SessionConfig, State},
    wire::{
        Afi, Message, Negotiated, NextHop, PathAttr, Prefix, Prefix4, Prefix6, Safi, Update,
        decode_path_attrs, pack, split_message,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

const MRT_TABLE_DUMP_V2: u16 = 13;
const PEER_INDEX_TABLE: u16 = 1;
const RIB_IPV4_UNICAST: u16 = 2;
const RIB_IPV6_UNICAST: u16 = 4;
const MP_REACH_NLRI: u8 = 14;
/// Encoded UPDATEs per write.
const CHUNK: usize = 64 * 1024;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the peers in the dump with their route counts.
    List,
    /// Serve one peer's table over BGP.
    Serve {
        /// Peer index, as shown by `list`.
        #[arg(long)]
        peer: u16,
        #[arg(long, default_value = "127.0.0.3:179")]
        listen: SocketAddr,
    },
}

#[derive(Debug, Clone, Copy)]
struct Peer {
    bgp_id: Ipv4Addr,
    addr: IpAddr,
    asn: u32,
}

/// Routes sharing attributes and next hop.
struct Group {
    attrs: Vec<PathAttr>,
    next_hop: Option<NextHop>,
    prefixes: Vec<Prefix>,
}

struct Table {
    peer: Peer,
    groups: Vec<Group>,
    routes: [usize; 2],
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    match args.command {
        Command::List => list(io::stdin().lock()),
        Command::Serve { peer, listen } => {
            let started = Instant::now();
            let table = load(io::stdin().lock(), peer)?;
            eprintln!(
                "loaded peer {peer} ({} AS{}): {} IPv4 + {} IPv6 routes in {} attribute groups, {:.1}s",
                table.peer.addr,
                table.peer.asn,
                table.routes[0],
                table.routes[1],
                table.groups.len(),
                started.elapsed().as_secs_f64()
            );
            tokio::runtime::Runtime::new()?.block_on(serve(Arc::new(table), listen))
        }
    }
}

/// Calls `f` with the subtype and body of every TABLE_DUMP_V2 record.
fn records(
    mut input: impl Read,
    mut f: impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut header = [0u8; 12];
    let mut body = Vec::new();
    loop {
        match input.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
        let kind = u16::from_be_bytes([header[4], header[5]]);
        let subtype = u16::from_be_bytes([header[6], header[7]]);
        let len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
        body.resize(len, 0);
        input.read_exact(&mut body)?;
        if kind == MRT_TABLE_DUMP_V2 {
            f(subtype, &body)?;
        }
    }
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

/// Bounds-checked cursor over an MRT record.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(bad("truncated MRT record"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
}

/// RFC 6396 §4.3.1
fn peer_index(body: &[u8]) -> io::Result<Vec<Peer>> {
    let mut c = Cursor(body);
    c.u32()?; // collector BGP ID
    let name_len = c.u16()? as usize;
    c.take(name_len)?;
    let count = c.u16()?;
    let mut peers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let kind = c.u8()?;
        let bgp_id = Ipv4Addr::from(c.u32()?);
        let addr = if kind & 1 != 0 {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(c.take(16)?).unwrap()))
        } else {
            IpAddr::V4(Ipv4Addr::from(c.u32()?))
        };
        let asn = if kind & 2 != 0 {
            c.u32()?
        } else {
            u32::from(c.u16()?)
        };
        peers.push(Peer { bgp_id, addr, asn });
    }
    Ok(peers)
}

/// One RIB record (RFC 6396 §4.3.2): calls `f` with peer index and raw
/// attributes for every entry.
fn rib_entries(subtype: u16, body: &[u8], mut f: impl FnMut(Prefix, u16, &[u8])) -> io::Result<()> {
    let mut c = Cursor(body);
    c.u32()?; // sequence number
    let len = c.u8()?;
    let bytes = c.take((len as usize).div_ceil(8))?;
    let prefix = if subtype == RIB_IPV4_UNICAST {
        let mut octets = [0u8; 4];
        octets
            .get_mut(..bytes.len())
            .ok_or_else(|| bad("prefix too long"))?
            .copy_from_slice(bytes);
        Prefix::V4(Prefix4::new(octets.into(), len).map_err(|_| bad("bad prefix"))?)
    } else {
        let mut octets = [0u8; 16];
        octets
            .get_mut(..bytes.len())
            .ok_or_else(|| bad("prefix too long"))?
            .copy_from_slice(bytes);
        Prefix::V6(Prefix6::new(octets.into(), len).map_err(|_| bad("bad prefix"))?)
    };
    let count = c.u16()?;
    for _ in 0..count {
        let peer = c.u16()?;
        c.u32()?; // originated time
        let attr_len = c.u16()? as usize;
        f(prefix, peer, c.take(attr_len)?);
    }
    Ok(())
}

fn list(input: impl Read) -> io::Result<()> {
    let mut peers = Vec::new();
    let mut counts: HashMap<u16, [usize; 2]> = HashMap::new();
    records(input, |subtype, body| {
        match subtype {
            PEER_INDEX_TABLE => peers = peer_index(body)?,
            RIB_IPV4_UNICAST | RIB_IPV6_UNICAST => {
                let family = usize::from(subtype == RIB_IPV6_UNICAST);
                rib_entries(subtype, body, |_, peer, _| {
                    counts.entry(peer).or_default()[family] += 1;
                })?;
            }
            _ => {}
        }
        Ok(())
    })?;
    println!(
        "{:>5}  {:<40} {:>10} {:>9} {:>9}",
        "index", "address", "AS", "IPv4", "IPv6"
    );
    for (i, peer) in peers.iter().enumerate() {
        let [v4, v6] = counts.get(&(i as u16)).copied().unwrap_or_default();
        println!(
            "{i:>5}  {:<40} {:>10} {v4:>9} {v6:>9}",
            peer.addr.to_string(),
            peer.asn
        );
    }
    Ok(())
}

/// Splits raw MRT attributes into the attributes proper and the next hop of
/// the abbreviated MP_REACH_NLRI (RFC 6396 §4.3.4: only length + address).
fn split_mp(raw: &[u8]) -> Option<(Vec<u8>, Option<NextHop>)> {
    let mut attrs = Vec::with_capacity(raw.len());
    let mut next_hop = None;
    let mut c = Cursor(raw);
    while !c.0.is_empty() {
        let start = c.0;
        let flags = c.u8().ok()?;
        let code = c.u8().ok()?;
        let (len, header) = if flags & 0x10 != 0 {
            (c.u16().ok()? as usize, 4)
        } else {
            (c.u8().ok()? as usize, 3)
        };
        let value = c.take(len).ok()?;
        if code == MP_REACH_NLRI {
            let addr = |b: &[u8]| Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap());
            next_hop = match value.first() {
                Some(16) if value.len() >= 17 => Some(NextHop::V6 {
                    global: addr(&value[1..17]),
                    link_local: None,
                }),
                Some(32) if value.len() >= 33 => Some(NextHop::V6 {
                    global: addr(&value[1..17]),
                    link_local: Some(addr(&value[17..33])),
                }),
                _ => return None,
            };
        } else {
            attrs.extend_from_slice(&start[..header + len]);
        }
    }
    Some((attrs, next_hop))
}

fn load(input: impl Read, wanted: u16) -> io::Result<Table> {
    let mut peer = None;
    let mut index: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut groups: Vec<Group> = Vec::new();
    let mut routes = [0usize; 2];
    let mut skipped = 0usize;
    let mut bad_records = 0usize;
    records(input, |subtype, body| {
        match subtype {
            PEER_INDEX_TABLE => {
                let peers = peer_index(body)?;
                peer = Some(
                    *peers
                        .get(wanted as usize)
                        .ok_or_else(|| bad("no such peer index"))?,
                );
            }
            RIB_IPV4_UNICAST | RIB_IPV6_UNICAST => {
                // A broken record is skipped, not the whole dump.
                let parsed = rib_entries(subtype, body, |prefix, entry_peer, raw| {
                    if entry_peer != wanted {
                        return;
                    }
                    let Some((attrs, next_hop)) = split_mp(raw) else {
                        skipped += 1;
                        return;
                    };
                    // IPv6 routes need the MP next hop.
                    if prefix.afi() == Afi::IPV6 && next_hop.is_none() {
                        skipped += 1;
                        return;
                    }
                    let mut key = attrs.clone();
                    if let Some(NextHop::V6 { global, link_local }) = next_hop {
                        key.extend_from_slice(&global.octets());
                        key.extend(link_local.iter().flat_map(|l| l.octets()));
                    }
                    let i = match index.get(&key) {
                        Some(&i) => i,
                        None => {
                            let Ok(decoded) = decode_path_attrs(Bytes::from(attrs)) else {
                                skipped += 1;
                                return;
                            };
                            groups.push(Group {
                                attrs: decoded,
                                next_hop,
                                prefixes: Vec::new(),
                            });
                            index.insert(key, groups.len() - 1);
                            groups.len() - 1
                        }
                    };
                    groups[i].prefixes.push(prefix);
                    routes[usize::from(prefix.afi() == Afi::IPV6)] += 1;
                });
                if parsed.is_err() {
                    bad_records += 1;
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    if skipped > 0 {
        eprintln!("skipped {skipped} routes herald cannot decode");
    }
    if bad_records > 0 {
        eprintln!("skipped {bad_records} malformed RIB records");
    }
    Ok(Table {
        peer: peer.ok_or_else(|| bad("no PEER_INDEX_TABLE"))?,
        groups,
        routes,
    })
}

async fn serve(table: Arc<Table>, listen: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    eprintln!("listening on {listen}");
    loop {
        let (stream, remote) = listener.accept().await?;
        let table = table.clone();
        tokio::spawn(async move {
            eprintln!("{remote}: connected");
            match session(stream, table).await {
                Ok(()) => eprintln!("{remote}: session ended"),
                Err(err) => eprintln!("{remote}: {err}"),
            }
        });
    }
}

/// One client: wait for its OPEN to learn its AS, then run herald's FSM.
async fn session(stream: TcpStream, table: Arc<Table>) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();
    let mut rbuf = BytesMut::with_capacity(64 * 1024);
    let open = loop {
        if reader.read_buf(&mut rbuf).await? == 0 {
            return Err(bad("closed before OPEN"));
        }
        let mut peek = rbuf.clone();
        if let Some((kind, body)) =
            split_message(&mut peek, 4096).map_err(|e| bad(&e.to_string()))?
        {
            match Message::decode(kind, body, &Negotiated::default()) {
                Ok(Message::Open(open)) => break open,
                _ => return Err(bad("first message is not an OPEN")),
            }
        }
    };

    let router_id = if table.peer.bgp_id.is_unspecified() {
        Ipv4Addr::new(203, 0, 113, 250)
    } else {
        table.peer.bgp_id
    };
    let mut fsm = Fsm::new(SessionConfig {
        local_asn: table.peer.asn,
        router_id,
        peer_asn: open.asn(),
        hold_time: 90,
        connect_retry: Duration::from_secs(5),
        max_connect_retry: Duration::from_secs(5),
        jitter: true,
        passive: false,
        graceful_restart: std::env::var("REPLAY_GRACEFUL_RESTART")
            .ok()
            .and_then(|s| s.parse().ok()),
    });

    let (control_tx, mut control_rx) = mpsc::channel::<Bytes>(16);
    let (data_tx, mut data_rx) = mpsc::channel::<Bytes>(16);
    let write = tokio::spawn(async move {
        loop {
            let bytes = tokio::select! {
                biased;
                msg = control_rx.recv() => match msg { Some(b) => b, None => break },
                Some(b) = data_rx.recv() => b,
            };
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    let mut actions = Vec::new();
    let now = Instant::now;
    fsm.handle(Event::Start, now(), &mut actions);
    actions.clear();
    fsm.handle(Event::TcpConnected, now(), &mut actions);
    let mut data_tx = Some(data_tx);
    let mut received = 0usize;
    loop {
        // Feed every complete message we have.
        loop {
            let neg = fsm.negotiated();
            match split_message(&mut rbuf, fsm.max_receive_len()) {
                Ok(Some((kind, body))) => {
                    let event = match Message::decode(kind, body, &neg) {
                        Ok(m) => Event::Message(m),
                        Err(error) => Event::Malformed {
                            kind: Some(kind),
                            error,
                        },
                    };
                    fsm.handle(event, now(), &mut actions);
                }
                Ok(None) => break,
                Err(error) => {
                    fsm.handle(Event::Malformed { kind: None, error }, now(), &mut actions);
                    break;
                }
            }
        }
        for action in actions.drain(..) {
            match action {
                Action::Send(message) => {
                    let mut buf = BytesMut::new();
                    if message.encode(&fsm.negotiated(), &mut buf).is_ok() {
                        let _ = control_tx.send(buf.freeze()).await;
                    }
                }
                Action::Up(info) => {
                    eprintln!("established with AS{}, sending table", info.asn);
                    if let Some(tx) = data_tx.take() {
                        tokio::spawn(send_table(
                            table.clone(),
                            info.negotiated,
                            info.families,
                            tx,
                        ));
                    }
                }
                Action::Update(_) => received += 1,
                Action::Down(reason) => eprintln!("down: {reason:?} (received {received} UPDATEs)"),
                Action::Close => {
                    drop(control_tx);
                    let _ = write.await;
                    return Ok(());
                }
                // The replay never parks connections.
                Action::Connect
                | Action::RouteRefresh(_)
                | Action::AcceptParked
                | Action::RejectParked { .. }
                | Action::Retain(_) => {}
            }
        }
        if fsm.state() == State::Idle {
            return Ok(());
        }
        let deadline = fsm.next_deadline();
        tokio::select! {
            n = reader.read_buf(&mut rbuf) => {
                if n.unwrap_or(0) == 0 {
                    fsm.handle(Event::TcpClosed, now(), &mut actions);
                }
            }
            _ = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            } => fsm.on_timeout(now(), &mut actions),
        }
    }
}

async fn send_table(
    table: Arc<Table>,
    neg: Negotiated,
    families: Vec<(Afi, Safi)>,
    tx: mpsc::Sender<Bytes>,
) {
    let started = Instant::now();
    let wanted = |p: &Prefix| families.contains(&(p.afi(), Safi::UNICAST));
    let mut buf = BytesMut::with_capacity(2 * CHUNK);
    let mut messages = 0;
    for group in &table.groups {
        let prefixes: Vec<Prefix> = group.prefixes.iter().copied().filter(wanted).collect();
        match pack::announce(
            &mut buf,
            &neg,
            &group.attrs,
            group.next_hop.as_ref(),
            &prefixes,
        ) {
            Ok(n) => messages += n,
            Err(err) => eprintln!("cannot encode a group of {} routes: {err}", prefixes.len()),
        }
        if buf.len() >= CHUNK && tx.send(buf.split().freeze()).await.is_err() {
            return;
        }
    }
    for &(afi, safi) in &families {
        let _ = Message::Update(Update::end_of_rib(afi, safi)).encode(&neg, &mut buf);
    }
    let _ = tx.send(buf.freeze()).await;
    eprintln!(
        "table sent: {messages} UPDATEs in {:.2}s",
        started.elapsed().as_secs_f64()
    );
}
