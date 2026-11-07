use herald_bgp::wire::{Afi, Notification};

use super::{
    link::{SharedLink, link_of},
    *,
};

#[test]
fn config_carries_md5_and_gtsm() {
    let text = "asn = 64500\nrouter_id = \"203.0.113.1\"\n[[neighbor]]\naddress = \"192.0.2.2\"\nasn = 64501\npassword = \"e2e-secret\"\nttl_security = 1\n";
    let config: Config = toml::from_str(text).unwrap();
    let n = &config.neighbors[0];
    let peer = PeerConfig::new(&config, 1, n, mpsc::channel(1).0);
    assert_eq!(peer.md5_key.as_ref().unwrap().as_bytes(), b"e2e-secret");
    assert_eq!(peer.ttl_security, Some(1));
    assert!(status::NeighborInfo::new(&config, 1, n).tcp_md5);
}

#[test]
fn shared_link_and_its_link_local_address() {
    let addr = |index, addr: &str, prefix_len, flags| herald_netlink::Address {
        index,
        addr: addr.parse().unwrap(),
        prefix_len,
        scope: 0,
        flags,
        label: None,
    };
    let addresses = [
        addr(2, "2001:db8:ff::1", 64, 0),
        addr(3, "fe80::3", 64, 0),
        addr(2, "fe80::2", 64, 0),
        addr(4, "10.0.0.1", 24, 0),
    ];
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
    assert_eq!(
        link_of(ip("2001:db8:ff::1"), ip("2001:db8:ff::9"), &addresses),
        Some(SharedLink {
            oif: 2,
            link_local: Some(v6("fe80::2"))
        })
    );
    // Multihop: the peer is not on our subnet.
    assert_eq!(
        link_of(ip("2001:db8:ff::1"), ip("2001:db8:1::9"), &addresses),
        None
    );
    // IPv4 session: the interface, but no link-local next hop of ours
    // (also on a link that has one).
    assert_eq!(
        link_of(
            ip("10.0.0.1"),
            ip("10.0.0.2"),
            &[addresses[3].clone(), addr(4, "fe80::4", 64, 0)]
        ),
        Some(SharedLink {
            oif: 4,
            link_local: None
        })
    );
    // IPv4 session on a link without IPv6.
    assert_eq!(
        link_of(ip("10.0.0.1"), ip("10.0.0.2"), &addresses),
        Some(SharedLink {
            oif: 4,
            link_local: None
        })
    );
    assert_eq!(link_of(ip("10.0.0.1"), ip("10.0.1.2"), &addresses), None);
    let tentative = [
        addresses[0].clone(),
        addr(2, "fe80::2", 64, herald_netlink::IFA_F_TENTATIVE),
    ];
    assert_eq!(
        link_of(ip("2001:db8:ff::1"), ip("2001:db8:ff::9"), &tentative),
        Some(SharedLink {
            oif: 2,
            link_local: None
        })
    );
    // A link-local session: its scope is the interface.
    let local = SocketAddr::V6(std::net::SocketAddrV6::new(v6("fe80::5"), 179, 0, 7));
    assert_eq!(
        shared_link(local, ip("fe80::6")),
        Some(SharedLink {
            oif: 7,
            link_local: Some(v6("fe80::5"))
        })
    );
}

/// A connected Connection and the peer's end of the socket.
async fn connected(flush: Duration) -> (Connection, TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ours = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (theirs, _) = listener.accept().await.unwrap();
    let conn = Connection::new(ours, Arc::default(), flush).unwrap();
    (conn, theirs)
}

fn cease() -> (Message, Vec<u8>) {
    let message = Message::Notification(Notification::admin_shutdown("bye"));
    let mut wire = BytesMut::new();
    message.encode(&Negotiated::default(), &mut wire).unwrap();
    (message, wire.to_vec())
}

#[tokio::test]
async fn close_waits_for_the_peer_to_read_the_notification() {
    let (conn, mut theirs) = connected(Duration::from_secs(5)).await;
    // Routes queued ahead of the NOTIFICATION still go out first.
    assert!(conn.send_data(Bytes::from_static(&[0xaa; 100_000])));
    let (message, wire) = cease();
    conn.send_control(&message, Negotiated::default());
    let writer = conn.close();

    // A well-behaved peer reads everything, then closes.
    let mut got = Vec::new();
    theirs.read_to_end(&mut got).await.unwrap();
    assert!(got.ends_with(&wire), "the NOTIFICATION arrives last");
    drop(theirs);
    // Our side finishes right after the peer's EOF, not at the timeout.
    tokio::time::timeout(Duration::from_secs(1), writer)
        .await
        .expect("finished after EOF")
        .unwrap();
}

#[tokio::test]
async fn close_gives_up_when_the_peer_does_not_close() {
    let (conn, _theirs) = connected(Duration::from_millis(200)).await;
    let (message, _) = cease();
    conn.send_control(&message, Negotiated::default());
    let start = Instant::now();
    // The peer never closes its end: we stop waiting after the timeout.
    conn.close().await.unwrap();
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(200) && took < Duration::from_secs(1),
        "{took:?}"
    );
}

#[tokio::test]
async fn close_during_a_stuck_send_resets_at_once() {
    // A big send to a peer that does not keep up.
    let (conn, mut theirs) = connected(Duration::from_secs(5)).await;
    assert!(conn.send_data(Bytes::from(vec![0xaa; 64 << 20])));
    // Let the writer fill the socket buffers and block.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (message, _) = cease();
    conn.send_control(&message, Negotiated::default());
    let start = Instant::now();
    conn.close().await.unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "no waiting for the timeout"
    );
    // The peer sees the connection reset, not a clean end.
    let mut buf = vec![0; 1 << 16];
    let err = loop {
        match theirs.read(&mut buf).await {
            Ok(0) => panic!("got FIN, expected a reset"),
            Ok(_) => continue,
            Err(err) => break err,
        }
    };
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
}

#[test]
fn counts_messages_in_a_batch() {
    let neg = Negotiated::default();
    let mut buf = BytesMut::new();
    for afi in [Afi::IPV4, Afi::IPV6] {
        Message::Update(Update::end_of_rib(afi, herald_bgp::wire::Safi::UNICAST))
            .encode(&neg, &mut buf)
            .unwrap();
    }
    Message::Keepalive.encode(&neg, &mut buf).unwrap();
    assert_eq!(count_messages(&buf), 3);
    assert_eq!(count_messages(&[]), 0);
    // A broken length field must not loop forever.
    let mut zero = vec![0xff; 16];
    zero.extend([0, 0, 4]);
    assert_eq!(count_messages(&zero), 0);
}
