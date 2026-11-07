//! Passive side: accepts BGP connections and hands each one to the peer
//! task of the neighbor it comes from. Connections from other addresses are
//! closed at once.
//!
//! TCP-MD5 keys are set on the listening socket per neighbor, so the kernel
//! already checks the handshake. GTSM is split: the listener sends with TTL
//! 255 (inherited by every accepted connection, so the SYN-ACK passes the
//! peer's check), the minimum incoming TTL is set per connection after
//! accept, for the neighbors that use GTSM.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    os::fd::AsFd,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::config::Md5Key;
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{mpsc, watch},
};
use tracing::{debug, info, warn};

use super::sockopt;

/// Connections from one neighbor that wait for its peer task.
pub const QUEUE: usize = 2;

/// What the listener knows about one neighbor.
#[derive(Debug, Clone)]
pub struct Neighbor {
    pub address: IpAddr,
    pub md5_key: Option<Md5Key>,
    pub ttl_security: Option<u8>,
    /// The neighbor's peer task.
    pub tx: mpsc::Sender<TcpStream>,
}

/// The neighbors the listener hands connections to, by address; changed
/// by a config reload.
pub type Neighbors = Arc<RwLock<HashMap<IpAddr, Neighbor>>>;

pub fn neighbors(list: Vec<Neighbor>) -> Neighbors {
    Arc::new(RwLock::new(
        list.into_iter().map(|n| (n.address, n)).collect(),
    ))
}

/// Opens one listening socket per address. Neighbors (TCP-MD5 keys, GTSM)
/// are added with [`update`].
pub fn bind(addrs: &[SocketAddr]) -> io::Result<Vec<Arc<TcpListener>>> {
    addrs
        .iter()
        .map(|&addr| {
            bind_one(addr)
                .map(Arc::new)
                .map_err(|err| io::Error::new(err.kind(), format!("listen on {addr}: {err}")))
        })
        .collect()
}

fn bind_one(addr: SocketAddr) -> io::Result<TcpListener> {
    let v6 = addr.is_ipv6();
    let socket = if v6 {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    if v6 {
        // "[::]:179" next to "0.0.0.0:179" must not take the IPv4 side too.
        sockopt::set_v6only(socket.as_fd())?;
    }
    socket.bind(addr)?;
    socket.listen(64)
}

/// Updates the listening sockets when a neighbor is added (`old` None),
/// removed (`new` None) or changed: its TCP-MD5 key, and TTL 255 for GTSM.
pub fn update(
    listeners: &[Arc<TcpListener>],
    old: Option<&Neighbor>,
    new: Option<&Neighbor>,
) -> io::Result<()> {
    let Some(address) = new.or(old).map(|n| n.address) else {
        return Ok(());
    };
    let old_key = old.and_then(|n| n.md5_key.as_ref());
    let new_key = new.and_then(|n| n.md5_key.as_ref());
    for listener in listeners {
        let v6 = listener.local_addr()?.is_ipv6();
        if v6 != address.is_ipv6() {
            continue;
        }
        match new_key {
            Some(key) if old_key != Some(key) => {
                sockopt::set_md5(listener.as_fd(), address, key.as_bytes())?
            }
            Some(_) => {}
            // An empty key removes it.
            None if old_key.is_some() => sockopt::set_md5(listener.as_fd(), address, &[])?,
            None => {}
        }
        if new.is_some_and(|n| n.ttl_security.is_some()) {
            sockopt::set_max_ttl(listener.as_fd(), v6)?;
        }
    }
    Ok(())
}

/// Accepts on all `listeners` until `shutdown` flips to true.
pub async fn run(
    listeners: Vec<Arc<TcpListener>>,
    neighbors: Neighbors,
    shutdown: watch::Receiver<bool>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    for listener in listeners {
        tasks.spawn(accept_loop(listener, neighbors.clone(), shutdown.clone()));
    }
    while tasks.join_next().await.is_some() {}
}

async fn accept_loop(
    listener: Arc<TcpListener>,
    neighbors: Neighbors,
    mut shutdown: watch::Receiver<bool>,
) {
    let local = listener.local_addr().ok();
    loop {
        let (stream, from) = tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    // Out of file descriptors and the like: don't spin.
                    warn!(%err, ?local, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        hand_over(stream, from, &neighbors);
    }
}

fn hand_over(stream: TcpStream, from: SocketAddr, neighbors: &Neighbors) {
    let n = neighbors
        .read()
        .expect("never poisoned: no panics while held")
        .get(&from.ip())
        .cloned();
    let Some(n) = n else {
        // Scanners would flood the log at info.
        debug!(%from, "connection from an address that is not a neighbor, closed");
        return;
    };
    if let Some(hops) = n.ttl_security
        && let Err(err) = sockopt::set_gtsm(stream.as_fd(), from.is_ipv6(), hops)
    {
        warn!(%err, %from, "cannot set up GTSM on an incoming connection, closed");
        return;
    }
    match n.tx.try_send(stream) {
        Ok(()) => info!(%from, "incoming connection"),
        Err(mpsc::error::TrySendError::Full(_)) => {
            info!(%from, "incoming connection while others still wait, closed")
        }
        // The peer task is gone (shutting down).
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neighbor(address: &str, tx: mpsc::Sender<TcpStream>) -> Neighbor {
        Neighbor {
            address: address.parse().unwrap(),
            md5_key: None,
            ttl_security: None,
            tx,
        }
    }

    #[tokio::test]
    async fn hands_known_peers_over_and_closes_others() {
        let (tx, mut rx) = mpsc::channel(QUEUE);
        let known = neighbor("127.0.0.1", tx);
        let listeners = bind(&["127.0.0.1:0".parse().unwrap()]).unwrap();
        update(&listeners, None, Some(&known)).unwrap();
        let addr = listeners[0].local_addr().unwrap();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(run(listeners, neighbors(vec![known]), shutdown));

        let _ours = TcpStream::connect(addr).await.unwrap();
        let theirs = rx.recv().await.unwrap();
        assert_eq!(theirs.local_addr().unwrap(), addr);

        stop.send(true).unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn unknown_addresses_are_closed() {
        let (tx, mut rx) = mpsc::channel(QUEUE);
        let other = neighbor("127.0.0.2", tx);
        let listeners = bind(&["127.0.0.1:0".parse().unwrap()]).unwrap();
        let addr = listeners[0].local_addr().unwrap();
        let (_stop, shutdown) = watch::channel(false);
        tokio::spawn(run(listeners, neighbors(vec![other]), shutdown));

        let mut ours = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0; 1];
        use tokio::io::AsyncReadExt;
        let read = tokio::time::timeout(Duration::from_secs(1), ours.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "closed: {read:?}");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn ipv4_and_ipv6_on_the_same_port() {
        let v4 = bind(&["127.0.0.1:0".parse().unwrap()]).unwrap();
        let port = v4[0].local_addr().unwrap().port();
        // No IPv6 on this host: nothing more to test.
        if std::net::TcpListener::bind("[::1]:0").is_err() {
            return;
        }
        bind(&[format!("[::]:{port}").parse().unwrap()]).expect("v6only");
    }

    #[tokio::test]
    async fn keys_follow_neighbor_changes() {
        use crate::config::Md5Key;
        let listeners = bind(&["127.0.0.1:0".parse().unwrap()]).unwrap();
        let addr = listeners[0].local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(QUEUE);
        let plain = neighbor("127.0.0.1", tx);
        let signed = Neighbor {
            md5_key: Some(Md5Key::new("k1")),
            ..plain.clone()
        };
        let map = neighbors(vec![signed.clone()]);
        update(&listeners, None, Some(&signed)).unwrap();
        let (_stop, shutdown) = watch::channel(false);
        tokio::spawn(run(listeners.clone(), map.clone(), shutdown));

        let connect = |key: Option<&'static str>| async move {
            let socket = TcpSocket::new_v4().unwrap();
            if let Some(key) = key {
                sockopt::set_md5(socket.as_fd(), addr.ip(), key.as_bytes()).unwrap();
            }
            tokio::time::timeout(Duration::from_millis(500), socket.connect(addr)).await
        };
        assert!(connect(None).await.is_err(), "unsigned SYNs are dropped");
        let _c = connect(Some("k1")).await.unwrap().unwrap();
        rx.recv().await.unwrap();

        // The key is removed: plain connections work again.
        update(&listeners, Some(&signed), Some(&plain)).unwrap();
        map.write().unwrap().insert(plain.address, plain.clone());
        let _c = connect(None).await.unwrap().unwrap();
        rx.recv().await.unwrap();
    }
}
