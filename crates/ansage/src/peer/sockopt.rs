//! Socket options for BGP sessions that std and tokio do not cover:
//! TCP-MD5 signatures (RFC 2385) and GTSM (RFC 5082).
//!
//! Both are set before `connect` (and, for a listener, before `listen`), so
//! the handshake is already protected. Linux only.

use std::{
    io,
    mem::{size_of, zeroed},
    net::IpAddr,
    os::fd::{AsRawFd, BorrowedFd},
};

use crate::config::MD5_MAX_KEY_LEN;

/// `struct tcp_md5sig` from linux/tcp.h (libc has the option, not the struct).
#[repr(C)]
struct TcpMd5Sig {
    addr: libc::sockaddr_storage,
    flags: u8,
    prefixlen: u8,
    keylen: u16,
    ifindex: libc::c_int,
    key: [u8; MD5_MAX_KEY_LEN],
}

/// Signs every segment to and from `peer` with `key` (RFC 2385). On a
/// listener it can be called once per peer. An empty key removes it.
///
/// Segments from `peer` without a valid signature are dropped by the
/// kernel, so a wrong key looks like a peer that does not answer.
pub fn set_md5(fd: BorrowedFd<'_>, peer: IpAddr, key: &[u8]) -> io::Result<()> {
    if key.len() > MD5_MAX_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TCP-MD5 key longer than {MD5_MAX_KEY_LEN} bytes"),
        ));
    }
    // SAFETY: all-zero is a valid value for this plain C struct.
    let mut sig: TcpMd5Sig = unsafe { zeroed() };
    write_sockaddr(&mut sig.addr, peer);
    sig.keylen = key.len() as u16;
    sig.key[..key.len()].copy_from_slice(key);
    setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_MD5SIG, &sig)
}

/// GTSM (RFC 5082) for a peer at most `hops` routers away (1 = directly
/// connected): we send with TTL / hop limit 255 and the kernel drops
/// everything that arrives with less than 256 - `hops`, so a packet from
/// further away cannot reach the session, not even its handshake.
///
/// `v6` is the socket's address family. Both ends have to enable it.
pub fn set_gtsm(fd: BorrowedFd<'_>, v6: bool, hops: u8) -> io::Result<()> {
    let min = 256 - libc::c_int::from(hops.max(1));
    set_max_ttl(fd, v6)?;
    if v6 {
        setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT, &min)
    } else {
        setsockopt(fd, libc::IPPROTO_IP, libc::IP_MINTTL, &min)
    }
}

/// Sends with TTL / hop limit 255, the outgoing half of GTSM.
pub fn set_max_ttl(fd: BorrowedFd<'_>, v6: bool) -> io::Result<()> {
    let ttl: libc::c_int = 255;
    if v6 {
        setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, &ttl)
    } else {
        setsockopt(fd, libc::IPPROTO_IP, libc::IP_TTL, &ttl)
    }
}

/// An IPv6 socket that does not also take IPv4 (mapped) connections.
pub fn set_v6only(fd: BorrowedFd<'_>) -> io::Result<()> {
    let on: libc::c_int = 1;
    setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &on)
}

fn write_sockaddr(storage: &mut libc::sockaddr_storage, addr: IpAddr) {
    let storage = storage as *mut libc::sockaddr_storage;
    match addr {
        IpAddr::V4(a) => {
            // SAFETY: sockaddr_storage is large and aligned enough for any
            // sockaddr.
            let sin = unsafe { &mut *storage.cast::<libc::sockaddr_in>() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = u32::from_ne_bytes(a.octets());
        }
        IpAddr::V6(a) => {
            // SAFETY: as above.
            let sin6 = unsafe { &mut *storage.cast::<libc::sockaddr_in6>() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr.s6_addr = a.octets();
        }
    }
}

fn setsockopt<T>(
    fd: BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
    // SAFETY: `value` points to a live T of the given size; the kernel
    // copies it before returning.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsFd, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpSocket, TcpStream},
    };

    const LOOP4: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    async fn listener(setup: impl FnOnce(&TcpSocket)) -> TcpListener {
        let socket = TcpSocket::new_v4().unwrap();
        setup(&socket);
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.listen(8).unwrap()
    }

    /// Connects with `setup` applied first; Err on refusal or after 500 ms.
    async fn connect(
        listener: &TcpListener,
        setup: impl FnOnce(&TcpSocket),
    ) -> io::Result<TcpStream> {
        let socket = TcpSocket::new_v4().unwrap();
        setup(&socket);
        let addr = listener.local_addr().unwrap();
        match tokio::time::timeout(Duration::from_millis(500), socket.connect(addr)).await {
            Ok(result) => result,
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
        }
    }

    /// Data passes both ways over an accepted connection.
    async fn talk(listener: &TcpListener, mut ours: TcpStream) {
        let (mut theirs, _) = listener.accept().await.unwrap();
        ours.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        theirs.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    fn md5(key: &'static [u8]) -> impl FnOnce(&TcpSocket) {
        move |s| set_md5(s.as_fd(), LOOP4, key).unwrap()
    }

    #[tokio::test]
    async fn md5_matching_keys_connect() {
        let l = listener(md5(b"e2e-secret")).await;
        let ours = connect(&l, md5(b"e2e-secret")).await.unwrap();
        talk(&l, ours).await;
    }

    #[tokio::test]
    async fn md5_mismatch_never_connects() {
        let l = listener(md5(b"e2e-secret")).await;
        let err = connect(&l, md5(b"wrong")).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // Unsigned SYNs are dropped too.
        let err = connect(&l, |_| {}).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn md5_rejects_long_keys() {
        let s = TcpSocket::new_v4().unwrap();
        let err = set_md5(s.as_fd(), LOOP4, &[b'x'; MD5_MAX_KEY_LEN + 1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        set_md5(s.as_fd(), LOOP4, &[b'x'; MD5_MAX_KEY_LEN]).unwrap();
    }

    fn gtsm(s: &TcpSocket) {
        set_gtsm(s.as_fd(), false, 1).unwrap();
    }

    #[tokio::test]
    async fn gtsm_both_ends_connect() {
        let l = listener(gtsm).await;
        let ours = connect(&l, gtsm).await.unwrap();
        talk(&l, ours).await;
    }

    #[tokio::test]
    async fn gtsm_drops_low_ttl() {
        // The peer answers with the default TTL (64): its SYN-ACK is dropped.
        let l = listener(|_| {}).await;
        let err = connect(&l, gtsm).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // A listener with GTSM drops our default-TTL SYN.
        let l = listener(gtsm).await;
        let err = connect(&l, |_| {}).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn gtsm_ipv6_options() {
        let s = std::net::TcpListener::bind("[::1]:0");
        // No IPv6 on this host: nothing to test.
        let Ok(s) = s else { return };
        set_gtsm(s.as_fd(), true, 2).unwrap();
    }
}
