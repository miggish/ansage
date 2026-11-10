//! A blocking `NETLINK_ROUTE` socket, for the FIB and its event thread, tests
//! and the example.

use std::{
    collections::HashSet,
    io, mem,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    time::Duration,
};

use super::{Batch, Received, parse};

// linux/netlink.h; libc does not have all of them on every version.
const NETLINK_ROUTE: libc::c_int = 0;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_ADD_MEMBERSHIP: libc::c_int = 1;
const NETLINK_CAP_ACK: libc::c_int = 10;
const NETLINK_EXT_ACK: libc::c_int = 11;
const NETLINK_GET_STRICT_CHK: libc::c_int = 12;

/// Replies the kernel owes us arrive within milliseconds; this only guards
/// against waiting forever on a bug.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Socket {
    fd: OwnedFd,
    buf: Vec<u8>,
}

impl Socket {
    /// Opens and binds a socket with extended ACKs (error texts), capped ACKs
    /// (errors do not echo the whole request) and strict checking (the
    /// kernel rejects malformed requests and filters dumps).
    pub fn open() -> io::Result<Self> {
        // SAFETY: plain socket(2); the result is checked before use.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a new, valid descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let socket = Socket {
            fd,
            buf: vec![0; 64 * 1024],
        };
        for opt in [NETLINK_EXT_ACK, NETLINK_CAP_ACK, NETLINK_GET_STRICT_CHK] {
            socket.setsockopt(SOL_NETLINK, opt, &1i32)?;
        }
        socket.set_timeout(DEFAULT_TIMEOUT)?;
        // SAFETY: sockaddr_nl is plain data; all zero = kernel assigns the
        // port.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: addr is a valid sockaddr_nl of the given length.
        let rc = unsafe {
            libc::bind(
                socket.fd.as_raw_fd(),
                (&raw const addr).cast(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    /// Receives notifications of multicast group `group` (RTNLGRP_*).
    pub fn join(&self, group: u32) -> io::Result<()> {
        self.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group)
    }

    /// Asks for a receive buffer of `bytes`: above the system limit
    /// (net.core.rmem_max) with CAP_NET_ADMIN, else up to that limit.
    pub fn set_receive_buffer(&self, bytes: usize) -> io::Result<()> {
        let size = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX);
        self.setsockopt(libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, &size)
            .or_else(|_| self.setsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF, &size))
    }

    /// How long `recv` waits (a `TimedOut` error after that).
    pub fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        // `as _`: the field types, without naming libc's `time_t` and
        // `suseconds_t` (deprecated on musl until they become 64-bit).
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as _,
            tv_usec: timeout.subsec_micros() as _,
        };
        self.setsockopt(libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv)
    }

    fn setsockopt<T>(&self, level: libc::c_int, opt: libc::c_int, value: &T) -> io::Result<()> {
        // SAFETY: value points to a live T of the given size.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                level,
                opt,
                (value as *const T).cast(),
                mem::size_of::<T>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Sends one datagram to the kernel.
    pub fn send(&self, bytes: &[u8]) -> io::Result<()> {
        // SAFETY: bytes is valid for its length; the socket is bound, so
        // send() goes to the kernel (port 0).
        let n = unsafe { libc::send(self.fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != bytes.len() {
            return Err(io::Error::other("netlink: short send"));
        }
        Ok(())
    }

    /// Receives one datagram (one or more messages, see [`parse`]).
    pub fn recv(&mut self) -> io::Result<&[u8]> {
        let fd = self.fd.as_raw_fd();
        // Peek with MSG_TRUNC first: it returns the full datagram size, so the
        // buffer can grow instead of losing the end of a large dump part.
        // SAFETY: buf is valid for its length.
        let size = unsafe {
            libc::recv(
                fd,
                self.buf.as_mut_ptr().cast(),
                self.buf.len(),
                libc::MSG_PEEK | libc::MSG_TRUNC,
            )
        };
        if size < 0 {
            return Err(recv_error());
        }
        if size as usize > self.buf.len() {
            self.buf.resize(size as usize, 0);
        }
        // SAFETY: as above.
        let n = unsafe { libc::recv(fd, self.buf.as_mut_ptr().cast(), self.buf.len(), 0) };
        if n < 0 {
            return Err(recv_error());
        }
        Ok(&self.buf[..n as usize])
    }

    /// Sends `batch` and collects the replies to its requests until each one
    /// got its final message (ACK, error or end of dump). Errors of single
    /// requests are in the replies (`Body::Error`), not the `Err`.
    pub fn run(&mut self, batch: &Batch) -> io::Result<Vec<Received>> {
        let mut pending: HashSet<u32> = batch.requests().iter().map(|r| r.seq).collect();
        let mut replies = Vec::new();
        if pending.is_empty() {
            return Ok(replies);
        }
        self.send(batch.bytes())?;
        while !pending.is_empty() {
            let data = self.recv()?;
            for message in parse(data) {
                let message = message.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                // Late answers to an earlier batch are not ours.
                if !pending.contains(&message.header.seq) {
                    continue;
                }
                if message.body.as_ref().is_ok_and(|b| b.is_final()) {
                    pending.remove(&message.header.seq);
                }
                replies.push(message);
            }
        }
        Ok(replies)
    }
}

/// All addresses of `family` (AF_UNSPEC: both), with a socket of its own.
pub fn addresses(family: u8) -> io::Result<Vec<super::Address>> {
    let mut socket = Socket::open()?;
    let mut batch = Batch::new(1);
    batch.dump_addresses(family);
    let mut addresses = Vec::new();
    for reply in socket.run(&batch)? {
        match reply.body {
            Ok(super::Body::Address(a)) => addresses.push(a),
            Ok(super::Body::Error(err)) => return Err(io::Error::other(err)),
            _ => {}
        }
    }
    Ok(addresses)
}

fn recv_error() -> io::Error {
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, "netlink: no reply from the kernel")
    } else {
        // ENOBUFS: the kernel dropped messages for this socket.
        err
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
