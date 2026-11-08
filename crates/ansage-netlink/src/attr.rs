//! Attributes (`struct rtattr`: length u16, type u16, value, padded to 4
//! bytes) and the request writer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{AF_INET, AF_INET6, HEADER_LEN, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};

/// Netlink pads messages and attributes to 4 bytes.
pub(crate) fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// Reads a u16 at `at`; the caller checked the length.
pub(crate) fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([buf[at], buf[at + 1]])
}

/// Reads a u32 at `at`; the caller checked the length.
pub(crate) fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Type bits of `rta_type` (the top two are the nested / byte order flags).
const TYPE_MASK: u16 = 0x3fff;

/// The attributes after a message's fixed header.
pub(crate) fn attrs(buf: &[u8]) -> Attrs<'_> {
    Attrs { buf }
}

pub(crate) struct Attrs<'a> {
    buf: &'a [u8],
}

/// An attribute whose length does not fit, with its type if it was readable.
#[derive(Debug)]
pub(crate) struct BadAttr(pub(crate) u16);

impl<'a> Iterator for Attrs<'a> {
    type Item = Result<(u16, &'a [u8]), BadAttr>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        if self.buf.len() < 4 {
            self.buf = &[];
            return Some(Err(BadAttr(0)));
        }
        let len = usize::from(u16_at(self.buf, 0));
        let kind = u16_at(self.buf, 2) & TYPE_MASK;
        if len < 4 || len > self.buf.len() {
            self.buf = &[];
            return Some(Err(BadAttr(kind)));
        }
        let value = &self.buf[4..len];
        self.buf = &self.buf[align(len).min(self.buf.len())..];
        Some(Ok((kind, value)))
    }
}

pub(crate) fn value_u32(value: &[u8]) -> Option<u32> {
    (value.len() == 4).then(|| u32_at(value, 0))
}

/// An address of `family` (4 or 16 bytes).
pub(crate) fn value_addr(family: u8, value: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET => <[u8; 4]>::try_from(value)
            .ok()
            .map(|a| IpAddr::V4(Ipv4Addr::from(a))),
        AF_INET6 => <[u8; 16]>::try_from(value)
            .ok()
            .map(|a| IpAddr::V6(Ipv6Addr::from(a))),
        _ => None,
    }
}

/// A NUL-terminated string (the NUL is optional).
pub(crate) fn value_str(value: &[u8]) -> String {
    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).into_owned()
}

pub(crate) fn family_of(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

/// One request in a [`Batch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub seq: u32,
    pub kind: u16,
    /// Answered by a series of messages and NLMSG_DONE instead of an ACK.
    pub dump: bool,
}

/// Requests written back to back into one buffer, to go out in one `send`.
///
/// Each request gets its own sequence number; every reply carries it. Every
/// request is answered by exactly one final message (ACK, error or DONE,
/// see [`super::Body::is_final`]), so a caller knows when a batch is done.
#[derive(Debug, Clone)]
pub struct Batch {
    buf: Vec<u8>,
    next_seq: u32,
    requests: Vec<Request>,
    /// Start of the message being written.
    open: Option<usize>,
}

impl Batch {
    /// An empty batch whose first request gets sequence number `first_seq`.
    pub fn new(first_seq: u32) -> Self {
        Self {
            buf: Vec::new(),
            next_seq: first_seq,
            requests: Vec::new(),
            open: None,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        debug_assert!(self.open.is_none());
        &self.buf
    }

    pub fn requests(&self) -> &[Request] {
        &self.requests
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Bytes written so far (callers keep a batch below the socket buffer).
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// The sequence number the next request will get.
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// Empties the batch; sequence numbers keep counting.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.requests.clear();
        self.open = None;
    }

    /// Starts a request. Dumps get `NLM_F_DUMP`, everything else `NLM_F_ACK`.
    pub(crate) fn begin(&mut self, kind: u16, flags: u16, dump: bool) -> u32 {
        debug_assert!(self.open.is_none());
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let flags = NLM_F_REQUEST | flags | if dump { NLM_F_DUMP } else { NLM_F_ACK };
        self.open = Some(self.buf.len());
        self.buf.extend_from_slice(&0u32.to_ne_bytes()); // length, set by end()
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(&flags.to_ne_bytes());
        self.buf.extend_from_slice(&seq.to_ne_bytes());
        self.buf.extend_from_slice(&0u32.to_ne_bytes()); // port: the kernel fills it in
        self.requests.push(Request { seq, kind, dump });
        seq
    }

    /// Appends raw bytes (a fixed header like `struct rtmsg`).
    pub(crate) fn put(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn attr(&mut self, kind: u16, value: &[u8]) {
        let len = u16::try_from(4 + value.len()).expect("attribute below 64 KiB");
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(value);
        self.buf.resize(align(self.buf.len()), 0);
    }

    pub(crate) fn attr_u32(&mut self, kind: u16, value: u32) {
        self.attr(kind, &value.to_ne_bytes());
    }

    pub(crate) fn attr_addr(&mut self, kind: u16, addr: &IpAddr) {
        match addr {
            IpAddr::V4(a) => self.attr(kind, &a.octets()),
            IpAddr::V6(a) => self.attr(kind, &a.octets()),
        }
    }

    /// Closes the request: writes its length.
    pub(crate) fn end(&mut self) {
        let start = self.open.take().expect("a request is open");
        let len = u32::try_from(self.buf.len() - start).expect("message below 4 GiB");
        debug_assert!(len as usize >= HEADER_LEN);
        self.buf[start..start + 4].copy_from_slice(&len.to_ne_bytes());
    }
}
