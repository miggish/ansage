//! Linux rtnetlink (`NETLINK_ROUTE`): the subset ansage needs to install
//! routes and to watch interfaces and addresses.
//!
//! Pure functions over byte buffers, no I/O. Requests
//! are written into a [`Batch`] (several per buffer, one `send`), replies are
//! read with [`parse`]. [`socket::Socket`] does the system calls.
//!
//! Layouts and numbers come from the kernel's uapi headers
//! (`linux/netlink.h`, `rtnetlink.h`, `nexthop.h`, `if_addr.h`, `if_link.h`);
//! the names below are theirs. Integers are in host byte order, addresses in
//! network byte order.
//!
//! # Installing a route through a nexthop object
//!
//! ```
//! use ansage_netlink::{Batch, Nexthop, RT_TABLE_MAIN, RTPROT_BGP, Route};
//!
//! let mut batch = Batch::new(1);
//! // Nexthop object 100: gateway 192.0.2.1 on interface 2.
//! batch.add_nexthop(&Nexthop::gateway(100, "192.0.2.1".parse()?, 2, RTPROT_BGP));
//! // 198.51.100.0/24 via that object, metric 20.
//! let dst = "198.51.100.0/24".parse()?;
//! batch.add_route(&Route::via_nexthop(dst, 100, RT_TABLE_MAIN, RTPROT_BGP, 20));
//! assert_eq!(batch.requests().len(), 2);
//!
//! // With CAP_NET_ADMIN, one `send` and the kernel's answer per request:
//! // let replies = ansage_netlink::socket::Socket::open()?.run(&batch)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod attr;
mod error;
mod link;
mod nexthop;
mod route;
pub mod socket;

#[cfg(test)]
mod tests;

pub use attr::Batch;
pub use error::{DecodeError, KernelError};
pub use link::{
    Address, IFA_F_DADFAILED, IFA_F_TENTATIVE, IFF_LOOPBACK, IFF_LOWER_UP, IFF_RUNNING, IFF_UP,
    Link,
};
pub use nexthop::{GroupMember, Nexthop};
pub use route::{Route, RouteHop};

/// `struct nlmsghdr`.
pub const HEADER_LEN: usize = 16;

// Message types (nlmsg_type).
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEXTHOP: u16 = 104;
pub const RTM_DELNEXTHOP: u16 = 105;
pub const RTM_GETNEXTHOP: u16 = 106;

// Header flags (nlmsg_flags).
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;
/// GET requests: all entries (`NLM_F_ROOT | NLM_F_MATCH`).
pub const NLM_F_DUMP: u16 = 0x300;
/// NEW requests: replace an existing entry.
pub const NLM_F_REPLACE: u16 = 0x100;
/// NEW requests: create the entry if it does not exist.
pub const NLM_F_CREATE: u16 = 0x400;
/// NLMSG_ERROR: the original request is not echoed (NETLINK_CAP_ACK).
pub const NLM_F_CAPPED: u16 = 0x100;
/// NLMSG_ERROR / NLMSG_DONE: extended ACK attributes follow.
pub const NLM_F_ACK_TLVS: u16 = 0x200;

// Address families.
pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

// Route protocols (rtm_protocol, nh_protocol). Values from 5 up are not
// interpreted by the kernel; `RTPROT_BGP` marks ansage's routes.
pub const RTPROT_KERNEL: u8 = 2;
pub const RTPROT_BOOT: u8 = 3;
pub const RTPROT_STATIC: u8 = 4;
pub const RTPROT_BGP: u8 = 186;

// Routing tables.
pub const RT_TABLE_UNSPEC: u32 = 0;
pub const RT_TABLE_MAIN: u32 = 254;
pub const RT_TABLE_LOCAL: u32 = 255;

// Route types (rtm_type).
pub const RTN_UNICAST: u8 = 1;
pub const RTN_LOCAL: u8 = 2;
pub const RTN_BROADCAST: u8 = 3;
pub const RTN_ANYCAST: u8 = 4;
pub const RTN_MULTICAST: u8 = 5;
pub const RTN_BLACKHOLE: u8 = 6;
pub const RTN_UNREACHABLE: u8 = 7;
pub const RTN_PROHIBIT: u8 = 8;

// Scopes (rtm_scope, ifa_scope).
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_HOST: u8 = 254;

// Next hop flags (rtm_flags low byte, nh_flags).
pub const RTNH_F_DEAD: u32 = 1;
pub const RTNH_F_ONLINK: u32 = 4;
pub const RTNH_F_LINKDOWN: u32 = 16;
/// RTM_GETROUTE: return the matching FIB entry, not the resolved host route.
pub const RTM_F_FIB_MATCH: u32 = 0x2000;

// Multicast groups (for event sockets).
pub const RTNLGRP_LINK: u32 = 1;
pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
pub const RTNLGRP_IPV4_ROUTE: u32 = 7;
pub const RTNLGRP_IPV6_IFADDR: u32 = 9;
pub const RTNLGRP_IPV6_ROUTE: u32 = 11;
pub const RTNLGRP_NEXTHOP: u32 = 32;

/// `struct nlmsghdr` without the length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    /// Port id of the sender (0 = kernel).
    pub port: u32,
}

/// One message read from the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub header: Header,
    /// An undecodable body does not stop the rest of a dump.
    pub body: Result<Body, DecodeError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// NLMSG_ERROR with error 0: the request `header.seq` succeeded.
    Ack,
    /// NLMSG_ERROR with an error, or a dump that ended with one.
    Error(KernelError),
    /// End of a dump (NLMSG_DONE).
    Done,
    /// RTM_NEWROUTE or RTM_DELROUTE (see `header.kind`).
    Route(Route),
    /// RTM_NEWNEXTHOP or RTM_DELNEXTHOP.
    Nexthop(Nexthop),
    /// RTM_NEWADDR or RTM_DELADDR.
    Address(Address),
    /// RTM_NEWLINK or RTM_DELLINK.
    Link(Link),
    /// NLMSG_NOOP or a type ansage does not read.
    Other,
}

impl Body {
    /// Ends the request it answers (every request ends with exactly one).
    pub fn is_final(&self) -> bool {
        matches!(self, Body::Ack | Body::Error(_) | Body::Done)
    }
}

/// Splits a buffer of received messages (one datagram) and decodes each.
///
/// A framing error (a length field that does not fit) ends the iteration,
/// because nothing after it can be found again.
pub fn parse(buf: &[u8]) -> Messages<'_> {
    Messages { buf }
}

pub struct Messages<'a> {
    buf: &'a [u8],
}

impl Iterator for Messages<'_> {
    type Item = Result<Received, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        if self.buf.len() < HEADER_LEN {
            self.buf = &[];
            return Some(Err(DecodeError::Truncated));
        }
        let len = attr::u32_at(self.buf, 0);
        let fits = usize::try_from(len).is_ok_and(|n| (HEADER_LEN..=self.buf.len()).contains(&n));
        if !fits {
            self.buf = &[];
            return Some(Err(DecodeError::BadLength(len)));
        }
        let len = len as usize;
        let header = Header {
            kind: attr::u16_at(self.buf, 4),
            flags: attr::u16_at(self.buf, 6),
            seq: attr::u32_at(self.buf, 8),
            port: attr::u32_at(self.buf, 12),
        };
        let body = decode_body(&header, &self.buf[HEADER_LEN..len]);
        self.buf = &self.buf[attr::align(len).min(self.buf.len())..];
        Some(Ok(Received { header, body }))
    }
}

fn decode_body(header: &Header, body: &[u8]) -> Result<Body, DecodeError> {
    match header.kind {
        NLMSG_ERROR => error::decode_error(header, body),
        NLMSG_DONE => error::decode_done(header, body),
        RTM_NEWROUTE | RTM_DELROUTE => Route::decode(header.kind, body).map(Body::Route),
        RTM_NEWNEXTHOP | RTM_DELNEXTHOP => Nexthop::decode(header.kind, body).map(Body::Nexthop),
        RTM_NEWADDR | RTM_DELADDR => Address::decode(header.kind, body).map(Body::Address),
        RTM_NEWLINK | RTM_DELLINK => Link::decode(header.kind, body).map(Body::Link),
        _ => Ok(Body::Other),
    }
}

/// Name of a route protocol as `ip route` prints it.
pub fn protocol_name(protocol: u8) -> Option<&'static str> {
    Some(match protocol {
        RTPROT_KERNEL => "kernel",
        RTPROT_BOOT => "boot",
        RTPROT_STATIC => "static",
        9 => "ra",
        11 => "zebra",
        12 => "bird",
        16 => "dhcp",
        RTPROT_BGP => "bgp",
        _ => return None,
    })
}
