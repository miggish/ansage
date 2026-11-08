//! What the FIB needs from the kernel, and the netlink implementation.
//!
//! The FIB logic talks to a [`Kernel`] so tests can run it against a fake;
//! [`Netlink`] turns the operations into rtnetlink requests, several per
//! datagram, and maps each answer back to its operation.

use std::{io, net::IpAddr};

use ansage_netlink::Batch;

use ansage_netlink::Body;

use ansage_netlink::KernelError;

use ansage_netlink::Nexthop;

use ansage_netlink::Route;

use ansage_netlink::socket::Socket;

/// One change to the kernel's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Create or replace a nexthop object.
    AddNexthop(Nexthop),
    /// Delete a nexthop object (and every route still using it).
    DeleteNexthop(u32),
    /// Create or replace a route.
    AddRoute(Route),
    DeleteRoute(Route),
}

/// Why an operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    /// The kernel refused it.
    Kernel(KernelError),
    /// The socket failed; the kernel's state is unknown.
    Io(String),
}

impl OpError {
    /// Short label for metrics and summaries: the errno name, or "io".
    pub fn reason(&self) -> String {
        match self {
            OpError::Kernel(e) => errno_name(e.errno),
            OpError::Io(_) => "io".into(),
        }
    }

    /// A delete of something that is not there (any more).
    pub fn is_not_found(&self) -> bool {
        matches!(self, OpError::Kernel(e) if e.errno == libc::ENOENT || e.errno == libc::ESRCH)
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpError::Kernel(e) => e.fmt(f),
            OpError::Io(e) => write!(f, "netlink: {e}"),
        }
    }
}

fn errno_name(errno: i32) -> String {
    let name = match errno {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::ENOMEM => "ENOMEM",
        libc::EEXIST => "EEXIST",
        libc::ENODEV => "ENODEV",
        libc::EINVAL => "EINVAL",
        libc::ENOSPC => "ENOSPC",
        libc::ENOBUFS => "ENOBUFS",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::ENETDOWN => "ENETDOWN",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::EHOSTUNREACH => "EHOSTUNREACH",
        other => return format!("errno {other}"),
    };
    name.into()
}

pub trait Kernel {
    /// Applies `ops` in order; one result per operation. A failed operation
    /// does not stop the ones after it.
    fn apply(&mut self, ops: &[Op]) -> Vec<Result<(), OpError>>;

    /// The routing entry the kernel uses for `addr` (`ip route get ADDR
    /// fibmatch`), out of interface `oif` when given; None when it has none.
    fn lookup(&mut self, addr: IpAddr, oif: Option<u32>) -> io::Result<Option<Route>>;

    /// All nexthop objects.
    fn nexthops(&mut self) -> io::Result<Vec<Nexthop>>;

    /// Nexthop object `id`, None when there is none.
    fn nexthop(&mut self, id: u32) -> io::Result<Option<Nexthop>>;

    /// The routes of `table` with `protocol`, both families.
    fn routes(&mut self, table: u32, protocol: u8) -> io::Result<Vec<Route>>;
}

/// Requests per datagram stop growing at this size. The kernel answers
/// each with an ACK of 36 bytes (more with an error text), all queued on
/// our socket before we read them, so the datagram size also bounds what
/// the receive buffer must hold.
const DATAGRAM: usize = 32 * 1024;
/// Receive buffer asked for: room for the ACKs of several datagrams and
/// for large dumps.
const RECEIVE_BUFFER: usize = 4 * 1024 * 1024;

/// The real kernel, over a `NETLINK_ROUTE` socket.
pub struct Netlink {
    socket: Socket,
    seq: u32,
}

impl Netlink {
    pub fn open() -> io::Result<Self> {
        let socket = Socket::open()?;
        socket.set_receive_buffer(RECEIVE_BUFFER)?;
        Ok(Self { socket, seq: 1 })
    }

    fn batch(&self) -> Batch {
        Batch::new(self.seq)
    }

    fn run(&mut self, batch: &Batch) -> io::Result<Vec<ansage_netlink::Received>> {
        self.seq = batch.next_seq();
        self.socket.run(batch)
    }
}

impl Kernel for Netlink {
    fn apply(&mut self, ops: &[Op]) -> Vec<Result<(), OpError>> {
        let mut results = Vec::with_capacity(ops.len());
        let mut rest = ops;
        while !rest.is_empty() {
            let mut batch = self.batch();
            let first = batch.next_seq();
            let mut taken = 0;
            for op in rest {
                if taken > 0 && batch.len() >= DATAGRAM {
                    break;
                }
                match op {
                    Op::AddNexthop(nh) => batch.add_nexthop(nh),
                    Op::DeleteNexthop(id) => batch.delete_nexthop(*id),
                    Op::AddRoute(route) => batch.add_route(route),
                    Op::DeleteRoute(route) => batch.delete_route(route),
                };
                taken += 1;
            }
            let start = results.len();
            results.resize(start + taken, Ok(()));
            match self.run(&batch) {
                Ok(replies) => {
                    for reply in replies {
                        let i = reply.header.seq.wrapping_sub(first) as usize;
                        if let (Ok(Body::Error(err)), Some(slot)) =
                            (reply.body, results.get_mut(start + i))
                        {
                            *slot = Err(OpError::Kernel(err));
                        }
                    }
                }
                Err(err) => {
                    // Nothing is known about this datagram or the rest.
                    let err = OpError::Io(err.to_string());
                    results.truncate(start);
                    results.resize(ops.len(), Err(err));
                    return results;
                }
            }
            rest = &rest[taken..];
        }
        results
    }

    fn lookup(&mut self, addr: IpAddr, oif: Option<u32>) -> io::Result<Option<Route>> {
        let mut batch = self.batch();
        batch.lookup_route_on(addr, oif);
        let mut found = None;
        for reply in self.run(&batch)? {
            match reply.body {
                Ok(Body::Route(route)) => found = Some(route),
                // ENETUNREACH and friends: no route at all.
                Ok(Body::Error(_)) => return Ok(None),
                _ => {}
            }
        }
        Ok(found)
    }

    fn routes(&mut self, table: u32, protocol: u8) -> io::Result<Vec<Route>> {
        let mut batch = self.batch();
        batch.dump_routes(ansage_netlink::AF_UNSPEC, table, protocol);
        let mut routes = Vec::new();
        for reply in self.run(&batch)? {
            match reply.body {
                // Strict checking filters in the kernel; checked again here.
                Ok(Body::Route(r)) if r.table == table && r.protocol == protocol => routes.push(r),
                Ok(Body::Error(err)) => return Err(io::Error::other(err)),
                _ => {}
            }
        }
        Ok(routes)
    }

    fn nexthop(&mut self, id: u32) -> io::Result<Option<Nexthop>> {
        let mut batch = self.batch();
        batch.get_nexthop(id);
        let mut found = None;
        for reply in self.run(&batch)? {
            match reply.body {
                Ok(Body::Nexthop(nh)) => found = Some(nh),
                Ok(Body::Error(err)) if err.errno == libc::ENOENT => return Ok(None),
                Ok(Body::Error(err)) => return Err(io::Error::other(err)),
                _ => {}
            }
        }
        Ok(found)
    }

    fn nexthops(&mut self) -> io::Result<Vec<Nexthop>> {
        let mut batch = self.batch();
        batch.dump_nexthops();
        let mut nexthops = Vec::new();
        for reply in self.run(&batch)? {
            match reply.body {
                Ok(Body::Nexthop(nh)) => nexthops.push(nh),
                Ok(Body::Error(err)) => return Err(io::Error::other(err)),
                _ => {}
            }
        }
        Ok(nexthops)
    }
}
