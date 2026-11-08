//! Watches the kernel: interfaces, addresses, routes and nexthop objects.
//!
//! Anything that could change how a next hop is reached sends one
//! [`FibMsg::KernelChanged`]; the FIB then resolves every next hop again.
//! ansage's own routes and nexthop objects are left out, since ansage made
//! those changes itself.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    time::Duration,
};

use ansage_netlink::Body;

use ansage_netlink::RTNLGRP_IPV4_IFADDR;

use ansage_netlink::RTNLGRP_IPV4_ROUTE;

use ansage_netlink::RTNLGRP_IPV6_IFADDR;

use ansage_netlink::RTNLGRP_IPV6_ROUTE;

use ansage_netlink::RTNLGRP_LINK;

use ansage_netlink::RTNLGRP_NEXTHOP;

use ansage_netlink::RTPROT_BGP;

use ansage_netlink::Received;

use ansage_netlink::parse;

use ansage_netlink::socket::Socket;
use tracing::{error, info_span};

use super::{FibMsg, NEXTHOP_IDS};

const GROUPS: [u32; 6] = [
    RTNLGRP_LINK,
    RTNLGRP_IPV4_IFADDR,
    RTNLGRP_IPV6_IFADDR,
    RTNLGRP_IPV4_ROUTE,
    RTNLGRP_IPV6_ROUTE,
    RTNLGRP_NEXTHOP,
];

/// Room for bursts. Installing a full table sends a notification per route
/// here too (ours, ignored); when they overflow the buffer, the kernel
/// drops some and says so (ENOBUFS), which counts as a change.
const RECEIVE_BUFFER: usize = 8 * 1024 * 1024;

/// Whether a notification can change how a next hop is reached.
pub fn relevant(message: &Received) -> bool {
    match &message.body {
        Ok(Body::Route(route)) => {
            route.protocol != RTPROT_BGP && !route.nh_id.is_some_and(|id| NEXTHOP_IDS.contains(&id))
        }
        Ok(Body::Nexthop(nh)) => !NEXTHOP_IDS.contains(&nh.id),
        Ok(Body::Link(_) | Body::Address(_)) => true,
        Ok(_) => false,
        // Not understood: safer to look again.
        Err(_) => true,
    }
}

/// Starts the watching thread. It ends when the FIB is gone (at the next
/// notification after that) or with the process.
pub fn spawn(tx: std_mpsc::Sender<FibMsg>, pending: Arc<AtomicBool>) -> io::Result<()> {
    let mut socket = Socket::open()?;
    socket.set_receive_buffer(RECEIVE_BUFFER)?;
    // No timeout: notifications come when they come.
    socket.set_timeout(Duration::ZERO)?;
    for group in GROUPS {
        socket.join(group)?;
    }
    std::thread::Builder::new()
        .name("ansage-fib-events".into())
        .spawn(move || {
            let _span = info_span!("fib-events").entered();
            loop {
                let changed = match socket.recv() {
                    Ok(data) => parse(data).any(|m| m.map_or(true, |m| relevant(&m))),
                    Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => true,
                    Err(err) => {
                        error!(%err, "cannot read kernel notifications: changes to \
                            how next hops are reached go unnoticed until ansage restarts");
                        return;
                    }
                };
                // One queued message is enough for any number of changes.
                if changed
                    && !pending.swap(true, Ordering::Relaxed)
                    && tx.send(FibMsg::KernelChanged).is_err()
                {
                    return;
                }
            }
        })?;
    Ok(())
}
