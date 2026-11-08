//! The link a session shares with its peer: interface and our link-local
//! address (RFC 2545).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use tracing::debug;

/// The link a session shares with its peer: the interface (the peer's
/// RFC 2545 link-local next hops are reached through it) and our usable
/// link-local address on it (RFC 2545 §3, sent with our IPv6 next hop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SharedLink {
    pub(super) oif: u32,
    pub(super) link_local: Option<Ipv6Addr>,
}

/// The shared link: the scope of a link-local session address, else the
/// interface whose subnet holds both ends. None for multihop sessions.
/// Needs netlink (allowed by default, and by the systemd unit with
/// `[kernel]`); without it, none.
pub(super) fn shared_link(local: SocketAddr, peer: IpAddr) -> Option<SharedLink> {
    if let SocketAddr::V6(local) = local
        && local.ip().is_unicast_link_local()
        && local.scope_id() != 0
    {
        return Some(SharedLink {
            oif: local.scope_id(),
            link_local: Some(*local.ip()),
        });
    }
    // A dump of the addresses takes well under a millisecond, once per
    // session.
    match ansage_netlink::socket::addresses(ansage_netlink::AF_UNSPEC) {
        Ok(addresses) => link_of(local.ip(), peer, &addresses),
        Err(err) => {
            debug!(%err, "cannot read the interface addresses: no shared link known");
            None
        }
    }
}

pub(super) fn link_of(
    local: IpAddr,
    peer: IpAddr,
    addresses: &[ansage_netlink::Address],
) -> Option<SharedLink> {
    use ansage_bgp::wire::{Prefix4, Prefix6};
    use ansage_netlink::{IFA_F_DADFAILED, IFA_F_TENTATIVE};
    let ours = addresses.iter().find(|a| a.addr == local)?;
    let same_subnet = match (local, peer) {
        (IpAddr::V4(l), IpAddr::V4(p)) => {
            Prefix4::new(l, ours.prefix_len).ok() == Prefix4::new(p, ours.prefix_len).ok()
        }
        (IpAddr::V6(l), IpAddr::V6(p)) => {
            Prefix6::new(l, ours.prefix_len).ok() == Prefix6::new(p, ours.prefix_len).ok()
        }
        _ => false,
    };
    if !same_subnet {
        return None;
    }
    // Our link-local next hop only goes with IPv6 sessions: an IPv4 session
    // with a configured next_hop_ipv6 sends that alone (as before).
    let link_local = addresses.iter().find_map(|a| match a.addr {
        IpAddr::V6(addr)
            if local.is_ipv6()
                && a.index == ours.index
                && addr.is_unicast_link_local()
                && a.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED) == 0 =>
        {
            Some(addr)
        }
        _ => None,
    });
    Some(SharedLink {
        oif: ours.index,
        link_local,
    })
}
