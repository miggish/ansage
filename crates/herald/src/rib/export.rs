//! Routes to peers: dirty prefixes, export batches and the Adj-RIB-Out.

use std::collections::HashMap;

use crate::config::ExportPolicy;
use bytes::{Bytes, BytesMut};
use herald_bgp::wire::{
    Afi, AsPath, AsSegment, NextHop, PathAttr, Prefix, Safi, SegmentType, Update,
};
use tracing::{debug, info, warn};

use super::{
    DEFAULT_LOCAL_PREF, EXPORT_BATCH, Outbound, PeerState, Rib,
    msg::{Announce, ExportBatch, PeerMsg},
    pool::{AttrId, AttrPool},
    table::{Change, LOCAL, Route, SourceId},
};

/// The source attribute set to announce `prefix` with to `peer`, if any.
fn export_route(
    state: &PeerState,
    peer: SourceId,
    prefix: Prefix,
    best: Option<Route>,
) -> Option<AttrId> {
    let best = best?;
    // Never send a route back where it came from.
    if best.source == peer {
        return None;
    }
    let allowed = match state.settings.export {
        ExportPolicy::Own => best.source == LOCAL,
    };
    if !allowed || !state.negotiated(prefix.afi()) || next_hop_missing(state, prefix.afi()) {
        return None;
    }
    Some(best.attrs)
}

fn next_hop_missing(state: &PeerState, afi: Afi) -> bool {
    match afi {
        Afi::IPV4 => state.up.next_hop_ipv4.is_none(),
        _ => state.up.next_hop_ipv6.is_none(),
    }
}

fn warn_missing_next_hops(state: &mut PeerState) {
    for afi in [Afi::IPV4, Afi::IPV6] {
        if state.negotiated(afi)
            && next_hop_missing(state, afi)
            && !state.out.no_next_hop_warned.contains(&afi)
        {
            state.out.no_next_hop_warned.push(afi);
            warn!(
                peer = state.up.peer,
                ?afi,
                "no next hop for this family (session runs over the other family; \
                 set next_hop_ipv4/next_hop_ipv6), its routes are not announced"
            );
        }
    }
}

/// Outgoing attributes for a route with source set `attrs` (RFC 4271 §5.1):
/// eBGP prepends our AS (`extra_prepend` more times) and drops LOCAL_PREF;
/// iBGP adds LOCAL_PREF to our own routes. The next hop is always ourselves.
fn export_attrs(
    pool: &AttrPool,
    local_asn: u32,
    state: &PeerState,
    attrs: AttrId,
    extra_prepend: u8,
) -> (Vec<PathAttr>, Option<NextHop>) {
    let ibgp = state.up.info.negotiated.ibgp;
    let mut out = Vec::new();
    for attr in pool.attrs(attrs) {
        match attr {
            PathAttr::AsPath(mut path) if !ibgp => {
                for _ in 0..=extra_prepend {
                    path = prepend(path, local_asn);
                }
                out.push(PathAttr::AsPath(path));
            }
            PathAttr::NextHop(_) => {}
            PathAttr::LocalPref(_) if !ibgp => {}
            PathAttr::MultiExitDisc(_) if !ibgp => {}
            other => out.push(other),
        }
    }
    if let Some(next_hop) = state.up.next_hop_ipv4 {
        out.push(PathAttr::NextHop(next_hop));
    }
    if ibgp && !out.iter().any(|a| matches!(a, PathAttr::LocalPref(_))) {
        out.push(PathAttr::LocalPref(DEFAULT_LOCAL_PREF));
    }
    out.sort_by_key(PathAttr::type_code);
    let next_hop = state.up.next_hop_ipv6.map(|global| NextHop::V6 {
        global,
        link_local: state.up.next_hop_ipv6_link_local,
    });
    (out, next_hop)
}

fn prepend(mut path: AsPath, asn: u32) -> AsPath {
    match path.segments.first_mut() {
        Some(segment) if segment.kind == SegmentType::Sequence && segment.asns.len() < 255 => {
            segment.asns.insert(0, asn);
        }
        _ => path.segments.insert(
            0,
            AsSegment {
                kind: SegmentType::Sequence,
                asns: vec![asn],
            },
        ),
    }
    path
}

/// Encodes an export batch into UPDATE messages.
pub fn encode_batch(
    batch: &ExportBatch,
    neg: &herald_bgp::wire::Negotiated,
) -> Result<Bytes, herald_bgp::wire::EncodeError> {
    use herald_bgp::wire::{Message, pack};
    let mut buf = BytesMut::new();
    pack::withdraw(&mut buf, neg, &batch.withdraw)?;
    for group in &batch.announce {
        pack::announce(
            &mut buf,
            neg,
            &group.attrs,
            group.next_hop.as_ref(),
            &group.prefixes,
        )?;
    }
    for &afi in &batch.end_of_rib {
        Message::Update(Update::end_of_rib(afi, Safi::UNICAST)).encode(neg, &mut buf)?;
    }
    Ok(buf.freeze())
}

impl Rib {
    /// Builds export batches for every ready peer with pending work.
    pub fn flush(&mut self, out: &mut Vec<(SourceId, PeerMsg)>) {
        let peers: Vec<SourceId> = self.peers.keys().copied().collect();
        for peer in peers {
            if let Some(batch) = self.next_batch(peer) {
                out.push((peer, PeerMsg::Export(batch)));
            }
        }
    }

    /// The best route of `prefix` changed: re-evaluate it for every peer
    /// whose export could be affected.
    pub(super) fn mark_dirty(&mut self, prefix: Prefix, change: Change) {
        let local = |route: Option<Route>| route.is_some_and(|r| r.source == LOCAL);
        let learned = |route: Option<Route>| route.is_some_and(|r| r.source != LOCAL);
        let involves_local = local(change.before) || local(change.after);
        if let Some(fib) = &mut self.fib
            && (learned(change.before) || learned(change.after))
        {
            fib.dirty.insert(prefix);
        }
        for state in self.peers.values_mut() {
            match state.settings.export {
                // Own-only peers care about our prefixes and about prefixes
                // they were sent before (to withdraw them). A learned route
                // replacing another learned route concerns neither, which
                // keeps a full table load cheap.
                ExportPolicy::Own => {
                    if involves_local || state.out.advertised.contains_key(&prefix) {
                        state.out.dirty.insert(prefix);
                    }
                }
            }
        }
    }

    pub(super) fn route_refresh(&mut self, peer: SourceId, afi: Afi, safi: Safi) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        // RFC 2918 §4: ignore families we did not advertise.
        if safi != Safi::UNICAST || !state.negotiated(afi) {
            debug!(
                peer,
                ?afi,
                ?safi,
                "ignoring route refresh for a family not negotiated"
            );
            return;
        }
        info!(peer, ?afi, "route refresh requested");
        // Forget what was sent, so everything goes out again.
        let resend: Vec<Prefix> = state
            .out
            .advertised
            .keys()
            .filter(|p| p.afi() == afi)
            .copied()
            .collect();
        let mut released = Vec::new();
        for prefix in &resend {
            released.extend(state.out.advertised.remove(prefix));
        }
        state.out.dirty.extend(resend);
        for attrs in released {
            self.pool.release(attrs);
        }
    }

    fn next_batch(&mut self, peer: SourceId) -> Option<ExportBatch> {
        let state = self.peers.get(&peer)?;
        if !state.out.ready || (state.out.dirty.is_empty() && state.out.eor_pending.is_empty()) {
            return None;
        }
        let mut batch = ExportBatch::default();
        // By source attribute set; true: our own route.
        let mut groups: HashMap<AttrId, (bool, Vec<Prefix>)> = HashMap::new();
        let mut retain = Vec::new();
        let mut release = Vec::new();

        let state = self.peers.get_mut(&peer).expect("checked");
        while batch.is_empty() && !state.out.dirty.is_empty() {
            let take: Vec<Prefix> = state.out.dirty.iter().take(EXPORT_BATCH).copied().collect();
            for prefix in take {
                state.out.dirty.remove(&prefix);
                let best = match prefix {
                    Prefix::V4(p) => self.v4.best(&p),
                    Prefix::V6(p) => self.v6.best(&p),
                };
                let own = best.is_some_and(|r| r.source == LOCAL);
                let wanted = export_route(state, peer, prefix, best);
                let current = state.out.advertised.get(&prefix).copied();
                if wanted == current {
                    continue;
                }
                match wanted {
                    Some(attrs) => {
                        groups
                            .entry(attrs)
                            .or_insert((own, Vec::new()))
                            .1
                            .push(prefix);
                        retain.push(attrs);
                        state.out.advertised.insert(prefix, attrs);
                    }
                    None => {
                        batch.withdraw.push(prefix);
                        state.out.advertised.remove(&prefix);
                    }
                }
                release.extend(current);
            }
            if state.out.dirty.is_empty() {
                batch.end_of_rib = std::mem::take(&mut state.out.eor_pending);
            }
        }
        if state.out.dirty.is_empty() && !state.out.eor_pending.is_empty() {
            batch.end_of_rib = std::mem::take(&mut state.out.eor_pending);
        }
        warn_missing_next_hops(state);

        for (attrs, (own, prefixes)) in groups {
            let extra_prepend = if own && self.drained.is_some() {
                state.settings.drain_prepend
            } else {
                0
            };
            let (attrs, next_hop) = export_attrs(
                &self.pool,
                self.config.local_asn,
                state,
                attrs,
                extra_prepend,
            );
            batch.announce.push(Announce {
                attrs,
                next_hop,
                prefixes,
            });
        }
        for attrs in retain {
            self.pool.retain(attrs);
        }
        for attrs in release {
            self.pool.release(attrs);
        }
        if batch.is_empty() {
            return None;
        }
        state.out.ready = false;
        Some(batch)
    }

    pub(super) fn release_outbound(&mut self, out: Outbound) {
        for attrs in out.advertised.into_values() {
            self.pool.release(attrs);
        }
    }
}
