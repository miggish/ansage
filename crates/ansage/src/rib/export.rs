//! Routes to peers: dirty prefixes, export batches and the Adj-RIB-Out.

use std::collections::HashMap;

use ansage_bgp::wire::{
    Afi, AsPath, NextHop, Origin, PathAttr, Prefix, Prefix4, Prefix6, Safi, Update, attr_flags,
};
use bytes::{Bytes, BytesMut};
use tracing::{debug, info, warn};

use super::{
    DEFAULT_LOCAL_PREF, EXPORT_BATCH, Outbound, PeerState, Rib, family_index,
    msg::{Announce, ExportBatch, PeerMsg, PeerSettings},
    pool::AttrId,
    table::{Change, LOCAL, Route, SourceId},
};
use crate::policy::{self, Export, RouteView};

/// 0.0.0.0/0 and ::/0, for `default_route`.
pub(super) fn default_routes() -> [Prefix; 2] {
    [
        Prefix::V4(Prefix4::new(std::net::Ipv4Addr::UNSPECIFIED, 0).expect("valid")),
        Prefix::V6(Prefix6::new(std::net::Ipv6Addr::UNSPECIFIED, 0).expect("valid")),
    ]
}

/// What a session can carry: from its OPEN, or assumed by `ansage test`
/// for a session that is not up.
#[derive(Debug, Clone, Copy)]
pub(super) struct SessionView {
    pub ibgp: bool,
    /// Negotiated, by family index.
    pub families: [bool; 2],
    /// A next hop to send routes of the family with.
    pub next_hops: [bool; 2],
}

impl SessionView {
    pub(super) fn of(state: &PeerState) -> Self {
        let afis = [Afi::IPV4, Afi::IPV6];
        Self {
            ibgp: state.up.info.negotiated.ibgp,
            families: afis.map(|afi| state.negotiated(afi)),
            next_hops: afis.map(|afi| !next_hop_missing(state, afi)),
        }
    }
}

/// Whether a session gets a prefix: the outgoing attributes (without
/// NEXT_HOP), why, and the filter rule that decided.
#[derive(Debug, Clone)]
pub(super) struct Decision {
    pub attrs: Option<Vec<PathAttr>>,
    pub reason: &'static str,
    pub rule: Option<usize>,
}

impl Decision {
    fn no(reason: &'static str) -> Self {
        Self {
            attrs: None,
            reason,
            rule: None,
        }
    }

    fn sent(attrs: Vec<PathAttr>, reason: &'static str, rule: Option<usize>) -> Self {
        Self {
            attrs: Some(attrs),
            reason,
            rule,
        }
    }
}

/// No next hop to send `afi` routes with. IPv4 routes can also use the IPv6
/// next hop once extended next hop (RFC 8950) is agreed.
fn next_hop_missing(state: &PeerState, afi: Afi) -> bool {
    let v6_missing = state.up.next_hop_ipv6.is_none();
    match afi {
        Afi::IPV4 => {
            state.up.next_hop_ipv4.is_none()
                && (v6_missing || !state.up.info.negotiated.extended_next_hop)
        }
        _ => v6_missing,
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
                 set next_hop_ipv4/next_hop_ipv6, or extended_next_hop for IPv4), \
                 its routes are not announced"
            );
        }
    }
}

/// Outgoing attributes for a route with attributes `attrs` (RFC 4271
/// §5.1), without NEXT_HOP (added per session when sending): eBGP prepends
/// our AS (`extra_prepend` more times) and drops LOCAL_PREF and MED; iBGP
/// adds LOCAL_PREF to our own routes. A learned route loses unknown
/// non-transitive attributes, and unknown transitive ones get PARTIAL.
fn export_attrs(
    attrs: Vec<PathAttr>,
    local_asn: u32,
    ibgp: bool,
    learned: bool,
    extra_prepend: u8,
) -> Vec<PathAttr> {
    let mut out = Vec::with_capacity(attrs.len() + 1);
    for attr in attrs {
        match attr {
            PathAttr::AsPath(mut path) if !ibgp => {
                for _ in 0..=extra_prepend {
                    path = policy::prepend(path, local_asn);
                }
                out.push(PathAttr::AsPath(path));
            }
            PathAttr::NextHop(_) => {}
            PathAttr::LocalPref(_) if !ibgp => {}
            PathAttr::MultiExitDisc(_) if !ibgp => {}
            PathAttr::Unknown { flags, .. } if learned && flags & attr_flags::TRANSITIVE == 0 => {}
            PathAttr::Unknown { flags, code, value } if learned => out.push(PathAttr::Unknown {
                flags: flags | attr_flags::PARTIAL,
                code,
                value,
            }),
            other => out.push(other),
        }
    }
    if ibgp && !out.iter().any(|a| matches!(a, PathAttr::LocalPref(_))) {
        out.push(PathAttr::LocalPref(DEFAULT_LOCAL_PREF));
    }
    out.sort_by_key(PathAttr::type_code);
    out
}

/// Encodes an export batch into UPDATE messages.
pub fn encode_batch(
    batch: &ExportBatch,
    neg: &ansage_bgp::wire::Negotiated,
) -> Result<Bytes, ansage_bgp::wire::EncodeError> {
    use ansage_bgp::wire::{Message, pack};
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
            let dirty = match &state.settings.export {
                // Nothing goes out, nothing to withdraw.
                Export::None => false,
                // Peers that may get learned routes care about every change.
                export if export.learned() => true,
                // The others care about our prefixes and about prefixes they
                // were sent before (to withdraw them). A learned route
                // replacing another learned route concerns neither, which
                // keeps a full table load cheap.
                Export::Own | Export::Filter(_) => {
                    involves_local || state.out.advertised.contains_key(&prefix)
                }
            };
            if dirty {
                state.out.dirty.insert(prefix);
            }
        }
    }

    /// Sessions with `default_route` re-check 0.0.0.0/0 and ::/0 (a provider
    /// session came up or went down).
    pub(super) fn default_routes_dirty(&mut self) {
        for state in self.peers.values_mut() {
            if state.settings.default_route {
                state.out.dirty.extend(default_routes());
            }
        }
    }

    /// The attributes (without NEXT_HOP) `peer` gets `prefix` with, if it
    /// gets it at all.
    pub(super) fn outgoing(&self, peer: SourceId, prefix: Prefix) -> Option<Vec<PathAttr>> {
        let state = self.peers.get(&peer)?;
        let best = match prefix {
            Prefix::V4(p) => self.v4.best(&p),
            Prefix::V6(p) => self.v6.best(&p),
        };
        self.decide(peer, &state.settings, SessionView::of(state), prefix, best)
            .attrs
    }

    /// Whether and how `peer` (with `settings`, on `session`) gets `prefix`
    /// whose best route is `best`: the leak guard, the export policy, the
    /// rewrite for the session and RFC 9234 egress. `best.attrs` must be in
    /// the pool.
    pub(super) fn decide(
        &self,
        peer: SourceId,
        settings: &PeerSettings,
        session: SessionView,
        prefix: Prefix,
        best: Option<Route>,
    ) -> Decision {
        let i = family_index(prefix.afi());
        if !session.families[i] {
            return Decision::no("family not negotiated");
        }
        if !session.next_hops[i] {
            return Decision::no("no next hop for this family");
        }
        let local_asn = self.config.local_asn;
        if settings.default_route && default_routes().contains(&prefix) {
            if !self.provider_up() {
                return Decision::no("default_route: no provider session is up");
            }
            let attrs = vec![
                PathAttr::Origin(Origin::Igp),
                PathAttr::AsPath(AsPath::default()),
            ];
            let mut out = export_attrs(attrs, local_asn, session.ibgp, false, 0);
            out.extend(policy::egress(settings.role, local_asn, &out));
            out.sort_by_key(PathAttr::type_code);
            return Decision::sent(out, "default_route", None);
        }
        let Some(best) = best else {
            return Decision::no("no route");
        };
        // Never send a route back where it came from.
        if best.source == peer {
            return Decision::no("came from this neighbor");
        }
        let own = best.source == LOCAL;
        let filter = match &settings.export {
            Export::None => return Decision::no("export none"),
            Export::Own if !own => return Decision::no("export own: a learned route"),
            Export::Own => None,
            Export::Filter(filter) => Some(filter),
        };
        let attrs = self.pool.attrs(best.attrs);
        let source = self.policy_source(best.source);
        if let Err(reason) = policy::guard(source, settings.role, &attrs) {
            return Decision::no(reason);
        }
        let mut rule = None;
        if let Some(filter) = filter {
            let view = RouteView {
                prefix,
                source,
                attrs: &attrs,
                local_asn,
            };
            let verdict = filter.verdict(&view);
            if !verdict.accept {
                return Decision {
                    attrs: None,
                    reason: if verdict.rule.is_some() {
                        "rejected by the export filter"
                    } else {
                        "no rule of the export filter matches"
                    },
                    rule: verdict.rule,
                };
            }
            rule = verdict.rule;
        }
        let extra_prepend = if own && self.drained.is_some() {
            settings.drain_prepend
        } else {
            0
        };
        let mut out = export_attrs(attrs, local_asn, session.ibgp, !own, extra_prepend);
        if let (Some(filter), Some(i)) = (filter, rule) {
            policy::apply(&filter.rules[i], &mut out, local_asn);
        }
        out.extend(policy::egress(settings.role, local_asn, &out));
        out.sort_by_key(PathAttr::type_code);
        let reason = if filter.is_some() {
            "accepted by the export filter"
        } else {
            "export own"
        };
        Decision::sent(out, reason, rule)
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
        // By outgoing attribute set.
        let mut groups: HashMap<AttrId, Vec<Prefix>> = HashMap::new();
        loop {
            let state = &self.peers[&peer];
            if !batch.is_empty() || state.out.dirty.is_empty() {
                break;
            }
            let take: Vec<Prefix> = state.out.dirty.iter().take(EXPORT_BATCH).copied().collect();
            let decided: Vec<(Prefix, Option<Vec<PathAttr>>)> = take
                .into_iter()
                .map(|prefix| (prefix, self.outgoing(peer, prefix)))
                .collect();
            let state = self.peers.get_mut(&peer).expect("checked");
            for (prefix, wanted) in decided {
                state.out.dirty.remove(&prefix);
                // The Adj-RIB-Out holds a reference to each set it names.
                let wanted = wanted.map(|attrs| self.pool.intern(&attrs, None));
                let current = state.out.advertised.get(&prefix).copied();
                if wanted == current {
                    if let Some(id) = wanted {
                        self.pool.release(id);
                    }
                    continue;
                }
                match wanted {
                    Some(id) => {
                        groups.entry(id).or_default().push(prefix);
                        state.out.advertised.insert(prefix, id);
                    }
                    None => {
                        batch.withdraw.push(prefix);
                        state.out.advertised.remove(&prefix);
                    }
                }
                if let Some(old) = current {
                    self.pool.release(old);
                }
            }
        }
        let state = self.peers.get_mut(&peer).expect("checked");
        if state.out.dirty.is_empty() && !state.out.eor_pending.is_empty() {
            batch.end_of_rib = std::mem::take(&mut state.out.eor_pending);
        }
        warn_missing_next_hops(state);

        let state = &self.peers[&peer];
        for (id, prefixes) in groups {
            let mut attrs = self.pool.attrs(id);
            if let Some(next_hop) = state.up.next_hop_ipv4 {
                attrs.push(PathAttr::NextHop(next_hop));
                attrs.sort_by_key(PathAttr::type_code);
            }
            let next_hop = state.up.next_hop_ipv6.map(|global| NextHop::V6 {
                global,
                link_local: state.up.next_hop_ipv6_link_local,
            });
            batch.announce.push(Announce {
                attrs,
                next_hop,
                prefixes,
            });
        }
        if batch.is_empty() {
            return None;
        }
        self.peers.get_mut(&peer).expect("checked").out.ready = false;
        Some(batch)
    }

    pub(super) fn release_outbound(&mut self, out: Outbound) {
        for attrs in out.advertised.into_values() {
            self.pool.release(attrs);
        }
    }
}
