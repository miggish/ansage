//! Route policy: filter rules, the route leak guard and RFC 9234 (roles,
//! Only-To-Customer). Pure functions over a route's attributes; the RIB uses
//! them for every route, and `ansage test` for one route it explains.

use std::{net::IpAddr, sync::Arc};

use ansage_bgp::wire::{AsPath, PathAttr, Prefix, SegmentType, path_len};

use crate::config::{Action, Config, ExportPolicy, ImportPolicy, NeighborRole, RouteSource, Rule};

/// Well-known communities (RFC 1997); without confederations,
/// NO_EXPORT_SUBCONFED means the same as NO_EXPORT.
const NO_EXPORT: u32 = 0xFFFF_FF01;
const NO_ADVERTISE: u32 = 0xFFFF_FF02;
const NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;

/// A filter from the config, by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub name: String,
    pub rules: Vec<Rule>,
}

impl Filter {
    /// The first rule that matches `route`, by index.
    pub fn first_match(&self, route: &RouteView) -> Option<usize> {
        self.rules.iter().position(|rule| matches(rule, route))
    }

    /// Accepts or rejects `route`; the matched rule tells which changes
    /// apply.
    pub fn verdict(&self, route: &RouteView) -> Verdict {
        let rule = self.first_match(route);
        Verdict {
            accept: rule.is_some_and(|i| self.rules[i].action == Action::Accept),
            rule,
        }
    }

    /// Some rule may accept a learned route.
    pub fn accepts_learned(&self) -> bool {
        self.rules.iter().any(Rule::accepts_learned)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub accept: bool,
    /// Index of the rule that decided; `None`: no rule matched (rejected).
    pub rule: Option<usize>,
}

/// Which learned routes a neighbor's routes go through, resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Import {
    #[default]
    None,
    All,
    Filter(Arc<Filter>),
}

/// Which routes a neighbor gets, resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Export {
    #[default]
    Own,
    None,
    Filter(Arc<Filter>),
}

impl Export {
    /// Learned routes may go out on this session.
    pub fn learned(&self) -> bool {
        match self {
            Export::Filter(filter) => filter.accepts_learned(),
            Export::Own | Export::None => false,
        }
    }
}

fn filter(config: &Config, name: &str) -> Arc<Filter> {
    // `Config::validate` checked that the name exists.
    let rules = config
        .filters
        .get(name)
        .map(|f| f.rules.clone())
        .unwrap_or_default();
    Arc::new(Filter {
        name: name.to_string(),
        rules,
    })
}

impl Import {
    pub fn new(config: &Config, policy: &ImportPolicy) -> Self {
        match policy {
            ImportPolicy::None => Self::None,
            ImportPolicy::All => Self::All,
            ImportPolicy::Filter(name) => Self::Filter(filter(config, name)),
        }
    }
}

impl Export {
    pub fn new(config: &Config, policy: &ExportPolicy) -> Self {
        match policy {
            ExportPolicy::Own => Self::Own,
            ExportPolicy::None => Self::None,
            ExportPolicy::Filter(name) => Self::Filter(filter(config, name)),
        }
    }
}

/// Where a route came from, as far as policy cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// One of our `announce` prefixes.
    Own,
    Learned {
        addr: IpAddr,
        role: Option<NeighborRole>,
        ibgp: bool,
    },
}

/// A route as filters see it: before the rewrite for the session it goes
/// out on.
#[derive(Debug, Clone, Copy)]
pub struct RouteView<'a> {
    pub prefix: Prefix,
    pub source: Source,
    pub attrs: &'a [PathAttr],
    /// Our AS: the origin of our own routes (their AS path is empty).
    pub local_asn: u32,
}

fn as_path(attrs: &[PathAttr]) -> Option<&AsPath> {
    attrs.iter().find_map(|a| match a {
        PathAttr::AsPath(path) => Some(path),
        _ => None,
    })
}

/// The AS that originated the route: the last AS of a trailing
/// AS_SEQUENCE (none after an AS_SET), ours for an empty path.
fn origin_as(route: &RouteView) -> Option<u32> {
    match as_path(route.attrs).and_then(|p| p.segments.last()) {
        None => Some(route.local_asn),
        Some(segment) if segment.kind == SegmentType::Sequence => segment.asns.last().copied(),
        Some(_) => None,
    }
}

fn communities(attrs: &[PathAttr]) -> &[u32] {
    attrs
        .iter()
        .find_map(|a| match a {
            PathAttr::Communities(list) => Some(list.as_slice()),
            _ => None,
        })
        .unwrap_or_default()
}

fn large_communities(attrs: &[PathAttr]) -> &[ansage_bgp::wire::LargeCommunity] {
    attrs
        .iter()
        .find_map(|a| match a {
            PathAttr::LargeCommunities(list) => Some(list.as_slice()),
            _ => None,
        })
        .unwrap_or_default()
}

fn matches(rule: &Rule, route: &RouteView) -> bool {
    let (own, role, addr) = match route.source {
        Source::Own => (true, None, None),
        Source::Learned { addr, role, .. } => (false, role, Some(addr)),
    };
    if let Some(source) = rule.source
        && (source == RouteSource::Own) != own
    {
        return false;
    }
    if !rule.from_role.is_empty() && !role.is_some_and(|r| rule.from_role.contains(&r)) {
        return false;
    }
    if !rule.from_neighbor.is_empty() && !addr.is_some_and(|a| rule.from_neighbor.contains(&a)) {
        return false;
    }
    if !rule.prefixes.is_empty() && !rule.prefixes.iter().any(|r| r.contains(&route.prefix)) {
        return false;
    }
    if !rule.origin_as.is_empty() && !origin_as(route).is_some_and(|a| rule.origin_as.contains(&a))
    {
        return false;
    }
    let path = as_path(route.attrs);
    if !rule.as_path_contains.is_empty()
        && !path.is_some_and(|p| {
            p.segments
                .iter()
                .any(|s| s.asns.iter().any(|a| rule.as_path_contains.contains(a)))
        })
    {
        return false;
    }
    if let Some(max) = rule.as_path_max_len
        && path.map_or(0, path_len) > max as usize
    {
        return false;
    }
    if !rule.communities.is_empty() {
        let have = communities(route.attrs);
        if !rule.communities.iter().any(|c| have.contains(&c.0)) {
            return false;
        }
    }
    if !rule.large_communities.is_empty() {
        let have = large_communities(route.attrs);
        if !rule.large_communities.iter().any(|c| have.contains(&c.0)) {
            return false;
        }
    }
    true
}

/// Applies an accepting rule's changes to `attrs` (kept sorted by type
/// code). `prepend` adds our AS in front of the path that many times.
pub fn apply(rule: &Rule, attrs: &mut Vec<PathAttr>, local_asn: u32) {
    if rule.prepend > 0 {
        let path = attrs.iter_mut().find_map(|a| match a {
            PathAttr::AsPath(path) => Some(path),
            _ => None,
        });
        if let Some(path) = path {
            for _ in 0..rule.prepend {
                *path = prepend(std::mem::take(path), local_asn);
            }
        }
    }
    if !rule.add_communities.is_empty() || !rule.remove_communities.is_empty() {
        let mut list = communities(attrs).to_vec();
        list.retain(|c| !rule.remove_communities.iter().any(|r| r.0 == *c));
        for c in &rule.add_communities {
            if !list.contains(&c.0) {
                list.push(c.0);
            }
        }
        set(attrs, PathAttr::Communities(list));
    }
    if !rule.add_large_communities.is_empty() || !rule.remove_large_communities.is_empty() {
        let mut list = large_communities(attrs).to_vec();
        list.retain(|c| !rule.remove_large_communities.iter().any(|r| r.0 == *c));
        for c in &rule.add_large_communities {
            if !list.contains(&c.0) {
                list.push(c.0);
            }
        }
        // RFC 8092 §3: no duplicates; sorted so equal sets intern once.
        list.sort_unstable();
        set(attrs, PathAttr::LargeCommunities(list));
    }
    if let Some(med) = rule.med {
        set(attrs, PathAttr::MultiExitDisc(med));
    }
    if let Some(pref) = rule.local_pref {
        set(attrs, PathAttr::LocalPref(pref));
    }
}

/// Replaces the attribute of the same type, or adds it; an empty community
/// list removes the attribute.
fn set(attrs: &mut Vec<PathAttr>, attr: PathAttr) {
    let code = attr.type_code();
    attrs.retain(|a| a.type_code() != code);
    let empty = matches!(&attr, PathAttr::Communities(l) if l.is_empty())
        || matches!(&attr, PathAttr::LargeCommunities(l) if l.is_empty());
    if !empty {
        attrs.push(attr);
    }
    attrs.sort_by_key(PathAttr::type_code);
}

/// `asn` in front of the path (a new segment when the first one is full or
/// a set).
pub fn prepend(mut path: AsPath, asn: u32) -> AsPath {
    use ansage_bgp::wire::AsSegment;
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

fn otc(attrs: &[PathAttr]) -> Option<u32> {
    attrs.iter().find_map(|a| match a {
        PathAttr::OnlyToCustomer(asn) => Some(*asn),
        _ => None,
    })
}

/// RFC 9234 §5 ingress, for a route from a neighbor with `role` and AS
/// `peer_asn`: `Err` with the reason when the route is a leak (ineligible),
/// otherwise the OTC attribute to add, if any.
pub fn ingress(
    role: Option<NeighborRole>,
    peer_asn: u32,
    attrs: &[PathAttr],
) -> Result<Option<PathAttr>, &'static str> {
    let Some(role) = role else {
        return Ok(None);
    };
    match (role, otc(attrs)) {
        (NeighborRole::Customer, Some(_)) => Err("route leak: OTC from a customer (RFC 9234)"),
        (NeighborRole::Peer, Some(asn)) if asn != peer_asn => {
            Err("route leak: OTC from a peer names another AS (RFC 9234)")
        }
        (NeighborRole::Provider | NeighborRole::Peer | NeighborRole::Rs, None) => {
            Ok(Some(PathAttr::OnlyToCustomer(peer_asn)))
        }
        _ => Ok(None),
    }
}

/// The leak guard: may a route from `source` go to a neighbor with
/// `target` role at all? `Err` says why not. Filters decide only what this
/// lets through.
pub fn guard(
    source: Source,
    target: Option<NeighborRole>,
    attrs: &[PathAttr],
) -> Result<(), &'static str> {
    let to_customer = target == Some(NeighborRole::Customer);
    // RFC 9234 §5 egress: OTC routes only go to customers.
    if otc(attrs).is_some() && target.is_some() && !to_customer {
        return Err("carries OTC: only for customers (RFC 9234)");
    }
    let Source::Learned { role, ibgp, .. } = source else {
        return Ok(());
    };
    // RFC 1997: learned routes only ever go to eBGP neighbors here.
    let well_known = communities(attrs);
    if well_known.contains(&NO_ADVERTISE) {
        return Err("carries NO_ADVERTISE");
    }
    if well_known.contains(&NO_EXPORT) || well_known.contains(&NO_EXPORT_SUBCONFED) {
        return Err("carries NO_EXPORT");
    }
    let Some(target) = target else {
        return Err("learned routes only go to neighbors with a role");
    };
    match role {
        Some(NeighborRole::Customer) => Ok(()),
        Some(NeighborRole::Provider | NeighborRole::Peer | NeighborRole::Rs) => {
            if target == NeighborRole::Customer {
                Ok(())
            } else {
                Err("from a provider, peer or route server: only for customers")
            }
        }
        None if ibgp && to_customer => Ok(()),
        None if ibgp => Err("learned over iBGP: only for customers"),
        None => Err("from an eBGP neighbor without role: never passed on"),
    }
}

/// RFC 9234 §5 egress: the OTC attribute to add for a neighbor with
/// `target` role, if any.
pub fn egress(
    target: Option<NeighborRole>,
    local_asn: u32,
    attrs: &[PathAttr],
) -> Option<PathAttr> {
    let marks = matches!(target, Some(NeighborRole::Customer | NeighborRole::Peer));
    (marks && otc(attrs).is_none()).then_some(PathAttr::OnlyToCustomer(local_asn))
}

#[cfg(test)]
mod tests;
