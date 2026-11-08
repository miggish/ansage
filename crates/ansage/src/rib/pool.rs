//! Interned path attribute sets.
//!
//! A full table has around a million routes but far fewer distinct attribute
//! sets, so every set is stored once and routes refer to it by a 4-byte
//! [`AttrId`]. Sets are reference counted and freed when the last route
//! using them goes away.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use ansage_bgp::wire::{
    NextHop, Origin, PathAttr, SegmentType, decode_path_attrs, encode_next_hop, encode_path_attrs,
};
use bytes::{Bytes, BytesMut};

use crate::fib::Gateway;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AttrId(u32);

/// What best path selection needs, decoded once per set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    /// RFC 4271 §9.1.2.2: an AS_SET counts as 1, confederation segments as 0.
    pub as_path_len: u32,
    pub origin: Origin,
    /// First AS of the path, for comparing MEDs.
    pub neighbor_as: Option<u32>,
    /// NEXT_HOP (IPv4 routes); where the kernel forwards to.
    pub next_hop: Option<Ipv4Addr>,
    /// Carries GRACEFUL_SHUTDOWN 65535:0 (RFC 8326): the neighbor is about
    /// to go away.
    pub graceful_shutdown: bool,
}

impl Summary {
    fn of(attrs: &[PathAttr]) -> Self {
        let mut summary = Summary {
            local_pref: None,
            med: None,
            as_path_len: 0,
            origin: Origin::Incomplete,
            neighbor_as: None,
            next_hop: None,
            graceful_shutdown: false,
        };
        for attr in attrs {
            match attr {
                PathAttr::Origin(origin) => summary.origin = *origin,
                PathAttr::NextHop(addr) => summary.next_hop = Some(*addr),
                PathAttr::Communities(c) => {
                    summary.graceful_shutdown = c.contains(&ansage_bgp::wire::GRACEFUL_SHUTDOWN);
                }
                PathAttr::LocalPref(v) => summary.local_pref = Some(*v),
                PathAttr::MultiExitDisc(v) => summary.med = Some(*v),
                PathAttr::AsPath(path) => {
                    for segment in &path.segments {
                        summary.as_path_len += match segment.kind {
                            SegmentType::Sequence => segment.asns.len() as u32,
                            SegmentType::Set => 1,
                            SegmentType::ConfedSequence | SegmentType::ConfedSet => 0,
                        };
                    }
                    // Only a leading AS_SEQUENCE names the neighbor AS.
                    summary.neighbor_as = path
                        .segments
                        .first()
                        .filter(|s| s.kind == SegmentType::Sequence)
                        .and_then(|s| s.asns.first().copied());
                }
                _ => {}
            }
        }
        summary
    }
}

struct Slot {
    /// Canonical attribute bytes followed by the MP next hop, if any.
    key: Arc<[u8]>,
    attr_len: usize,
    mp_next_hop: Option<NextHop>,
    refs: u32,
    summary: Summary,
}

#[derive(Default)]
pub struct AttrPool {
    slots: Vec<Option<Slot>>,
    free: Vec<u32>,
    index: HashMap<Arc<[u8]>, u32>,
    scratch: BytesMut,
}

impl AttrPool {
    /// Interns `attrs` (sorted by type code, without MP attributes) plus the
    /// MP next hop of IPv6 routes, taking one reference.
    pub fn intern(&mut self, attrs: &[PathAttr], mp_next_hop: Option<&NextHop>) -> AttrId {
        self.scratch.clear();
        // Our own attributes always fit; an oversized set from a peer could
        // not have been received in the first place.
        encode_path_attrs(attrs, &mut self.scratch).expect("attributes fit 64 KiB");
        let attr_len = self.scratch.len();
        if let Some(next_hop) = mp_next_hop {
            encode_next_hop(next_hop, &mut self.scratch);
        }

        if let Some(&id) = self.index.get(&self.scratch[..]) {
            self.slot_mut(AttrId(id)).refs += 1;
            return AttrId(id);
        }
        let key: Arc<[u8]> = Arc::from(&self.scratch[..]);
        let slot = Slot {
            key: key.clone(),
            attr_len,
            mp_next_hop: mp_next_hop.copied(),
            refs: 1,
            summary: Summary::of(attrs),
        };
        let id = match self.free.pop() {
            Some(id) => {
                self.slots[id as usize] = Some(slot);
                id
            }
            None => {
                let id = u32::try_from(self.slots.len()).expect("fewer than 2^32 attribute sets");
                self.slots.push(Some(slot));
                id
            }
        };
        self.index.insert(key, id);
        AttrId(id)
    }

    /// Takes another reference to an existing set.
    pub fn retain(&mut self, id: AttrId) {
        self.slot_mut(id).refs += 1;
    }

    /// Drops one reference; frees the set when it was the last.
    pub fn release(&mut self, id: AttrId) {
        let slot = self.slot_mut(id);
        slot.refs -= 1;
        if slot.refs == 0 {
            let slot = self.slots[id.0 as usize].take().expect("live slot");
            self.index.remove(&slot.key);
            self.free.push(id.0);
        }
    }

    pub fn summary(&self, id: AttrId) -> &Summary {
        &self.slot(id).summary
    }

    pub fn mp_next_hop(&self, id: AttrId) -> Option<&NextHop> {
        self.slot(id).mp_next_hop.as_ref()
    }

    /// The next hop of a route with these attributes, whatever its family:
    /// the global MP next hop if there is one, else NEXT_HOP.
    pub fn next_hop(&self, id: AttrId) -> Option<IpAddr> {
        let slot = self.slot(id);
        match slot.mp_next_hop {
            Some(NextHop::V6 { global, .. }) => Some(IpAddr::V6(global)),
            Some(NextHop::V4(addr)) => Some(IpAddr::V4(addr)),
            None => slot.summary.next_hop.map(IpAddr::V4),
        }
    }

    /// The neighbor's RFC 2545 link-local next hop, if it sent one.
    pub fn link_local(&self, id: AttrId) -> Option<Ipv6Addr> {
        match self.slot(id).mp_next_hop {
            Some(NextHop::V6 { link_local, .. }) => link_local,
            _ => None,
        }
    }

    /// [`AttrPool::next_hop`] as a [`Gateway`], for a neighbor whose session
    /// runs over interface `oif` (None: not on a shared link).
    pub fn gateway(&self, id: AttrId, oif: Option<u32>) -> Option<Gateway> {
        let addr = self.next_hop(id)?;
        Some(Gateway::new(addr, self.link_local(id), oif))
    }

    /// [`AttrPool::forwarding_next_hop`] as a [`Gateway`].
    pub fn forwarding_gateway(&self, id: AttrId, ipv6: bool, oif: Option<u32>) -> Option<Gateway> {
        let addr = self.forwarding_next_hop(id, ipv6)?;
        Some(Gateway::new(addr, self.link_local(id), oif))
    }

    /// The address a route with these attributes is forwarded to: NEXT_HOP
    /// for IPv4 routes, the global MP next hop for IPv6 routes. None when
    /// missing, and for an IPv4 next hop of an IPv6 route (RFC 8950), which
    /// ansage does not install.
    pub fn forwarding_next_hop(&self, id: AttrId, ipv6: bool) -> Option<IpAddr> {
        let slot = self.slot(id);
        if !ipv6 {
            return slot.summary.next_hop.map(IpAddr::V4);
        }
        match slot.mp_next_hop {
            Some(NextHop::V6 { global, .. }) => Some(IpAddr::V6(global)),
            _ => None,
        }
    }

    /// The attributes, decoded again from their canonical bytes.
    pub fn attrs(&self, id: AttrId) -> Vec<PathAttr> {
        let slot = self.slot(id);
        let bytes = Bytes::copy_from_slice(&slot.key[..slot.attr_len]);
        decode_path_attrs(bytes).expect("canonical bytes decode")
    }

    /// Number of distinct sets in use.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    fn slot(&self, id: AttrId) -> &Slot {
        self.slots[id.0 as usize]
            .as_ref()
            .expect("live attribute set")
    }

    fn slot_mut(&mut self, id: AttrId) -> &mut Slot {
        self.slots[id.0 as usize]
            .as_mut()
            .expect("live attribute set")
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use ansage_bgp::wire::{AsPath, AsSegment};

    fn attrs(path: &[u32]) -> Vec<PathAttr> {
        vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence(path.to_vec())),
            PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
        ]
    }

    #[test]
    fn equal_sets_share_one_slot() {
        let mut pool = AttrPool::default();
        let a = pool.intern(&attrs(&[64501, 3356]), None);
        let b = pool.intern(&attrs(&[64501, 3356]), None);
        let c = pool.intern(&attrs(&[64501]), None);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.attrs(a), attrs(&[64501, 3356]));
    }

    #[test]
    fn next_hop_is_part_of_the_key() {
        let mut pool = AttrPool::default();
        let hop = |s: &str| NextHop::V6 {
            global: s.parse().unwrap(),
            link_local: None,
        };
        let a = pool.intern(&attrs(&[64501]), Some(&hop("2001:db8::1")));
        let b = pool.intern(&attrs(&[64501]), Some(&hop("2001:db8::2")));
        assert_ne!(a, b);
        assert_eq!(pool.mp_next_hop(b), Some(&hop("2001:db8::2")));
    }

    #[test]
    fn release_frees_and_reuses_slots() {
        let mut pool = AttrPool::default();
        let a = pool.intern(&attrs(&[1]), None);
        pool.retain(a);
        pool.release(a);
        assert_eq!(pool.len(), 1, "still one reference");
        pool.release(a);
        assert!(pool.is_empty());
        let b = pool.intern(&attrs(&[2]), None);
        assert_eq!(a, b, "slot reused");
    }

    #[test]
    fn summary() {
        let mut pool = AttrPool::default();
        let mut set = attrs(&[]);
        set[1] = PathAttr::AsPath(AsPath {
            segments: vec![
                AsSegment {
                    kind: SegmentType::Sequence,
                    asns: vec![64501, 3356],
                },
                AsSegment {
                    kind: SegmentType::Set,
                    asns: vec![1, 2, 3],
                },
            ],
        });
        set.push(PathAttr::MultiExitDisc(10));
        let id = pool.intern(&set, None);
        let s = pool.summary(id);
        assert_eq!(
            (s.as_path_len, s.neighbor_as, s.med),
            (3, Some(64501), Some(10))
        );
        assert_eq!((s.origin, s.local_pref), (Origin::Igp, None));
        assert_eq!(s.next_hop, Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn forwarding_next_hop() {
        let mut pool = AttrPool::default();
        let v4 = pool.intern(&attrs(&[64501]), None);
        assert_eq!(
            pool.forwarding_next_hop(v4, false),
            Some("192.0.2.1".parse().unwrap())
        );
        let global = NextHop::V6 {
            global: "2001:db8::1".parse().unwrap(),
            link_local: Some("fe80::1".parse().unwrap()),
        };
        let v6 = pool.intern(&attrs(&[64501])[..2], Some(&global));
        assert_eq!(
            pool.forwarding_next_hop(v6, true),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(pool.forwarding_next_hop(v6, false), None, "no NEXT_HOP");
        let rfc8950 = pool.intern(
            &attrs(&[64502])[..2],
            Some(&NextHop::V4(Ipv4Addr::LOCALHOST)),
        );
        assert_eq!(pool.forwarding_next_hop(rfc8950, true), None);
    }
}
