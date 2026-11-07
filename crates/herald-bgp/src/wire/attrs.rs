use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};

use super::{
    Afi, DecodeError, EncodeError, Negotiated, Prefix, Prefix4, Prefix6, Safi, open::AS_TRANS,
    reader::Reader,
};
use attr_flags::{EXTENDED_LENGTH, OPTIONAL, PARTIAL, TRANSITIVE};
use type_code::*;

/// Path attribute flags (RFC 4271 §4.3).
pub mod attr_flags {
    pub const OPTIONAL: u8 = 0x80;
    pub const TRANSITIVE: u8 = 0x40;
    pub const PARTIAL: u8 = 0x20;
    pub const EXTENDED_LENGTH: u8 = 0x10;
}

/// Path attribute type codes (IANA registry).
pub mod type_code {
    pub const ORIGIN: u8 = 1;
    pub const AS_PATH: u8 = 2;
    pub const NEXT_HOP: u8 = 3;
    pub const MULTI_EXIT_DISC: u8 = 4;
    pub const LOCAL_PREF: u8 = 5;
    pub const ATOMIC_AGGREGATE: u8 = 6;
    pub const AGGREGATOR: u8 = 7;
    pub const COMMUNITIES: u8 = 8;
    pub const MP_REACH_NLRI: u8 = 14;
    pub const MP_UNREACH_NLRI: u8 = 15;
    pub const AS4_PATH: u8 = 17;
    pub const AS4_AGGREGATOR: u8 = 18;
    pub const LARGE_COMMUNITIES: u8 = 32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

impl Origin {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Igp,
            1 => Self::Egp,
            2 => Self::Incomplete,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SegmentType {
    Set = 1,
    Sequence = 2,
    /// RFC 5065
    ConfedSequence = 3,
    /// RFC 5065
    ConfedSet = 4,
}

impl SegmentType {
    pub fn is_confed(self) -> bool {
        matches!(self, Self::ConfedSequence | Self::ConfedSet)
    }

    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Set,
            2 => Self::Sequence,
            3 => Self::ConfedSequence,
            4 => Self::ConfedSet,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsSegment {
    pub kind: SegmentType,
    pub asns: Vec<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AsPath {
    pub segments: Vec<AsSegment>,
}

impl AsPath {
    /// A path of one AS_SEQUENCE; empty `asns` gives the empty path.
    pub fn sequence(asns: impl Into<Vec<u32>>) -> Self {
        let asns = asns.into();
        if asns.is_empty() {
            return Self::default();
        }
        Self {
            segments: vec![AsSegment {
                kind: SegmentType::Sequence,
                asns,
            }],
        }
    }

    fn decode(value: Bytes, four_octet: bool, err: DecodeError) -> Result<Self, DecodeError> {
        let mut r = Reader::new(value, err);
        let mut segments = Vec::new();
        while !r.is_empty() {
            let Some(kind) = SegmentType::from_u8(r.u8()?) else {
                return r.fail();
            };
            let count = usize::from(r.u8()?);
            if count == 0 {
                return r.fail();
            }
            let mut asns = Vec::with_capacity(count);
            for _ in 0..count {
                asns.push(if four_octet {
                    r.u32()?
                } else {
                    u32::from(r.u16()?)
                });
            }
            segments.push(AsSegment { kind, asns });
        }
        Ok(Self { segments })
    }

    /// Segments longer than 255 ASNs are split. Without 4-octet AS support,
    /// ASNs above 65535 become AS_TRANS.
    fn encode(&self, four_octet: bool, buf: &mut BytesMut) {
        for segment in &self.segments {
            for chunk in segment.asns.chunks(255) {
                buf.put_u8(segment.kind as u8);
                buf.put_u8(chunk.len() as u8);
                for &asn in chunk {
                    if four_octet {
                        buf.put_u32(asn);
                    } else {
                        buf.put_u16(u16::try_from(asn).unwrap_or(AS_TRANS));
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aggregator {
    pub asn: u32,
    pub addr: Ipv4Addr,
}

/// Well-known community GRACEFUL_SHUTDOWN 65535:0 (RFC 8326): the route is
/// about to go away, receivers should prefer any other path.
pub const GRACEFUL_SHUTDOWN: u32 = 0xFFFF_0000;

/// RFC 8092
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LargeCommunity {
    pub global_admin: u32,
    pub local_data_1: u32,
    pub local_data_2: u32,
}

/// A path attribute other than MP_REACH_NLRI / MP_UNREACH_NLRI. Those carry
/// routes rather than route properties and live in [`super::Update`] fields,
/// so a `Vec<PathAttr>` can be shared between all routes of an UPDATE.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathAttr {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(Ipv4Addr),
    MultiExitDisc(u32),
    LocalPref(u32),
    AtomicAggregate,
    Aggregator(Aggregator),
    /// RFC 1997
    Communities(Vec<u32>),
    /// RFC 6793
    As4Path(AsPath),
    /// RFC 6793
    As4Aggregator(Aggregator),
    LargeCommunities(Vec<LargeCommunity>),
    /// Kept as received so it can be passed on. `flags` holds only the
    /// OPTIONAL, TRANSITIVE and PARTIAL bits; the encoder picks the length
    /// format.
    Unknown {
        flags: u8,
        code: u8,
        value: Bytes,
    },
}

/// Required OPTIONAL/TRANSITIVE bits for the attributes we know.
fn expected_flags(code: u8) -> Option<u8> {
    match code {
        ORIGIN | AS_PATH | NEXT_HOP | LOCAL_PREF | ATOMIC_AGGREGATE => Some(TRANSITIVE),
        MULTI_EXIT_DISC | MP_REACH_NLRI | MP_UNREACH_NLRI => Some(OPTIONAL),
        AGGREGATOR | COMMUNITIES | AS4_PATH | AS4_AGGREGATOR | LARGE_COMMUNITIES => {
            Some(OPTIONAL | TRANSITIVE)
        }
        _ => None,
    }
}

impl PathAttr {
    pub fn type_code(&self) -> u8 {
        match self {
            PathAttr::Origin(_) => ORIGIN,
            PathAttr::AsPath(_) => AS_PATH,
            PathAttr::NextHop(_) => NEXT_HOP,
            PathAttr::MultiExitDisc(_) => MULTI_EXIT_DISC,
            PathAttr::LocalPref(_) => LOCAL_PREF,
            PathAttr::AtomicAggregate => ATOMIC_AGGREGATE,
            PathAttr::Aggregator(_) => AGGREGATOR,
            PathAttr::Communities(_) => COMMUNITIES,
            PathAttr::As4Path(_) => AS4_PATH,
            PathAttr::As4Aggregator(_) => AS4_AGGREGATOR,
            PathAttr::LargeCommunities(_) => LARGE_COMMUNITIES,
            PathAttr::Unknown { code, .. } => *code,
        }
    }

    /// Flags this attribute is sent with (EXTENDED_LENGTH is added as needed;
    /// the four unused low bits are always zero, RFC 4271 §4.3).
    pub fn flags(&self) -> u8 {
        match self {
            PathAttr::Unknown { flags, .. } => flags & (OPTIONAL | TRANSITIVE | PARTIAL),
            known => expected_flags(known.type_code()).unwrap_or(OPTIONAL | TRANSITIVE),
        }
    }

    pub(crate) fn encode(&self, neg: &Negotiated, buf: &mut BytesMut) -> Result<(), EncodeError> {
        put_attr(buf, self.flags(), self.type_code(), |buf| match self {
            PathAttr::Origin(origin) => buf.put_u8(*origin as u8),
            PathAttr::AsPath(path) => path.encode(neg.four_octet_as, buf),
            PathAttr::NextHop(addr) => buf.put_slice(&addr.octets()),
            PathAttr::MultiExitDisc(v) | PathAttr::LocalPref(v) => buf.put_u32(*v),
            PathAttr::AtomicAggregate => {}
            PathAttr::Aggregator(agg) => {
                if neg.four_octet_as {
                    buf.put_u32(agg.asn);
                } else {
                    buf.put_u16(u16::try_from(agg.asn).unwrap_or(AS_TRANS));
                }
                buf.put_slice(&agg.addr.octets());
            }
            PathAttr::Communities(communities) => {
                for c in communities {
                    buf.put_u32(*c);
                }
            }
            PathAttr::As4Path(path) => path.encode(true, buf),
            PathAttr::As4Aggregator(agg) => {
                buf.put_u32(agg.asn);
                buf.put_slice(&agg.addr.octets());
            }
            PathAttr::LargeCommunities(communities) => {
                for c in communities {
                    buf.put_u32(c.global_admin);
                    buf.put_u32(c.local_data_1);
                    buf.put_u32(c.local_data_2);
                }
            }
            PathAttr::Unknown { value, .. } => buf.put_slice(value),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextHop {
    V4(Ipv4Addr),
    /// RFC 2545: global address, optionally followed by a link-local one.
    V6 {
        global: Ipv6Addr,
        link_local: Option<Ipv6Addr>,
    },
}

/// MP_REACH_NLRI (RFC 4760). Only IPv4/IPv6 unicast is decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReach {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop: NextHop,
    pub nlri: Vec<Prefix>,
}

/// The only families herald negotiates; MP attributes for others are ignored.
fn supported(afi: Afi, safi: Safi) -> bool {
    safi == Safi::UNICAST && (afi == Afi::IPV4 || afi == Afi::IPV6)
}

impl MpReach {
    /// `None` for an address family we do not support (attribute discard).
    fn decode(value: Bytes, err: DecodeError) -> Result<Option<Self>, DecodeError> {
        let mut r = Reader::new(value, err);
        let afi = Afi(r.u16()?);
        let safi = Safi(r.u8()?);
        if !supported(afi, safi) {
            return Ok(None);
        }
        // RFC 7606 §7.11: a next-hop length that does not fit the family
        // means the NLRI cannot be located reliably (session reset).
        let next_hop = match (afi, r.u8()?) {
            (Afi::IPV4, 4) => NextHop::V4(Ipv4Addr::from(r.u32()?)),
            (Afi::IPV6, 16) => NextHop::V6 {
                global: read_ipv6(&mut r)?,
                link_local: None,
            },
            (Afi::IPV6, 32) => NextHop::V6 {
                global: read_ipv6(&mut r)?,
                link_local: Some(read_ipv6(&mut r)?),
            },
            _ => return r.fail(),
        };
        let _reserved = r.u8()?;
        let nlri = decode_mp_prefixes(afi, &mut r)?;
        Ok(Some(Self {
            afi,
            safi,
            next_hop,
            nlri,
        }))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) -> Result<(), EncodeError> {
        put_attr(buf, OPTIONAL, MP_REACH_NLRI, |buf| {
            buf.put_u16(self.afi.0);
            buf.put_u8(self.safi.0);
            put_next_hop(buf, &self.next_hop);
            buf.put_u8(0);
            for prefix in &self.nlri {
                prefix.encode(buf);
            }
        })
    }
}

/// Next-hop length and address(es) as in MP_REACH_NLRI.
pub(crate) fn put_next_hop(buf: &mut BytesMut, next_hop: &NextHop) {
    match next_hop {
        NextHop::V4(addr) => {
            buf.put_u8(4);
            buf.put_slice(&addr.octets());
        }
        NextHop::V6 {
            global,
            link_local: None,
        } => {
            buf.put_u8(16);
            buf.put_slice(&global.octets());
        }
        NextHop::V6 {
            global,
            link_local: Some(link_local),
        } => {
            buf.put_u8(32);
            buf.put_slice(&global.octets());
            buf.put_slice(&link_local.octets());
        }
    }
}

/// MP_UNREACH_NLRI (RFC 4760). Only IPv4/IPv6 unicast is decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreach {
    pub afi: Afi,
    pub safi: Safi,
    pub withdrawn: Vec<Prefix>,
}

impl MpUnreach {
    /// `None` for an address family we do not support (attribute discard).
    fn decode(value: Bytes, err: DecodeError) -> Result<Option<Self>, DecodeError> {
        let mut r = Reader::new(value, err);
        let afi = Afi(r.u16()?);
        let safi = Safi(r.u8()?);
        if !supported(afi, safi) {
            return Ok(None);
        }
        let withdrawn = decode_mp_prefixes(afi, &mut r)?;
        Ok(Some(Self {
            afi,
            safi,
            withdrawn,
        }))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) -> Result<(), EncodeError> {
        put_attr(buf, OPTIONAL, MP_UNREACH_NLRI, |buf| {
            buf.put_u16(self.afi.0);
            buf.put_u8(self.safi.0);
            for prefix in &self.withdrawn {
                prefix.encode(buf);
            }
        })
    }
}

fn read_ipv6(r: &mut Reader) -> Result<Ipv6Addr, DecodeError> {
    let mut octets = [0u8; 16];
    r.fill(&mut octets)?;
    Ok(octets.into())
}

fn decode_mp_prefixes(afi: Afi, r: &mut Reader) -> Result<Vec<Prefix>, DecodeError> {
    let mut prefixes = Vec::new();
    while !r.is_empty() {
        prefixes.push(match afi {
            Afi::IPV4 => Prefix::V4(Prefix4::decode(r)?),
            _ => Prefix::V6(Prefix6::decode(r)?),
        });
    }
    Ok(prefixes)
}

/// Writes one attribute. The value is written behind a 2-octet length; if it
/// turns out to fit in one octet, it is moved back by one byte. That avoids
/// both a scratch buffer and computing every value's length up front.
fn put_attr(
    buf: &mut BytesMut,
    flags: u8,
    code: u8,
    value: impl FnOnce(&mut BytesMut),
) -> Result<(), EncodeError> {
    let start = buf.len();
    buf.put_slice(&[flags | EXTENDED_LENGTH, code, 0, 0]);
    value(buf);
    let len = buf.len() - start - 4;
    if let Ok(short) = u8::try_from(len) {
        buf[start] = flags & !EXTENDED_LENGTH;
        buf[start + 2] = short;
        buf.copy_within(start + 4.., start + 3);
        buf.truncate(buf.len() - 1);
    } else if let Ok(long) = u16::try_from(len) {
        buf[start + 2..start + 4].copy_from_slice(&long.to_be_bytes());
    } else {
        buf.truncate(start);
        return Err(EncodeError::AttributeTooLong(code));
    }
    Ok(())
}

/// RFC 7606 §2 error handling approaches, ordered by strength. When an
/// UPDATE has several errors, the strongest wins (§3(h)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Handling {
    /// Drop just this attribute.
    Discard,
    /// Keep the session, treat all routes of the UPDATE as withdrawn.
    Withdraw,
    /// The rest of the message cannot be trusted: NOTIFICATION and close.
    Reset,
}

/// The path attributes section of an UPDATE, split as in [`super::Update`].
pub(crate) struct Attributes {
    pub(crate) attrs: Vec<PathAttr>,
    pub(crate) mp_reach: Option<MpReach>,
    pub(crate) mp_unreach: Option<MpUnreach>,
    /// Errors that call for treat-as-withdraw, with the attribute type code
    /// they concern (if known), so NEXT_HOP errors can be dropped later.
    pub(crate) withdraw: Vec<(Option<u8>, DecodeError)>,
    /// Errors that dropped a single attribute.
    pub(crate) discarded: Vec<DecodeError>,
    seen: [u64; 4],
}

impl Attributes {
    pub(crate) fn has(&self, code: u8) -> bool {
        self.seen[usize::from(code / 64)] & (1 << (code % 64)) != 0
    }

    fn mark(&mut self, code: u8) {
        self.seen[usize::from(code / 64)] |= 1 << (code % 64);
    }

    pub(crate) fn note_withdraw(&mut self, code: Option<u8>, err: DecodeError) {
        self.withdraw.push((code, err));
    }

    fn note(
        &mut self,
        handling: Handling,
        code: Option<u8>,
        err: DecodeError,
    ) -> Result<(), DecodeError> {
        match handling {
            Handling::Reset => return Err(err),
            Handling::Withdraw => self.note_withdraw(code, err),
            Handling::Discard => self.discarded.push(err),
        }
        Ok(())
    }
}

enum Decoded {
    Attr(PathAttr),
    MpReach(MpReach),
    MpUnreach(MpUnreach),
    /// Dropped with a logged reason (unsupported family, AS4_* from a
    /// 4-octet peer).
    Ignored(DecodeError),
    /// Dropped silently: LOCAL_PREF from an external peer (RFC 7606 §7.5).
    Dropped,
}

/// Decodes the path attributes with RFC 7606 error handling: only errors
/// that make the rest of the UPDATE unparsable reset the session; the others
/// withdraw the UPDATE's routes or drop one attribute.
pub(crate) fn decode_attributes(buf: Bytes, neg: &Negotiated) -> Result<Attributes, DecodeError> {
    let mut r = Reader::new(buf, DecodeError::MalformedAttributeList);
    let mut out = Attributes {
        attrs: Vec::new(),
        mp_reach: None,
        mp_unreach: None,
        withdraw: Vec::new(),
        discarded: Vec::new(),
        seen: [0; 4],
    };
    while !r.is_empty() {
        let started = r.peek_rest();
        // §4: an attribute running past the section is treat-as-withdraw; the
        // NLRI field is still found through the section length. But if it is
        // an MP attribute, its routes cannot be located (§3(j)): reset.
        let Ok((flags, code, value, raw)) = read_attr(&mut r) else {
            let handling = match started.get(1) {
                Some(&code) if is_mp(code) => Handling::Reset,
                _ => Handling::Withdraw,
            };
            out.note(handling, None, DecodeError::MalformedAttributeList)?;
            break;
        };

        // §3(g): duplicates of MP attributes reset, others keep the first.
        if out.has(code) {
            let handling = if is_mp(code) {
                Handling::Reset
            } else {
                Handling::Discard
            };
            out.note(handling, Some(code), DecodeError::MalformedAttributeList)?;
            continue;
        }
        out.mark(code);

        match decode_attr(flags, code, value, raw, neg) {
            Ok(Decoded::Attr(attr)) => out.attrs.push(attr),
            Ok(Decoded::MpReach(m)) => out.mp_reach = Some(m),
            Ok(Decoded::MpUnreach(m)) => out.mp_unreach = Some(m),
            Ok(Decoded::Ignored(err)) => out.note(Handling::Discard, Some(code), err)?,
            Ok(Decoded::Dropped) => {}
            Err((handling, err)) => out.note(handling, Some(code), err)?,
        }
    }
    Ok(out)
}

fn is_mp(code: u8) -> bool {
    code == MP_REACH_NLRI || code == MP_UNREACH_NLRI
}

/// Flags, type code, value and the complete raw attribute (for NOTIFICATION
/// data).
fn read_attr(r: &mut Reader) -> Result<(u8, u8, Bytes, Bytes), DecodeError> {
    let start = r.peek_rest();
    let flags = r.u8()?;
    let code = r.u8()?;
    let (len, header_len) = if flags & EXTENDED_LENGTH != 0 {
        (usize::from(r.u16()?), 4)
    } else {
        (usize::from(r.u8()?), 3)
    };
    let value = r.bytes(len)?;
    Ok((flags, code, value, start.slice(..header_len + len)))
}

fn decode_attr(
    flags: u8,
    code: u8,
    value: Bytes,
    raw: Bytes,
    neg: &Negotiated,
) -> Result<Decoded, (Handling, DecodeError)> {
    let Some(expected) = expected_flags(code) else {
        if flags & OPTIONAL == 0 {
            // RFC 7606 does not cover this case; RFC 4271 resets.
            return Err((
                Handling::Reset,
                DecodeError::UnrecognizedWellKnownAttribute(raw),
            ));
        }
        // The four unused low bits are ignored on receipt (RFC 4271 §4.3).
        return Ok(Decoded::Attr(PathAttr::Unknown {
            flags: flags & (OPTIONAL | TRANSITIVE | PARTIAL),
            code,
            value,
        }));
    };
    // RFC 7606 §7.5: LOCAL_PREF from an external peer is always discarded.
    if code == LOCAL_PREF && !neg.ibgp {
        return Ok(Decoded::Dropped);
    }
    // RFC 6793 §6: AS4_* must not be carried between 4-octet speakers.
    if neg.four_octet_as && (code == AS4_PATH || code == AS4_AGGREGATOR) {
        return Ok(Decoded::Ignored(DecodeError::OptionalAttribute(raw)));
    }

    // RFC 7606 §7 (and RFC 6793 §6 for AS4_*): what a malformed attribute
    // calls for. §3(c): flags errors use the same approach, and §3(f) turns
    // resets of ATOMIC_AGGREGATE / AGGREGATOR into attribute discard.
    let handling = match code {
        ATOMIC_AGGREGATE | AGGREGATOR | AS4_PATH | AS4_AGGREGATOR => Handling::Discard,
        MP_REACH_NLRI | MP_UNREACH_NLRI => Handling::Reset,
        _ => Handling::Withdraw,
    };
    // PARTIAL is only allowed on optional transitive attributes.
    let partial_ok = expected == OPTIONAL | TRANSITIVE;
    if flags & (OPTIONAL | TRANSITIVE) != expected || (flags & PARTIAL != 0 && !partial_ok) {
        return Err((handling, DecodeError::AttributeFlags(raw)));
    }
    decode_value(code, value, raw, neg).map_err(|err| (handling, err))
}

fn decode_value(
    code: u8,
    value: Bytes,
    raw: Bytes,
    neg: &Negotiated,
) -> Result<Decoded, DecodeError> {
    let mut r = Reader::new(value, DecodeError::AttributeLength(raw.clone()));
    let attr = match code {
        ORIGIN => {
            let origin = Origin::from_u8(r.u8()?);
            PathAttr::Origin(origin.ok_or_else(|| DecodeError::InvalidOrigin(raw.clone()))?)
        }
        AS_PATH => {
            let path = AsPath::decode(r.rest(), neg.four_octet_as, DecodeError::MalformedAsPath)?;
            // RFC 5065 §5: herald is in no confederation, so confederation
            // segments from any neighbor make the AS_PATH malformed.
            if path.segments.iter().any(|s| s.kind.is_confed()) {
                return Err(DecodeError::MalformedAsPath);
            }
            PathAttr::AsPath(path)
        }
        NEXT_HOP => {
            let addr = Ipv4Addr::from(r.u32()?);
            if addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast() {
                return Err(DecodeError::InvalidNextHop(raw));
            }
            PathAttr::NextHop(addr)
        }
        MULTI_EXIT_DISC => PathAttr::MultiExitDisc(r.u32()?),
        LOCAL_PREF => PathAttr::LocalPref(r.u32()?),
        ATOMIC_AGGREGATE => PathAttr::AtomicAggregate,
        AGGREGATOR => {
            let asn = if neg.four_octet_as {
                r.u32()?
            } else {
                u32::from(r.u16()?)
            };
            PathAttr::Aggregator(Aggregator {
                asn,
                addr: r.u32()?.into(),
            })
        }
        COMMUNITIES => {
            if r.remaining() == 0 || !r.remaining().is_multiple_of(4) {
                return r.fail();
            }
            let mut communities = Vec::with_capacity(r.remaining() / 4);
            while !r.is_empty() {
                communities.push(r.u32()?);
            }
            PathAttr::Communities(communities)
        }
        AS4_PATH => {
            // RFC 6793 §6: at least one AS number; confederation segments
            // are dropped.
            let value = r.rest();
            if value.len() < 6 {
                return Err(DecodeError::OptionalAttribute(raw));
            }
            let mut path = AsPath::decode(value, true, DecodeError::OptionalAttribute(raw))?;
            path.segments.retain(|s| !s.kind.is_confed());
            PathAttr::As4Path(path)
        }
        AS4_AGGREGATOR => PathAttr::As4Aggregator(Aggregator {
            asn: r.u32()?,
            addr: r.u32()?.into(),
        }),
        LARGE_COMMUNITIES => {
            if r.remaining() == 0 || !r.remaining().is_multiple_of(12) {
                return r.fail();
            }
            let mut communities = Vec::with_capacity(r.remaining() / 12);
            while !r.is_empty() {
                communities.push(LargeCommunity {
                    global_admin: r.u32()?,
                    local_data_1: r.u32()?,
                    local_data_2: r.u32()?,
                });
            }
            // RFC 8092 §3: redundant values MUST be removed. Sorting also
            // makes equal sets intern to one entry.
            communities.sort_unstable();
            communities.dedup();
            PathAttr::LargeCommunities(communities)
        }
        MP_REACH_NLRI => {
            let err = DecodeError::OptionalAttribute(raw);
            return Ok(match MpReach::decode(r.rest(), err.clone())? {
                Some(reach) => Decoded::MpReach(reach),
                None => Decoded::Ignored(err),
            });
        }
        MP_UNREACH_NLRI => {
            let err = DecodeError::OptionalAttribute(raw);
            return Ok(match MpUnreach::decode(r.rest(), err.clone())? {
                Some(unreach) => Decoded::MpUnreach(unreach),
                None => Decoded::Ignored(err),
            });
        }
        _ => unreachable!("expected_flags covers exactly the decoded type codes"),
    };
    r.finish()?;
    Ok(Decoded::Attr(attr))
}

/// Encodes `attrs` (sorted by type code) for one session; MP attributes and
/// type codes rejected by `keep` are skipped.
///
/// AS4_PATH / AS4_AGGREGATOR are never passed through (RFC 6793): towards a
/// 2-octet peer they are generated from AS_PATH / AGGREGATOR when those hold
/// non-mappable AS numbers (§4.2.2), between 4-octet speakers they must not
/// appear at all (§4.1).
pub(crate) fn encode_attr_list(
    neg: &Negotiated,
    attrs: &[PathAttr],
    keep: impl Fn(u8) -> bool,
    buf: &mut BytesMut,
) -> Result<(), EncodeError> {
    let non_mappable = |asn: u32| asn > u32::from(u16::MAX);
    let mut extra = Vec::new();
    if !neg.four_octet_as {
        for attr in attrs {
            match attr {
                PathAttr::AsPath(path)
                    if path
                        .segments
                        .iter()
                        .flat_map(|s| &s.asns)
                        .any(|&a| non_mappable(a)) =>
                {
                    let segments = path
                        .segments
                        .iter()
                        .filter(|s| !s.kind.is_confed())
                        .cloned()
                        .collect();
                    extra.push(PathAttr::As4Path(AsPath { segments }));
                }
                PathAttr::Aggregator(agg) if non_mappable(agg.asn) => {
                    extra.push(PathAttr::As4Aggregator(*agg));
                }
                _ => {}
            }
        }
    }
    // Generated attributes go into their place in type code order.
    let mut extra = extra.into_iter().peekable();
    for attr in attrs {
        let code = attr.type_code();
        if is_mp(code) || code == AS4_PATH || code == AS4_AGGREGATOR || !keep(code) {
            continue;
        }
        while let Some(generated) = extra.next_if(|e| e.type_code() < code) {
            generated.encode(neg, buf)?;
        }
        attr.encode(neg, buf)?;
    }
    for generated in extra {
        generated.encode(neg, buf)?;
    }
    Ok(())
}

/// Number of AS numbers in a path as counted for route selection
/// (RFC 4271 §9.1.2.2, RFC 5065): an AS_SET counts 1, confederation
/// segments 0.
pub fn path_len(path: &AsPath) -> usize {
    path.segments
        .iter()
        .map(|s| match s.kind {
            SegmentType::Sequence => s.asns.len(),
            SegmentType::Set => 1,
            SegmentType::ConfedSequence | SegmentType::ConfedSet => 0,
        })
        .sum()
}

/// RFC 6793 §4.2.3: combines AS4_PATH / AS4_AGGREGATOR received from a
/// 2-octet peer with AS_PATH / AGGREGATOR. The AS4 attributes are removed.
pub(crate) fn merge_as4(attrs: &mut Vec<PathAttr>) {
    let take = |attrs: &mut Vec<PathAttr>, code: u8| {
        let i = attrs.iter().position(|a| a.type_code() == code)?;
        Some(attrs.remove(i))
    };
    let mut as4_path = take(attrs, AS4_PATH);
    if let Some(PathAttr::As4Aggregator(as4_agg)) = take(attrs, AS4_AGGREGATOR)
        && let Some(PathAttr::Aggregator(agg)) = attrs
            .iter_mut()
            .find(|a| matches!(a, PathAttr::Aggregator(_)))
    {
        if agg.asn == u32::from(AS_TRANS) {
            *agg = as4_agg;
        } else {
            // The aggregator is a 2-octet speaker: AS_PATH is authoritative.
            as4_path = None;
        }
    }
    let Some(PathAttr::As4Path(as4)) = as4_path else {
        return;
    };
    let Some(PathAttr::AsPath(path)) = attrs.iter_mut().find(|a| matches!(a, PathAttr::AsPath(_)))
    else {
        return;
    };
    let (n, m) = (path_len(path), path_len(&as4));
    if n < m {
        return;
    }
    // Take as many leading AS numbers from AS_PATH as AS4_PATH lacks.
    let mut need = n - m;
    let mut merged = Vec::new();
    for segment in &path.segments {
        if need == 0 {
            break;
        }
        match segment.kind {
            SegmentType::Sequence => {
                let k = need.min(segment.asns.len());
                merged.push(AsSegment {
                    kind: SegmentType::Sequence,
                    asns: segment.asns[..k].to_vec(),
                });
                need -= k;
            }
            SegmentType::Set => {
                merged.push(segment.clone());
                need -= 1;
            }
            SegmentType::ConfedSequence | SegmentType::ConfedSet => merged.push(segment.clone()),
        }
    }
    // Join adjacent sequences, so equal paths compare (and intern) equal.
    for segment in as4.segments {
        match merged.last_mut() {
            Some(last)
                if last.kind == SegmentType::Sequence && segment.kind == SegmentType::Sequence =>
            {
                last.asns.extend(segment.asns);
            }
            _ => merged.push(segment),
        }
    }
    *path = AsPath { segments: merged };
}

/// Canonical encoding of an attribute set, used as interning key: 4-octet
/// AS numbers, the given order (keep it sorted), MP attributes skipped.
pub fn encode_path_attrs(attrs: &[PathAttr], buf: &mut BytesMut) -> Result<(), EncodeError> {
    encode_attr_list(&CANONICAL, attrs, |_| true, buf)
}

/// Inverse of [`encode_path_attrs`].
pub fn decode_path_attrs(bytes: Bytes) -> Result<Vec<PathAttr>, DecodeError> {
    let decoded = decode_attributes(bytes, &CANONICAL)?;
    match decoded.withdraw.into_iter().next() {
        Some((_, err)) => Err(err),
        None => Ok(decoded.attrs),
    }
}

/// Session parameters of the canonical encoding: 4-octet AS numbers, and
/// iBGP so that LOCAL_PREF is kept.
const CANONICAL: Negotiated = Negotiated {
    four_octet_as: true,
    extended_message: false,
    ibgp: true,
};

/// Next-hop length and address(es) as in MP_REACH_NLRI.
pub fn encode_next_hop(next_hop: &NextHop, buf: &mut BytesMut) {
    put_next_hop(buf, next_hop);
}
