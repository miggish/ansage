use bytes::{BufMut, Bytes, BytesMut};

use super::{
    Afi, DecodeError, EncodeError, Negotiated, Prefix4, Safi,
    attrs::{self, MpReach, MpUnreach, PathAttr, merge_as4 as attrs_merge_as4, type_code},
    header::patch_u16,
    reader::Reader,
};

/// UPDATE message (RFC 4271 §4.3, RFC 4760).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Update {
    /// Withdrawn IPv4 unicast routes.
    pub withdrawn: Vec<Prefix4>,
    /// Path attributes except MP_REACH_NLRI / MP_UNREACH_NLRI, sorted by
    /// type code. Decoding sorts them, so equal attribute sets compare equal
    /// whatever order the peer sent; the encoder relies on the order.
    pub attrs: Vec<PathAttr>,
    pub mp_reach: Option<MpReach>,
    pub mp_unreach: Option<MpUnreach>,
    /// Announced IPv4 unicast routes.
    pub nlri: Vec<Prefix4>,
    /// Set when decoding found an error that RFC 7606 handles with
    /// "treat-as-withdraw": every route in `nlri` and `mp_reach` must be
    /// treated as withdrawn. Holds the first such error. Not encoded.
    pub treat_as_withdraw: Option<DecodeError>,
    /// Attributes dropped while decoding (RFC 7606 "attribute discard").
    /// Not encoded.
    pub discarded: Vec<DecodeError>,
}

impl Update {
    /// End-of-RIB marker (RFC 4724 §2).
    pub fn end_of_rib(afi: Afi, safi: Safi) -> Self {
        if afi == Afi::IPV4 && safi == Safi::UNICAST {
            return Self::default();
        }
        Self {
            mp_unreach: Some(MpUnreach {
                afi,
                safi,
                withdrawn: Vec::new(),
            }),
            ..Self::default()
        }
    }

    /// The address family this UPDATE marks as complete, if it is an
    /// End-of-RIB.
    pub fn is_end_of_rib(&self) -> Option<(Afi, Safi)> {
        if !self.withdrawn.is_empty()
            || !self.nlri.is_empty()
            || !self.attrs.is_empty()
            || self.mp_reach.is_some()
        {
            return None;
        }
        match &self.mp_unreach {
            None => Some((Afi::IPV4, Safi::UNICAST)),
            Some(u) if u.withdrawn.is_empty() => Some((u.afi, u.safi)),
            Some(_) => None,
        }
    }

    pub fn attr(&self, code: u8) -> Option<&PathAttr> {
        self.attrs.iter().find(|a| a.type_code() == code)
    }

    pub(crate) fn decode(body: Bytes, neg: &Negotiated) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body, DecodeError::MalformedAttributeList);
        let withdrawn_len = usize::from(r.u16()?);
        let withdrawn = decode_prefixes(r.bytes(withdrawn_len)?)?;
        let attrs_len = usize::from(r.u16()?);
        let mut attrs = attrs::decode_attributes(r.bytes(attrs_len)?, neg)?;
        let nlri = decode_prefixes(r.rest())?;
        // Type codes are unique (duplicates were dropped), so unstable is fine.
        // Peers almost always send them sorted already.
        attrs.attrs.sort_unstable_by_key(PathAttr::type_code);

        // RFC 6793 §4.2.3: a 2-octet peer may add AS4_PATH / AS4_AGGREGATOR.
        if !neg.four_octet_as {
            attrs_merge_as4(&mut attrs.attrs);
        }

        // RFC 4760 §3: NEXT_HOP in an UPDATE without IPv4 NLRI is ignored,
        // including errors found in it.
        if nlri.is_empty() {
            attrs.attrs.retain(|a| a.type_code() != type_code::NEXT_HOP);
            attrs
                .withdraw
                .retain(|(code, _)| *code != Some(type_code::NEXT_HOP));
        }

        let mp_routes = attrs.mp_reach.as_ref().is_some_and(|m| !m.nlri.is_empty());
        let reachable = !nlri.is_empty() || mp_routes;
        // RFC 7606 §3(d): missing well-known attributes are treat-as-withdraw.
        if reachable {
            for code in [type_code::ORIGIN, type_code::AS_PATH] {
                if !attrs.has(code) {
                    let err = DecodeError::MissingWellKnownAttribute(code);
                    attrs.note_withdraw(Some(code), err);
                }
            }
        }
        // NEXT_HOP is only needed for routes outside MP_REACH_NLRI (RFC 4760
        // §3).
        if !nlri.is_empty() && !attrs.has(type_code::NEXT_HOP) {
            let err = DecodeError::MissingWellKnownAttribute(type_code::NEXT_HOP);
            attrs.note_withdraw(Some(type_code::NEXT_HOP), err);
        }
        let treat_as_withdraw = attrs.withdraw.into_iter().next().map(|(_, err)| err);
        // RFC 7606 §5.2: without reachable routes we cannot be sure the
        // message was parsed correctly, so treat-as-withdraw becomes a reset.
        if !reachable && let Some(err) = treat_as_withdraw {
            return Err(err);
        }

        Ok(Self {
            withdrawn,
            attrs: attrs.attrs,
            mp_reach: attrs.mp_reach,
            mp_unreach: attrs.mp_unreach,
            nlri,
            treat_as_withdraw,
            discarded: attrs.discarded,
        })
    }

    /// MP_REACH / MP_UNREACH go first (RFC 7606 §5.1), then `attrs` in order.
    /// `attrs` entries with code 14/15 are skipped.
    pub(crate) fn encode_body(
        &self,
        neg: &Negotiated,
        buf: &mut BytesMut,
    ) -> Result<(), EncodeError> {
        let pos = buf.len();
        buf.put_u16(0);
        for prefix in &self.withdrawn {
            prefix.encode(buf);
        }
        patch_u16(buf, pos, buf.len() - pos - 2);

        let pos = buf.len();
        buf.put_u16(0);
        if let Some(reach) = &self.mp_reach {
            reach.encode(buf)?;
        }
        if let Some(unreach) = &self.mp_unreach {
            unreach.encode(buf)?;
        }
        attrs::encode_attr_list(neg, &self.attrs, |_| true, buf)?;
        patch_u16(buf, pos, buf.len() - pos - 2);

        for prefix in &self.nlri {
            prefix.encode(buf);
        }
        Ok(())
    }
}

fn decode_prefixes(buf: Bytes) -> Result<Vec<Prefix4>, DecodeError> {
    let mut r = Reader::new(buf, DecodeError::InvalidNetworkField);
    let mut prefixes = Vec::new();
    while !r.is_empty() {
        prefixes.push(Prefix4::decode(&mut r)?);
    }
    Ok(prefixes)
}
