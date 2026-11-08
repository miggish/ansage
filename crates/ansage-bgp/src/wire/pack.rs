//! Size-based packing of outbound UPDATEs.
//!
//! Writes complete messages straight into the send buffer, as many prefixes
//! per message as `Negotiated::max_message_len` allows. Follows RFC 7606
//! §5.1: MP_REACH / MP_UNREACH is the first attribute, and each UPDATE
//! carries only one of withdrawn routes, NLRI, MP_REACH or MP_UNREACH.

use std::iter::Peekable;

use bytes::{BufMut, BytesMut};

use super::{
    Afi, EncodeError, MessageType, Negotiated, NextHop, PathAttr, Prefix, Safi,
    attrs::{attr_flags, encode_attr_list, put_next_hop, type_code},
    header::{self, patch_u16},
};

/// Appends UPDATEs announcing `prefixes` with `attrs`; returns the number of
/// messages. IPv6 prefixes go into MP_REACH_NLRI with `next_hop`, and NEXT_HOP
/// is left out of those. IPv4 prefixes go into the NLRI field when `attrs`
/// carries NEXT_HOP; without it, and with [`Negotiated::extended_next_hop`]
/// and an IPv6 `next_hop`, into MP_REACH_NLRI with that next hop (RFC 8950).
/// MP entries in `attrs` are ignored. On error `buf` is left as it was.
pub fn announce(
    buf: &mut BytesMut,
    neg: &Negotiated,
    attrs: &[PathAttr],
    next_hop: Option<&NextHop>,
    prefixes: &[Prefix],
) -> Result<usize, EncodeError> {
    let start = buf.len();
    let result = announce_inner(buf, neg, attrs, next_hop, prefixes);
    if result.is_err() {
        buf.truncate(start);
    }
    result
}

/// Appends UPDATEs withdrawing `prefixes`; returns the number of messages.
/// On error `buf` is left as it was.
pub fn withdraw(
    buf: &mut BytesMut,
    neg: &Negotiated,
    prefixes: &[Prefix],
) -> Result<usize, EncodeError> {
    let start = buf.len();
    let result = withdraw_inner(buf, neg, prefixes);
    if result.is_err() {
        buf.truncate(start);
    }
    result
}

fn announce_inner(
    buf: &mut BytesMut,
    neg: &Negotiated,
    attrs: &[PathAttr],
    next_hop: Option<&NextHop>,
    prefixes: &[Prefix],
) -> Result<usize, EncodeError> {
    let max = neg.max_message_len();
    let mut count = 0;

    let mut v4 = family(prefixes, Afi::IPV4);
    let classic_next_hop = attrs.iter().any(|a| matches!(a, PathAttr::NextHop(_)));
    if v4.peek().is_some() && classic_next_hop {
        let attr_bytes = encode_attrs(neg, attrs, |_| true)?;
        while v4.peek().is_some() {
            let start = header::begin(buf, MessageType::Update);
            buf.put_u16(0);
            buf.put_u16(u16::try_from(attr_bytes.len()).unwrap_or(u16::MAX));
            buf.put_slice(&attr_bytes);
            fill(buf, start, max, 0, &mut v4)?;
            header::finish(buf, start, max)?;
            count += 1;
        }
    } else if v4.peek().is_some() {
        // RFC 8950: an IPv6 next hop for IPv4 routes, only if agreed.
        let next_hop = next_hop
            .filter(|nh| neg.extended_next_hop && matches!(nh, NextHop::V6 { .. }))
            .ok_or(EncodeError::MissingNextHop)?;
        count += announce_mp(buf, neg, attrs, next_hop, Afi::IPV4, &mut v4)?;
    }

    let mut v6 = family(prefixes, Afi::IPV6);
    if v6.peek().is_some() {
        let next_hop = next_hop.ok_or(EncodeError::MissingNextHop)?;
        count += announce_mp(buf, neg, attrs, next_hop, Afi::IPV6, &mut v6)?;
    }
    Ok(count)
}

/// Announces `prefixes` of `afi` in MP_REACH_NLRI with `next_hop`; NEXT_HOP
/// is left out. Returns the number of messages.
fn announce_mp(
    buf: &mut BytesMut,
    neg: &Negotiated,
    attrs: &[PathAttr],
    next_hop: &NextHop,
    afi: Afi,
    prefixes: &mut Peekable<impl Iterator<Item = Prefix>>,
) -> Result<usize, EncodeError> {
    let max = neg.max_message_len();
    let attr_bytes = encode_attrs(neg, attrs, |code| code != type_code::NEXT_HOP)?;
    let mut count = 0;
    while prefixes.peek().is_some() {
        let start = header::begin(buf, MessageType::Update);
        buf.put_u16(0);
        let attrs_pos = buf.len();
        buf.put_u16(0);
        let mp = begin_mp(buf, type_code::MP_REACH_NLRI, afi);
        put_next_hop(buf, next_hop);
        buf.put_u8(0);
        // The other attributes follow MP_REACH, so keep room for them.
        fill(buf, start, max, attr_bytes.len(), prefixes)?;
        patch_u16(buf, mp + 2, buf.len() - mp - 4);
        buf.put_slice(&attr_bytes);
        patch_u16(buf, attrs_pos, buf.len() - attrs_pos - 2);
        header::finish(buf, start, max)?;
        count += 1;
    }
    Ok(count)
}

fn withdraw_inner(
    buf: &mut BytesMut,
    neg: &Negotiated,
    prefixes: &[Prefix],
) -> Result<usize, EncodeError> {
    let max = neg.max_message_len();
    let mut count = 0;

    let mut v4 = family(prefixes, Afi::IPV4);
    while v4.peek().is_some() {
        let start = header::begin(buf, MessageType::Update);
        let withdrawn_pos = buf.len();
        buf.put_u16(0);
        // Keep room for the (empty) attribute length field.
        fill(buf, start, max, 2, &mut v4)?;
        patch_u16(buf, withdrawn_pos, buf.len() - withdrawn_pos - 2);
        buf.put_u16(0);
        header::finish(buf, start, max)?;
        count += 1;
    }

    let mut v6 = family(prefixes, Afi::IPV6);
    while v6.peek().is_some() {
        let start = header::begin(buf, MessageType::Update);
        buf.put_u16(0);
        let attrs_pos = buf.len();
        buf.put_u16(0);
        let mp = begin_mp(buf, type_code::MP_UNREACH_NLRI, Afi::IPV6);
        fill(buf, start, max, 0, &mut v6)?;
        patch_u16(buf, mp + 2, buf.len() - mp - 4);
        patch_u16(buf, attrs_pos, buf.len() - attrs_pos - 2);
        header::finish(buf, start, max)?;
        count += 1;
    }
    Ok(count)
}

/// Encodes the attributes shared by every message of a batch, once.
fn encode_attrs(
    neg: &Negotiated,
    attrs: &[PathAttr],
    keep: impl Fn(u8) -> bool,
) -> Result<BytesMut, EncodeError> {
    let mut out = BytesMut::new();
    encode_attr_list(neg, attrs, keep, &mut out)?;
    Ok(out)
}

fn family(prefixes: &[Prefix], afi: Afi) -> Peekable<impl Iterator<Item = Prefix> + '_> {
    prefixes
        .iter()
        .copied()
        .filter(move |p| p.afi() == afi)
        .peekable()
}

/// Starts a unicast MP attribute for `afi` with a 2-octet length placeholder;
/// returns its start. Extended length is always used, which RFC 4271 allows
/// for any length, so the attribute can grow without moving bytes.
fn begin_mp(buf: &mut BytesMut, code: u8, afi: Afi) -> usize {
    let start = buf.len();
    buf.put_slice(&[
        attr_flags::OPTIONAL | attr_flags::EXTENDED_LENGTH,
        code,
        0,
        0,
    ]);
    buf.put_u16(afi.0);
    buf.put_u8(Safi::UNICAST.0);
    start
}

/// Appends prefixes while the message, plus `reserve` bytes still to come,
/// stays within `max`. Fails if not even one prefix fits.
fn fill(
    buf: &mut BytesMut,
    start: usize,
    max: usize,
    reserve: usize,
    prefixes: &mut Peekable<impl Iterator<Item = Prefix>>,
) -> Result<(), EncodeError> {
    let mut added = false;
    while let Some(prefix) = prefixes.peek() {
        let len = buf.len() - start + reserve + prefix.encoded_len();
        if len > max {
            if !added {
                return Err(EncodeError::MessageTooLong { len, max });
            }
            break;
        }
        prefix.encode(buf);
        prefixes.next();
        added = true;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::wire::{
        AsPath, MAX_MESSAGE_LEN, Message, Origin, Prefix4, Prefix6, Update, split_message,
    };

    const NEG: Negotiated = Negotiated {
        four_octet_as: true,
        extended_message: false,
        ibgp: false,
        extended_next_hop: false,
    };

    fn attrs() -> Vec<PathAttr> {
        vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([64500])),
            PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
        ]
    }

    fn v6_next_hop() -> NextHop {
        NextHop::V6 {
            global: "2001:db8::1".parse().unwrap(),
            link_local: None,
        }
    }

    fn v4s(n: u32) -> Vec<Prefix> {
        (0..n)
            .map(|i| Prefix::V4(Prefix4::new(Ipv4Addr::from(0x0a00_0000 + (i << 8)), 24).unwrap()))
            .collect()
    }

    fn v6s(n: u32) -> Vec<Prefix> {
        (0..n)
            .map(|i| {
                let addr = Ipv6Addr::from((0x2001_0db8u128 << 96) + (u128::from(i) << 80));
                Prefix::V6(Prefix6::new(addr, 48).unwrap())
            })
            .collect()
    }

    /// Splits `buf` into decoded UPDATEs, checking each message's size.
    fn decode_all(mut buf: BytesMut, neg: &Negotiated) -> Vec<(usize, Update)> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            let len = usize::from(u16::from_be_bytes([buf[16], buf[17]]));
            assert!(len <= neg.max_message_len());
            let (kind, body) = split_message(&mut buf, neg.max_message_len())
                .unwrap()
                .unwrap();
            let Message::Update(update) = Message::decode(kind, body, neg).unwrap() else {
                panic!("not an UPDATE");
            };
            assert_eq!(
                (&update.treat_as_withdraw, update.discarded.len()),
                (&None, 0)
            );
            out.push((len, update));
        }
        out
    }

    fn announced(updates: &[(usize, Update)]) -> Vec<Prefix> {
        updates
            .iter()
            .flat_map(|(_, u)| {
                u.nlri
                    .iter()
                    .map(|p| Prefix::V4(*p))
                    .chain(u.mp_reach.iter().flat_map(|m| m.nlri.iter().copied()))
            })
            .collect()
    }

    #[test]
    fn small_batch_is_one_message_per_family() {
        let prefixes: Vec<Prefix> = v4s(3).into_iter().chain(v6s(2)).collect();
        let mut buf = BytesMut::new();
        let n = announce(&mut buf, &NEG, &attrs(), Some(&v6_next_hop()), &prefixes).unwrap();
        assert_eq!(n, 2);
        let updates = decode_all(buf, &NEG);
        assert_eq!(announced(&updates), prefixes);
        assert_eq!(updates[0].1.attrs, attrs());
        // IPv6: no NEXT_HOP attribute, next hop lives in MP_REACH.
        let v6 = &updates[1].1;
        assert!(v6.attr(type_code::NEXT_HOP).is_none());
        assert_eq!(v6.mp_reach.as_ref().unwrap().next_hop, v6_next_hop());
    }

    #[test]
    fn mp_reach_is_the_first_attribute() {
        let mut buf = BytesMut::new();
        announce(&mut buf, &NEG, &attrs(), Some(&v6_next_hop()), &v6s(1)).unwrap();
        // Header 19 + withdrawn length 2 + attribute length 2.
        assert_eq!(&buf[23..25], &[0x90, type_code::MP_REACH_NLRI]);
    }

    #[test]
    fn large_batches_fill_messages() {
        let prefixes: Vec<Prefix> = v4s(3000).into_iter().chain(v6s(1000)).collect();
        let mut buf = BytesMut::new();
        announce(&mut buf, &NEG, &attrs(), Some(&v6_next_hop()), &prefixes).unwrap();
        let updates = decode_all(buf, &NEG);
        assert_eq!(announced(&updates), prefixes, "all prefixes, in order");
        // Every message but the last of each family is (nearly) full: the
        // next prefix (4 bytes for a /24, 7 for a /48) did not fit.
        let v4_messages = updates.iter().filter(|(_, u)| !u.nlri.is_empty()).count();
        for (len, update) in &updates[..v4_messages - 1] {
            assert!(MAX_MESSAGE_LEN - len < 4, "{len} {}", update.nlri.len());
        }
        for (len, _) in &updates[v4_messages..updates.len() - 1] {
            assert!(MAX_MESSAGE_LEN - len < 7, "{len}");
        }

        // With extended messages everything fits into one message per family.
        let extended = Negotiated {
            extended_message: true,
            ..NEG
        };
        let mut buf = BytesMut::new();
        let n = announce(
            &mut buf,
            &extended,
            &attrs(),
            Some(&v6_next_hop()),
            &prefixes,
        )
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(announced(&decode_all(buf, &extended)), prefixes);
    }

    #[test]
    fn withdrawals() {
        let prefixes: Vec<Prefix> = v4s(2000).into_iter().chain(v6s(1000)).collect();
        let mut buf = BytesMut::new();
        withdraw(&mut buf, &NEG, &prefixes).unwrap();
        let updates = decode_all(buf, &NEG);
        let withdrawn: Vec<Prefix> = updates
            .iter()
            .flat_map(|(_, u)| {
                u.withdrawn.iter().map(|p| Prefix::V4(*p)).chain(
                    u.mp_unreach
                        .iter()
                        .flat_map(|m| m.withdrawn.iter().copied()),
                )
            })
            .collect();
        assert_eq!(withdrawn, prefixes);
        assert!(
            updates
                .iter()
                .all(|(_, u)| u.attrs.is_empty() && u.nlri.is_empty())
        );
    }

    #[test]
    fn ipv6_without_next_hop_fails_cleanly() {
        let mut buf = BytesMut::from(&b"keep"[..]);
        let err = announce(&mut buf, &NEG, &attrs(), None, &v6s(1)).unwrap_err();
        assert_eq!(err, EncodeError::MissingNextHop);
        assert_eq!(&buf[..], b"keep");
    }

    const EXTENDED_NEXT_HOP: Negotiated = Negotiated {
        extended_next_hop: true,
        ..NEG
    };

    fn attrs_without_next_hop() -> Vec<PathAttr> {
        let mut attrs = attrs();
        attrs.retain(|a| a.type_code() != type_code::NEXT_HOP);
        attrs
    }

    #[test]
    fn ipv4_with_ipv6_next_hop_goes_into_mp_reach() {
        let prefixes: Vec<Prefix> = v4s(3000).into_iter().chain(v6s(2)).collect();
        let mut buf = BytesMut::new();
        let attrs = attrs_without_next_hop();
        let neg = &EXTENDED_NEXT_HOP;
        announce(&mut buf, neg, &attrs, Some(&v6_next_hop()), &prefixes).unwrap();
        let updates = decode_all(buf, neg);
        assert_eq!(announced(&updates), prefixes, "all prefixes, in order");
        assert!(updates.len() > 2, "IPv4 prefixes fill several messages");
        for (_, update) in &updates {
            let mp = update.mp_reach.as_ref().unwrap();
            assert!(update.nlri.is_empty());
            assert_eq!(mp.next_hop, v6_next_hop());
            assert!(mp.nlri.iter().all(|p| p.afi() == mp.afi));
            assert_eq!(update.attrs, attrs);
        }
        let afis: Vec<Afi> = updates
            .iter()
            .map(|(_, u)| u.mp_reach.as_ref().unwrap().afi)
            .collect();
        assert_eq!(afis.last(), Some(&Afi::IPV6));
        assert_eq!(afis.iter().filter(|a| **a == Afi::IPV6).count(), 1);
    }

    #[test]
    fn ipv4_next_hop_attribute_wins_over_extended_next_hop() {
        let mut buf = BytesMut::new();
        let neg = &EXTENDED_NEXT_HOP;
        announce(&mut buf, neg, &attrs(), Some(&v6_next_hop()), &v4s(2)).unwrap();
        let updates = decode_all(buf, neg);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].1.nlri.len(), 2);
        assert_eq!(updates[0].1.mp_reach, None);
    }

    #[test]
    fn ipv4_without_any_next_hop_fails_cleanly() {
        let v4_next_hop = NextHop::V4(Ipv4Addr::new(192, 0, 2, 1));
        for (neg, next_hop) in [
            // Not agreed with the peer.
            (&NEG, Some(v6_next_hop())),
            // Agreed, but no IPv6 next hop to send.
            (&EXTENDED_NEXT_HOP, None),
            (&EXTENDED_NEXT_HOP, Some(v4_next_hop)),
        ] {
            let mut buf = BytesMut::from(&b"keep"[..]);
            let prefixes: Vec<Prefix> = v6s(1).into_iter().chain(v4s(1)).collect();
            let err = announce(
                &mut buf,
                neg,
                &attrs_without_next_hop(),
                next_hop.as_ref(),
                &prefixes,
            )
            .unwrap_err();
            assert_eq!(err, EncodeError::MissingNextHop);
            assert_eq!(&buf[..], b"keep");
        }
    }
}
