//! Test vectors are written out by hand from the RFC layouts, not produced
//! by the encoder, so encoder and decoder are checked against the spec.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Bytes, BytesMut};

use super::*;

const NEG4: Negotiated = Negotiated {
    four_octet_as: true,
    extended_message: false,
    ibgp: false,
};
const NEG2: Negotiated = Negotiated {
    four_octet_as: false,
    extended_message: false,
    ibgp: false,
};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A message: marker, then `rest` (length, type, body) in hex.
fn msg(rest: &str) -> Vec<u8> {
    hex(&format!("ffffffffffffffffffffffffffffffff {rest}"))
}

fn decode(bytes: &[u8], neg: &Negotiated) -> Result<Message, DecodeError> {
    let mut buf = BytesMut::from(bytes);
    let (kind, body) = split_message(&mut buf, neg.max_message_len())?.expect("complete message");
    assert!(buf.is_empty(), "trailing bytes after message");
    Message::decode(kind, body, neg)
}

fn encode(message: &Message, neg: &Negotiated) -> Vec<u8> {
    let mut buf = BytesMut::new();
    message.encode(neg, &mut buf).unwrap();
    buf.to_vec()
}

/// Decodes `bytes`, compares with `expected`, and checks that encoding
/// `expected` gives back exactly `bytes`.
fn roundtrip(bytes: &[u8], neg: &Negotiated, expected: Message) {
    assert_eq!(decode(bytes, neg).unwrap(), expected);
    assert_eq!(encode(&expected, neg), bytes);
}

fn p4(s: &str) -> Prefix4 {
    s.parse().unwrap()
}

fn update_err(rest: &str) -> DecodeError {
    decode(&msg(rest), &NEG4).unwrap_err()
}

#[test]
fn keepalive() {
    roundtrip(&msg("0013 04"), &NEG4, Message::Keepalive);
}

#[test]
fn open_with_capabilities() {
    // AS 64501, hold 90, id 192.0.2.2; capabilities: MP IPv4/IPv6 unicast,
    // route refresh, 4-octet AS 64501, extended message.
    let bytes = msg("0035 01 04 fbf5 005a c0000202 18 02 16
                     0104 0001 00 01  0104 0002 00 01  0200  4104 0000fbf5  0600");
    let open = Open {
        my_as: 64501,
        hold_time: 90,
        bgp_id: Ipv4Addr::new(192, 0, 2, 2),
        capabilities: vec![
            Capability::Multiprotocol {
                afi: Afi::IPV4,
                safi: Safi::UNICAST,
            },
            Capability::Multiprotocol {
                afi: Afi::IPV6,
                safi: Safi::UNICAST,
            },
            Capability::RouteRefresh,
            Capability::FourOctetAs(64501),
            Capability::ExtendedMessage,
        ],
    };
    assert_eq!(open.asn(), 64501);
    roundtrip(&bytes, &NEG2, Message::Open(open));
}

#[test]
fn open_four_octet_asn() {
    let open = Open::new(4_200_000_000, 90, Ipv4Addr::new(192, 0, 2, 1), vec![]);
    assert_eq!(open.my_as, AS_TRANS);
    assert_eq!(open.asn(), 4_200_000_000);
    assert_eq!(
        open.capabilities,
        vec![Capability::FourOctetAs(4_200_000_000)]
    );
}

#[test]
fn open_extended_parameters() {
    // RFC 9072: 255, 255, 2-octet length, parameters with 2-octet lengths.
    let bytes = msg("0025 01 04 fbf5 005a c0000202 ff ff 0005 02 0002 0200");
    let Message::Open(open) = decode(&bytes, &NEG2).unwrap() else {
        panic!("not an OPEN");
    };
    assert_eq!(open.capabilities, vec![Capability::RouteRefresh]);
}

#[test]
fn open_errors() {
    let err = decode(&msg("001d 01 03 fbf5 005a c0000202 00"), &NEG2).unwrap_err();
    assert_eq!(err, DecodeError::UnsupportedVersion(3));
    let n = err.notification();
    assert_eq!((n.code, n.subcode, &n.data[..]), (2, 1, &[0, 4][..]));

    let err = decode(&msg("001d 01 04 fbf5 0002 c0000202 00"), &NEG2).unwrap_err();
    assert_eq!(err, DecodeError::UnacceptableHoldTime(2));

    let err = decode(&msg("001d 01 04 fbf5 005a 00000000 00"), &NEG2).unwrap_err();
    assert_eq!(err, DecodeError::BadBgpIdentifier);

    // Optional parameter length points past the end.
    let err = decode(&msg("001d 01 04 fbf5 005a c0000202 05"), &NEG2).unwrap_err();
    assert_eq!(err, DecodeError::MalformedOpen);

    // Parameter type 1 (authentication, deprecated).
    let err = decode(&msg("001f 01 04 fbf5 005a c0000202 02 01 00"), &NEG2).unwrap_err();
    assert_eq!(err, DecodeError::UnsupportedOptionalParameter(1));
}

#[test]
fn update_ipv4() {
    // ORIGIN IGP, AS_PATH [64500], NEXT_HOP 192.0.2.1, NLRI 198.51.100.0/24.
    let bytes = msg("002f 02 0000 0014
                     40 01 01 00
                     40 02 06 02 01 0000fbf4
                     40 03 04 c0000201
                     18 c63364");
    let update = Update {
        attrs: vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([64500])),
            PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
        ],
        nlri: vec![p4("198.51.100.0/24")],
        ..Update::default()
    };
    roundtrip(&bytes, &NEG4, Message::Update(update));
}

#[test]
fn update_two_octet_as_path() {
    let bytes = msg("002d 02 0000 0012
                     40 01 01 00
                     40 02 04 02 01 fbf4
                     40 03 04 c0000201
                     18 c63364");
    let Message::Update(update) = decode(&bytes, &NEG2).unwrap() else {
        panic!("not an UPDATE");
    };
    assert_eq!(
        update.attr(type_code::AS_PATH),
        Some(&PathAttr::AsPath(AsPath::sequence([64500])))
    );

    // The 4-octet encoding is a malformed AS_PATH when read as 2-octet:
    // RFC 7606 treat-as-withdraw, the session stays up.
    let four = msg("002f 02 0000 0014 40010100 400206020100 00fbf4 400304c0000201 18c63364");
    assert_eq!(
        decoded_update(&four, &NEG2).treat_as_withdraw,
        Some(DecodeError::MalformedAsPath)
    );
}

#[test]
fn four_octet_asn_over_a_two_octet_session() {
    let update = Update {
        attrs: vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([4_200_000_000])),
            PathAttr::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
        ],
        nlri: vec![p4("198.51.100.0/24")],
        ..Update::default()
    };
    let bytes = encode(&Message::Update(update.clone()), &NEG2);
    // RFC 6793 §4.2.2: AS_PATH [AS_TRANS] plus AS4_PATH [4200000000].
    let attrs = &bytes[23..];
    let as_path = hex("40 02 04 02 01 5ba0");
    let as4_path = hex("c0 11 06 02 01 fa56ea00");
    assert!(attrs.windows(as_path.len()).any(|w| w == as_path));
    assert!(attrs.windows(as4_path.len()).any(|w| w == as4_path));

    // RFC 6793 §4.2.3: the receiver merges them back.
    assert_eq!(decoded_update(&bytes, &NEG2).attrs, update.attrs);
    // Between 4-octet speakers no AS4_PATH is sent.
    let four = encode(&Message::Update(update), &NEG4);
    assert!(!four[23..].windows(2).any(|w| w == [0xc0, 0x11]));
}

#[test]
fn as4_path_merge_keeps_trailing_two_octet_hops() {
    // A 2-octet peer prepended its AS (64999) and an OLD hop (65001) to a
    // route from AS 4200000000: AS_PATH [64999 65001 23456], AS4_PATH
    // [65001 4200000000] -> [64999 65001 4200000000].
    let bytes = msg(&format!(
        "003e 02 0000 0023 40010100 40020802 03fde7 fde9 5ba0 {NEXT_HOP} c0110a 0202 0000fde9 fa56ea00 {NLRI}"
    ));
    let update = decoded_update(&bytes, &NEG2);
    assert_eq!(
        update.attr(type_code::AS_PATH),
        Some(&PathAttr::AsPath(AsPath::sequence([
            64999,
            65001,
            4_200_000_000
        ])))
    );
    assert!(update.attr(type_code::AS4_PATH).is_none());

    // From a 4-octet peer, AS4_PATH is discarded (RFC 6793 §4.1).
    let bytes = msg(&format!(
        "003c 02 0000 0021 40010100 {AS_PATH} {NEXT_HOP} c0110a 0202 0000fde9 fa56ea00 {NLRI}"
    ));
    let update = decoded_update(&bytes, &NEG4);
    assert!(update.attr(type_code::AS4_PATH).is_none());
    assert_eq!(update.discarded.len(), 1);
}

#[test]
fn update_ipv6_mp_reach() {
    // MP_REACH IPv6 unicast (first, RFC 7606 §5.1), next hop 2001:db8::1,
    // NLRI 2001:db8:1::/48; ORIGIN IGP, AS_PATH [64500].
    let bytes = msg("0043 02 0000 002c
                     80 0e 1c 0002 01 10 20010db8000000000000000000000001 00 30 20010db80001
                     40 01 01 00
                     40 02 06 02 01 0000fbf4");
    let update = Update {
        attrs: vec![
            PathAttr::Origin(Origin::Igp),
            PathAttr::AsPath(AsPath::sequence([64500])),
        ],
        mp_reach: Some(MpReach {
            afi: Afi::IPV6,
            safi: Safi::UNICAST,
            next_hop: NextHop::V6 {
                global: "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
                link_local: None,
            },
            nlri: vec!["2001:db8:1::/48".parse().unwrap()],
        }),
        ..Update::default()
    };
    roundtrip(&bytes, &NEG4, Message::Update(update));
}

#[test]
fn end_of_rib() {
    let v4 = msg("0017 02 0000 0000");
    roundtrip(
        &v4,
        &NEG4,
        Message::Update(Update::end_of_rib(Afi::IPV4, Safi::UNICAST)),
    );

    let v6 = msg("001d 02 0000 0006 80 0f 03 0002 01");
    let update = Update::end_of_rib(Afi::IPV6, Safi::UNICAST);
    assert_eq!(update.is_end_of_rib(), Some((Afi::IPV6, Safi::UNICAST)));
    roundtrip(&v6, &NEG4, Message::Update(update));
}

#[test]
fn unknown_optional_attribute_is_kept() {
    let bytes = msg("001c 02 0000 0005 c0 63 02 abcd");
    let update = Update {
        attrs: vec![PathAttr::Unknown {
            flags: attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            code: 99,
            value: Bytes::from_static(&[0xab, 0xcd]),
        }],
        ..Update::default()
    };
    roundtrip(&bytes, &NEG4, Message::Update(update));
}

fn decoded_update(bytes: &[u8], neg: &Negotiated) -> Update {
    match decode(bytes, neg) {
        Ok(Message::Update(update)) => update,
        other => panic!("expected an UPDATE, got {other:?}"),
    }
}

const NLRI: &str = "18 c63364";
const AS_PATH: &str = "400206020100 00fbf4";
const NEXT_HOP: &str = "400304c0000201";

#[test]
fn rfc7606_treat_as_withdraw() {
    let cases = [
        // Missing ORIGIN.
        (
            format!("002b 02 0000 0010 {AS_PATH} {NEXT_HOP} {NLRI}"),
            DecodeError::MissingWellKnownAttribute(1),
        ),
        // ORIGIN with length 2.
        (
            format!("0030 02 0000 0015 4001020000 {AS_PATH} {NEXT_HOP} {NLRI}"),
            DecodeError::AttributeLength(Bytes::from(hex("4001020000"))),
        ),
        // ORIGIN flagged optional.
        (
            format!("002f 02 0000 0014 80010100 {AS_PATH} {NEXT_HOP} {NLRI}"),
            DecodeError::AttributeFlags(Bytes::from(hex("80010100"))),
        ),
        // ORIGIN value 3.
        (
            format!("002f 02 0000 0014 40010103 {AS_PATH} {NEXT_HOP} {NLRI}"),
            DecodeError::InvalidOrigin(Bytes::from(hex("40010103"))),
        ),
        // NEXT_HOP 0.0.0.0.
        (
            format!("002f 02 0000 0014 40010100 {AS_PATH} 40030400000000 {NLRI}"),
            DecodeError::InvalidNextHop(Bytes::from(hex("40030400000000"))),
        ),
        // NEXT_HOP length runs past the attribute section (§4).
        (
            format!("002f 02 0000 0014 40010100 {AS_PATH} 400305c0000201 {NLRI}"),
            DecodeError::MalformedAttributeList,
        ),
    ];
    for (bytes, expected) in cases {
        let update = decoded_update(&msg(&bytes), &NEG4);
        assert_eq!(update.treat_as_withdraw, Some(expected), "{bytes}");
        // The routes are still known, so they can be withdrawn.
        assert_eq!(update.nlri, [p4("198.51.100.0/24")], "{bytes}");
    }
}

#[test]
fn rfc7606_attribute_discard() {
    // Second ORIGIN is dropped, the first one kept.
    let update = decoded_update(
        &msg(&format!(
            "0033 02 0000 0018 40010100 40010101 {AS_PATH} {NEXT_HOP} {NLRI}"
        )),
        &NEG4,
    );
    assert_eq!(update.treat_as_withdraw, None);
    assert_eq!(update.attrs[0], PathAttr::Origin(Origin::Igp));
    assert_eq!(update.discarded, [DecodeError::MalformedAttributeList]);

    // AGGREGATOR with length 5.
    let update = decoded_update(
        &msg(&format!(
            "0037 02 0000 001c 40010100 {AS_PATH} {NEXT_HOP} c00705 0000fbf401 {NLRI}"
        )),
        &NEG4,
    );
    assert_eq!(update.treat_as_withdraw, None);
    assert!(update.attr(type_code::AGGREGATOR).is_none());
    assert_eq!(update.discarded.len(), 1);

    // MP_REACH for IPv4 multicast, which we never negotiate.
    let update = decoded_update(
        &msg(&format!(
            "0035 02 0000 001a 800e03 000102 40010100 {AS_PATH} {NEXT_HOP} {NLRI}"
        )),
        &NEG4,
    );
    assert_eq!((update.treat_as_withdraw, update.mp_reach), (None, None));
    assert_eq!(update.discarded.len(), 1);
}

#[test]
fn rfc7606_local_pref_depends_on_session_type() {
    // LOCAL_PREF with length 2.
    let bytes = msg(&format!(
        "0034 02 0000 0019 40010100 {AS_PATH} {NEXT_HOP} 40050200 64 {NLRI}"
    ));
    // RFC 7606 §7.5: from eBGP it is always discarded, malformed or not.
    let ebgp = decoded_update(&bytes, &NEG4);
    assert_eq!(ebgp.treat_as_withdraw, None);
    assert!(ebgp.attr(type_code::LOCAL_PREF).is_none());

    let ibgp = Negotiated { ibgp: true, ..NEG4 };
    assert!(decoded_update(&bytes, &ibgp).treat_as_withdraw.is_some());
}

#[test]
fn rfc7606_session_reset() {
    // Unknown attribute flagged well-known (RFC 4271; RFC 7606 is silent).
    let err = update_err("001a 02 0000 0003 406300");
    assert_eq!(
        err,
        DecodeError::UnrecognizedWellKnownAttribute(Bytes::from(hex("406300")))
    );

    // Withdrawn /33: the withdrawn routes field cannot be parsed.
    assert_eq!(
        update_err("001c 02 0005 21c0000200 0000"),
        DecodeError::InvalidNetworkField
    );

    // MP_UNREACH twice.
    assert_eq!(
        update_err("0023 02 0000 000c 800f03000201 800f03000201"),
        DecodeError::MalformedAttributeList
    );

    // IPv6 MP_REACH with a 4-byte next hop (§7.11).
    let err = update_err(&format!(
        "0030 02 0000 0019 800e09 0002 01 04 c0000201 00 40010100 {AS_PATH}"
    ));
    assert_eq!(
        err,
        DecodeError::OptionalAttribute(Bytes::from(hex("800e09000201 04c0000201 00")))
    );

    // §5.2: no reachable routes, so treat-as-withdraw errors become resets.
    let err = update_err("001c 02 0000 0005 4001020000");
    assert_eq!(
        err,
        DecodeError::AttributeLength(Bytes::from(hex("4001020000")))
    );
    let n = err.notification();
    assert_eq!((n.code, n.subcode), (3, 5));
    assert_eq!(n.data, Bytes::from(hex("4001020000")));
    assert_eq!(
        update_err("001b 02 0000 0004 40010500"),
        DecodeError::MalformedAttributeList
    );
}

#[test]
fn header_errors() {
    let mut bad_marker = msg("0013 04");
    bad_marker[0] = 0;
    let err = decode(&bad_marker, &NEG4).unwrap_err();
    assert_eq!(err, DecodeError::ConnectionNotSynchronized);
    assert_eq!(err.notification().code, error_code::MESSAGE_HEADER);

    let err = decode(&msg("0012 04"), &NEG4).unwrap_err();
    assert_eq!(err, DecodeError::BadMessageLength(18));
    assert_eq!(err.notification().data, Bytes::from_static(&[0x00, 0x12]));

    // KEEPALIVE must be exactly 19 bytes.
    assert_eq!(
        decode(&msg("0014 04 00"), &NEG4).unwrap_err(),
        DecodeError::BadMessageLength(20)
    );

    assert_eq!(
        decode(&msg("0013 09"), &NEG4).unwrap_err(),
        DecodeError::BadMessageType(9)
    );

    // Length above 4096 without extended messages, rejected before the body
    // arrives.
    let mut buf = BytesMut::from(&msg("1001 02")[..]);
    assert_eq!(
        split_message(&mut buf, MAX_MESSAGE_LEN).unwrap_err(),
        DecodeError::BadMessageLength(4097)
    );
}

#[test]
fn split_partial_and_back_to_back() {
    let keepalive = msg("0013 04");
    let notification = msg("0015 03 0602");

    let mut buf = BytesMut::from(&keepalive[..10]);
    assert_eq!(split_message(&mut buf, MAX_MESSAGE_LEN).unwrap(), None);
    buf.extend_from_slice(&keepalive[10..]);
    buf.extend_from_slice(&notification);

    let (kind, body) = split_message(&mut buf, MAX_MESSAGE_LEN).unwrap().unwrap();
    assert_eq!((kind, body.len()), (MessageType::Keepalive, 0));
    let (kind, body) = split_message(&mut buf, MAX_MESSAGE_LEN).unwrap().unwrap();
    assert_eq!(kind, MessageType::Notification);
    assert_eq!(&body[..], &[6, 2]);
    assert_eq!(split_message(&mut buf, MAX_MESSAGE_LEN).unwrap(), None);
    assert!(buf.is_empty());
}

#[test]
fn extended_length_attribute() {
    let update = Update {
        attrs: vec![PathAttr::Communities((0..100).collect())],
        ..Update::default()
    };
    let bytes = encode(&Message::Update(update.clone()), &NEG4);
    // Header 19, withdrawn length 2, attribute length 2, then the attribute.
    assert_eq!(
        bytes[23],
        attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::EXTENDED_LENGTH
    );
    assert_eq!(&bytes[25..27], &400u16.to_be_bytes());
    assert_eq!(decode(&bytes, &NEG4).unwrap(), Message::Update(update));
}

#[test]
fn message_too_long() {
    let update = Update {
        withdrawn: (0..2000u32)
            .map(|i| Prefix4::new(Ipv4Addr::from(0x0a00_0000 + i), 32).unwrap())
            .collect(),
        ..Update::default()
    };
    let message = Message::Update(update);

    let mut buf = BytesMut::from(&b"keep"[..]);
    let err = message.encode(&NEG4, &mut buf).unwrap_err();
    assert_eq!(
        err,
        EncodeError::MessageTooLong {
            len: 10023,
            max: 4096
        }
    );
    assert_eq!(&buf[..], b"keep", "buffer restored after failed encode");

    let extended = Negotiated {
        four_octet_as: true,
        extended_message: true,
        ibgp: false,
    };
    assert_eq!(
        decode(&encode(&message, &extended), &extended).unwrap(),
        message
    );
}

#[test]
fn notification_admin_shutdown() {
    let notification = Notification::admin_shutdown("maintenance");
    let bytes = msg("0021 03 06 02 0b 6d61696e74656e616e6365");
    roundtrip(&bytes, &NEG4, Message::Notification(notification));
}

#[test]
fn route_refresh() {
    let refresh = RouteRefresh {
        afi: Afi::IPV6,
        subtype: 0,
        safi: Safi::UNICAST,
    };
    roundtrip(
        &msg("0017 05 0002 00 01"),
        &NEG4,
        Message::RouteRefresh(refresh),
    );
}

#[test]
fn prefix_parsing() {
    assert_eq!(p4("192.0.2.0/24").to_string(), "192.0.2.0/24");
    assert_eq!(
        "2001:db8:1::/48".parse::<Prefix>().unwrap().to_string(),
        "2001:db8:1::/48"
    );
    assert_eq!(
        "192.0.2.1/24".parse::<Prefix4>(),
        Err(PrefixError::HostBitsSet("192.0.2.0/24".into()))
    );
    assert_eq!(
        "192.0.2.0/33".parse::<Prefix4>(),
        Err(PrefixError::Length(33))
    );
    assert_eq!(
        "192.0.2.0".parse::<Prefix4>(),
        Err(PrefixError::MissingSlash)
    );
    assert_eq!(p4("0.0.0.0/0").prefix_len(), 0);

    // new() clears host bits instead of failing.
    let masked = Prefix4::new(Ipv4Addr::new(192, 0, 2, 255), 24).unwrap();
    assert_eq!(masked, p4("192.0.2.0/24"));
}

#[test]
fn attributes_are_sorted_on_decode() {
    // Unknown attribute 73 sent before AS_PATH and NEXT_HOP (found by mutation
    // fuzzing). With an NLRI, so NEXT_HOP counts (RFC 4760 §3).
    let bytes =
        msg("002f 02 0000 0014 c8 49 01 00  40 02 06 02 01 0000fbf4  40 03 04 c0000201  18 c63364");
    let Message::Update(update) = decode(&bytes, &NEG4).unwrap() else {
        panic!("not an UPDATE");
    };
    let codes: Vec<u8> = update.attrs.iter().map(PathAttr::type_code).collect();
    assert_eq!(codes, [2, 3, 73]);
}

// Regressions from the RFC review.

/// A message of `kind` with `body` (hex), header length computed.
fn with_header(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xff; 16];
    out.extend(u16::try_from(body.len() + 19).unwrap().to_be_bytes());
    out.push(kind);
    out.extend(body);
    out
}

/// An UPDATE without withdrawn routes; both length fields computed.
fn update_bytes(attrs: &str, nlri: &str) -> Vec<u8> {
    let attrs = hex(attrs);
    let mut body = vec![0, 0];
    body.extend(u16::try_from(attrs.len()).unwrap().to_be_bytes());
    body.extend(attrs);
    body.extend(hex(nlri));
    with_header(2, &body)
}

#[test]
fn rfc9072_detected_by_type_255_whatever_the_length_says() {
    // Non-extended length 0x0c instead of 255, first type 255 (RFC 9072 §3).
    let bytes = with_header(
        1,
        &hex("04 fbf5 00b4 c0000202 0c ff 0009 02 0006 4104 0000fbf5"),
    );
    let Message::Open(open) = decode(&bytes, &NEG2).unwrap() else {
        panic!("not an OPEN");
    };
    assert_eq!(open.capabilities, [Capability::FourOctetAs(64501)]);
}

#[test]
fn rfc7606_unlocatable_mp_routes_reset() {
    // MP_UNREACH claims 64 bytes, 6 present (§3(j)).
    let bytes = update_bytes(&format!("40010100 {AS_PATH} 900f0040 000201 302001"), "");
    assert_eq!(
        decode(&bytes, &NEG4).unwrap_err(),
        DecodeError::MalformedAttributeList
    );

    // Empty MP_REACH is no reachable route: an invalid ORIGIN resets (§5.2).
    let bytes = update_bytes(
        &format!("800e15 0002 01 10 20010db8000000000000000000000001 00 40010107 {AS_PATH}"),
        "",
    );
    assert_eq!(
        decode(&bytes, &NEG4).unwrap_err(),
        DecodeError::InvalidOrigin(Bytes::from(hex("40010107")))
    );
}

#[test]
fn rfc7606_discard_cases() {
    // LOCAL_PREF with wrong flags from eBGP: discarded, routes kept (§7.5).
    let bytes = update_bytes(
        &format!("40010100 {AS_PATH} {NEXT_HOP} c00504000000c8"),
        NLRI,
    );
    let update = decoded_update(&bytes, &NEG4);
    assert_eq!(update.treat_as_withdraw, None);
    assert!(update.attr(type_code::LOCAL_PREF).is_none());

    // AGGREGATOR with wrong flags: discard (§3(f)).
    let bytes = update_bytes(
        &format!("40010100 {AS_PATH} {NEXT_HOP} 400708 0000fbf5 c0000201"),
        NLRI,
    );
    let update = decoded_update(&bytes, &NEG4);
    assert_eq!(update.treat_as_withdraw, None);
    assert_eq!(update.discarded.len(), 1);

    // AS4_PATH shorter than 6 bytes from a 2-octet peer (RFC 6793 §6).
    let bytes = update_bytes(&format!("40010100 40020402 01fbf5 {NEXT_HOP} c01100"), NLRI);
    let update = decoded_update(&bytes, &NEG2);
    assert_eq!(update.treat_as_withdraw, None);
    assert_eq!(update.discarded.len(), 1);
}

#[test]
fn confederation_segments_are_a_malformed_as_path() {
    // RFC 5065 §5: AS_CONFED_SEQUENCE [65001] from a neighbor outside our
    // (non-existent) confederation.
    let bytes = update_bytes(
        &format!("40010100 40020c 0301 0000fde9 0201 0000fbf5 {NEXT_HOP}"),
        NLRI,
    );
    let update = decoded_update(&bytes, &NEG4);
    assert_eq!(update.treat_as_withdraw, Some(DecodeError::MalformedAsPath));
}

#[test]
fn duplicate_large_communities_are_removed() {
    let c = "0000fbf5 00000001 00000002";
    let bytes = update_bytes(
        &format!("40010100 {AS_PATH} {NEXT_HOP} c02018 {c} {c}"),
        NLRI,
    );
    let update = decoded_update(&bytes, &NEG4);
    let Some(PathAttr::LargeCommunities(values)) = update.attr(type_code::LARGE_COMMUNITIES) else {
        panic!("no large communities");
    };
    assert_eq!(values.len(), 1);
}

#[test]
fn next_hop_is_ignored_in_mp_only_updates() {
    // RFC 4760 §3: NEXT_HOP 0.0.0.0 next to an IPv6 MP_REACH.
    let bytes = update_bytes(
        &format!(
            "800e1c 0002 01 10 20010db8000000000000000000000001 00 30 20010db80001 40010100 {AS_PATH} 40030400000000"
        ),
        "",
    );
    let update = decoded_update(&bytes, &NEG4);
    assert_eq!(update.treat_as_withdraw, None);
    assert!(update.attr(type_code::NEXT_HOP).is_none());
    assert_eq!(update.mp_reach.unwrap().nlri.len(), 1);
}

#[test]
fn shutdown_text_is_at_most_128_bytes() {
    let n = Notification::admin_shutdown(&"x".repeat(300));
    assert_eq!((n.data[0], n.data.len()), (128, 129));
}

#[test]
fn unused_flag_bits_are_not_sent() {
    let update = Update {
        attrs: vec![PathAttr::Unknown {
            flags: 0xcf,
            code: 99,
            value: Bytes::from_static(&[1]),
        }],
        ..Update::default()
    };
    let bytes = encode(&Message::Update(update), &NEG4);
    assert_eq!(bytes[23], 0xc0);
}

#[test]
fn notification_shutdown_text() {
    let n = Notification::admin_shutdown("maintenance");
    assert_eq!(n.shutdown_text().as_deref(), Some("maintenance"));
    // Administrative Reset carries a text too; other subcodes do not.
    let reset = Notification::new(
        error_code::CEASE,
        cease_subcode::ADMINISTRATIVE_RESET,
        n.data.clone(),
    );
    assert_eq!(reset.shutdown_text().as_deref(), Some("maintenance"));
    let other = Notification::new(
        error_code::CEASE,
        cease_subcode::PEER_DECONFIGURED,
        n.data.clone(),
    );
    assert_eq!(other.shutdown_text(), None);
    // A length beyond the data is cut, invalid UTF-8 replaced, empty is none.
    let long = Notification::new(error_code::CEASE, 2, Bytes::from_static(b"\x10ab\xff"));
    assert_eq!(long.shutdown_text().as_deref(), Some("ab\u{fffd}"));
    let empty = Notification::new(error_code::CEASE, 2, Bytes::from_static(b"\x00"));
    assert_eq!(empty.shutdown_text(), None);
    assert_eq!(
        Notification::new(error_code::CEASE, 2, Bytes::new()).shutdown_text(),
        None
    );
}

#[test]
fn open_graceful_restart() {
    // GR: R + N, restart time 120; IPv4 unicast F=1, IPv6 unicast F=0.
    let bytes = msg("002b 01 04 fbf5 005a c0000202 0e 02 0c
                     400a c078 0001 01 80 0002 01 00");
    let open = Open {
        my_as: 64501,
        hold_time: 90,
        bgp_id: Ipv4Addr::new(192, 0, 2, 2),
        capabilities: vec![Capability::GracefulRestart(GracefulRestart {
            restarting: true,
            notification: true,
            restart_time: 120,
            families: vec![
                GrFamily {
                    afi: Afi::IPV4,
                    safi: Safi::UNICAST,
                    forwarding: true,
                },
                GrFamily {
                    afi: Afi::IPV6,
                    safi: Safi::UNICAST,
                    forwarding: false,
                },
            ],
        })],
    };
    roundtrip(&bytes, &NEG2, Message::Open(open));

    // No families (helper only, RFC 4724 §3), no flags; reserved flag bits ignored.
    let Message::Open(open) = decode(
        &msg("0023 01 04 fbf5 005a c0000202 06 02 04 40 02 1000"),
        &NEG2,
    )
    .unwrap() else {
        panic!("not an OPEN");
    };
    assert_eq!(
        open.capabilities,
        [Capability::GracefulRestart(GracefulRestart {
            restarting: false,
            notification: false,
            restart_time: 0,
            families: vec![],
        })]
    );

    // Restart time over 12 bits is cut to the maximum.
    let gr = GracefulRestart {
        restarting: false,
        notification: false,
        restart_time: 5000,
        families: vec![],
    };
    let open = Open::new(
        64500,
        90,
        Ipv4Addr::new(192, 0, 2, 1),
        vec![Capability::GracefulRestart(gr)],
    );
    let Message::Open(back) = decode(&encode(&Message::Open(open), &NEG2), &NEG2).unwrap() else {
        panic!("not an OPEN");
    };
    assert!(
        back.capabilities
            .contains(&Capability::GracefulRestart(GracefulRestart {
                restarting: false,
                notification: false,
                restart_time: GracefulRestart::MAX_RESTART_TIME,
                families: vec![],
            }))
    );

    // A partial family is malformed.
    let err = decode(
        &msg("0025 01 04 fbf5 005a c0000202 08 02 06 40 04 0078 0001"),
        &NEG2,
    )
    .unwrap_err();
    assert_eq!(err, DecodeError::MalformedOpen);
}

#[test]
fn notification_hard_reset() {
    let inner = Notification::admin_shutdown("stop");
    let hard = Notification::hard_reset(&inner);
    assert!(hard.is_hard_reset());
    assert_eq!((hard.code, hard.subcode), (6, 9));
    assert_eq!(
        &hard.data[..],
        b"\x06\x02\x04stop",
        "RFC 8538 §3: code, subcode, data"
    );
    assert_eq!(hard.hard_reset_inner(), Some(inner.clone()));
    assert_eq!(hard.shutdown_text().as_deref(), Some("stop"));
    assert!(!inner.is_hard_reset());
    assert_eq!(inner.hard_reset_inner(), None);
    // Empty Hard Reset: nothing inside.
    let empty = Notification::new(error_code::CEASE, cease_subcode::HARD_RESET, Bytes::new());
    assert_eq!(empty.hard_reset_inner(), None);
    assert_eq!(empty.shutdown_text(), None);
    roundtrip(
        &encode(&Message::Notification(hard.clone()), &NEG4),
        &NEG4,
        Message::Notification(hard),
    );
}
