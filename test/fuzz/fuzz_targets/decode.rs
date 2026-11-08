//! Feeds arbitrary bytes through framing and decoding. Must never panic, and
//! every message that decodes must survive an encode/decode round trip.

#![no_main]

use bytes::BytesMut;
use ansage_bgp::wire::Message;
use ansage_bgp::wire::Negotiated;
use ansage_bgp::wire::split_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for neg in [
        Negotiated::default(),
        Negotiated {
            four_octet_as: true,
            extended_message: true,
            ibgp: false,
            extended_next_hop: true,
        },
    ] {
        let mut buf = BytesMut::from(data);
        while let Ok(Some((kind, body))) = split_message(&mut buf, neg.max_message_len()) {
            let Ok(message) = Message::decode(kind, body, &neg) else {
                continue;
            };
            // RFC 7606 dropped something: the re-encoded message differs by design.
            if let Message::Update(u) = &message
                && (u.treat_as_withdraw.is_some() || !u.discarded.is_empty())
            {
                continue;
            }
            let mut out = BytesMut::new();
            if message.encode(&neg, &mut out).is_err() {
                continue;
            }
            let (kind, body) = split_message(&mut out, neg.max_message_len())
                .expect("re-encoded message frames")
                .expect("re-encoded message is complete");
            let again = Message::decode(kind, body, &neg).expect("re-encoded message decodes");
            assert_eq!(again, message);
        }
    }
});
