//! BGP-4 wire format (RFC 4271): decoding and encoding of messages.
//!
//! Pure functions over byte buffers, no I/O and no async. The session layer
//! reads from the socket into a `BytesMut`, cuts complete messages off the
//! front with [`split_message`] and parses them with [`Message::decode`].
//! Decoded messages share the receive buffer (zero-copy `Bytes`).

mod attrs;
mod error;
mod header;
mod notification;
mod open;
pub mod pack;
mod prefix;
mod reader;
mod route_refresh;
mod update;

#[cfg(test)]
mod tests;

use bytes::{Bytes, BytesMut};

pub use attrs::{
    Aggregator, AsPath, AsSegment, GRACEFUL_SHUTDOWN, LargeCommunity, MpReach, MpUnreach, NextHop,
    Origin, PathAttr, SegmentType, attr_flags, decode_path_attrs, encode_next_hop,
    encode_path_attrs, path_len, type_code,
};
pub use error::{DecodeError, EncodeError};
pub use header::{
    HEADER_LEN, MAX_EXTENDED_MESSAGE_LEN, MAX_MESSAGE_LEN, MessageType, split_message,
};
pub use notification::{Notification, cease_subcode, error_code};
pub use open::{
    AS_TRANS, BGP_VERSION, Capability, ExtendedNextHop, GrFamily, GracefulRestart, Open,
};
pub use prefix::{Prefix, Prefix4, Prefix6, PrefixError};
pub use route_refresh::RouteRefresh;
pub use update::Update;

/// Address Family Identifier (IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Afi(pub u16);

impl Afi {
    pub const IPV4: Self = Self(1);
    pub const IPV6: Self = Self(2);
}

/// Subsequent Address Family Identifier (IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Safi(pub u8);

impl Safi {
    pub const UNICAST: Self = Self(1);
}

/// Session parameters agreed in the OPEN exchange that change how messages
/// are encoded. Before the exchange all are `false`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Negotiated {
    /// Both sides sent the 4-octet AS capability (RFC 6793): AS numbers in
    /// AS_PATH and AGGREGATOR are 4 octets wide.
    pub four_octet_as: bool,
    /// Both sides sent the Extended Message capability (RFC 8654).
    pub extended_message: bool,
    /// Both sides are in the same AS. Changes RFC 7606 handling of a
    /// malformed LOCAL_PREF (treat-as-withdraw instead of attribute discard).
    pub ibgp: bool,
    /// Both sides sent the Extended Next Hop Encoding capability for IPv4
    /// unicast with IPv6 next hops (RFC 8950): IPv4 routes may come in
    /// MP_REACH_NLRI with an IPv6 next hop, and may be sent that way.
    pub extended_next_hop: bool,
}

impl Negotiated {
    /// Largest message this session may send or receive.
    pub fn max_message_len(&self) -> usize {
        if self.extended_message {
            MAX_EXTENDED_MESSAGE_LEN
        } else {
            MAX_MESSAGE_LEN
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Open(Open),
    Update(Update),
    Notification(Notification),
    Keepalive,
    RouteRefresh(RouteRefresh),
}

impl Message {
    pub fn kind(&self) -> MessageType {
        match self {
            Message::Open(_) => MessageType::Open,
            Message::Update(_) => MessageType::Update,
            Message::Notification(_) => MessageType::Notification,
            Message::Keepalive => MessageType::Keepalive,
            Message::RouteRefresh(_) => MessageType::RouteRefresh,
        }
    }

    /// Parses a message body as returned by [`split_message`].
    pub fn decode(kind: MessageType, body: Bytes, neg: &Negotiated) -> Result<Self, DecodeError> {
        Ok(match kind {
            MessageType::Open => Message::Open(Open::decode(body)?),
            MessageType::Update => Message::Update(Update::decode(body, neg)?),
            MessageType::Notification => Message::Notification(Notification::decode(body)?),
            MessageType::Keepalive => {
                if !body.is_empty() {
                    return Err(DecodeError::BadMessageLength(body_len_field(&body)));
                }
                Message::Keepalive
            }
            MessageType::RouteRefresh => Message::RouteRefresh(RouteRefresh::decode(body)?),
        })
    }

    /// Appends the encoded message (header included) to `buf`.
    /// On error `buf` is left as it was.
    pub fn encode(&self, neg: &Negotiated, buf: &mut BytesMut) -> Result<(), EncodeError> {
        let kind = self.kind();
        let start = header::begin(buf, kind);
        let result = match self {
            Message::Open(m) => m.encode_body(buf),
            Message::Update(m) => m.encode_body(neg, buf),
            Message::Notification(m) => {
                m.encode_body(buf);
                Ok(())
            }
            Message::Keepalive => Ok(()),
            Message::RouteRefresh(m) => {
                m.encode_body(buf);
                Ok(())
            }
        };
        // RFC 8654: OPEN and KEEPALIVE never exceed 4096 bytes.
        let max = match kind {
            MessageType::Open | MessageType::Keepalive => MAX_MESSAGE_LEN,
            _ => neg.max_message_len(),
        };
        let result = result.and_then(|()| header::finish(buf, start, max));
        if result.is_err() {
            buf.truncate(start);
        }
        result
    }
}

/// The header length field a body of this size came with, for error data.
fn body_len_field(body: &Bytes) -> u16 {
    u16::try_from(body.len() + HEADER_LEN).unwrap_or(u16::MAX)
}
