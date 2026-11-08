use bytes::Bytes;
use thiserror::Error;

use super::{
    notification::{Notification, error_code},
    open::BGP_VERSION,
};

/// A received message that violates the protocol.
///
/// Each variant maps to the NOTIFICATION RFC 4271 §6 prescribes, see
/// [`DecodeError::notification`]. Attribute errors carry the complete
/// offending attribute (flags, type, length, value) as NOTIFICATION data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("connection not synchronized (bad marker)")]
    ConnectionNotSynchronized,
    #[error("bad message length {0}")]
    BadMessageLength(u16),
    #[error("bad message type {0}")]
    BadMessageType(u8),

    #[error("malformed OPEN message")]
    MalformedOpen,
    #[error("unsupported BGP version {0}")]
    UnsupportedVersion(u8),
    #[error("bad peer AS {0}")]
    BadPeerAs(u32),
    #[error("bad BGP identifier")]
    BadBgpIdentifier,
    #[error("unsupported optional parameter {0}")]
    UnsupportedOptionalParameter(u8),
    #[error("unacceptable hold time {0}")]
    UnacceptableHoldTime(u16),

    #[error("malformed attribute list")]
    MalformedAttributeList,
    #[error("unrecognized well-known attribute (type {})", attr_type(.0))]
    UnrecognizedWellKnownAttribute(Bytes),
    #[error("missing well-known attribute (type {0})")]
    MissingWellKnownAttribute(u8),
    #[error("attribute flags error (type {})", attr_type(.0))]
    AttributeFlags(Bytes),
    #[error("attribute length error (type {})", attr_type(.0))]
    AttributeLength(Bytes),
    #[error("invalid ORIGIN attribute")]
    InvalidOrigin(Bytes),
    #[error("invalid NEXT_HOP attribute")]
    InvalidNextHop(Bytes),
    #[error("optional attribute error (type {})", attr_type(.0))]
    OptionalAttribute(Bytes),
    #[error("invalid network field")]
    InvalidNetworkField,
    #[error("malformed AS_PATH")]
    MalformedAsPath,
}

fn attr_type(raw: &Bytes) -> u8 {
    raw.get(1).copied().unwrap_or(0)
}

impl DecodeError {
    /// The NOTIFICATION to send before closing the session.
    pub fn notification(&self) -> Notification {
        use DecodeError::*;
        use error_code::{MESSAGE_HEADER, OPEN_MESSAGE, UPDATE_MESSAGE};

        let none = Bytes::new;
        let (code, subcode, data) = match self {
            ConnectionNotSynchronized => (MESSAGE_HEADER, 1, none()),
            BadMessageLength(len) => (MESSAGE_HEADER, 2, copy(&len.to_be_bytes())),
            BadMessageType(kind) => (MESSAGE_HEADER, 3, copy(&[*kind])),

            MalformedOpen => (OPEN_MESSAGE, 0, none()),
            // Data: the largest version we support.
            UnsupportedVersion(_) => (OPEN_MESSAGE, 1, copy(&u16::from(BGP_VERSION).to_be_bytes())),
            BadPeerAs(_) => (OPEN_MESSAGE, 2, none()),
            BadBgpIdentifier => (OPEN_MESSAGE, 3, none()),
            UnsupportedOptionalParameter(_) => (OPEN_MESSAGE, 4, none()),
            UnacceptableHoldTime(_) => (OPEN_MESSAGE, 6, none()),

            MalformedAttributeList => (UPDATE_MESSAGE, 1, none()),
            UnrecognizedWellKnownAttribute(attr) => (UPDATE_MESSAGE, 2, attr.clone()),
            MissingWellKnownAttribute(code) => (UPDATE_MESSAGE, 3, copy(&[*code])),
            AttributeFlags(attr) => (UPDATE_MESSAGE, 4, attr.clone()),
            AttributeLength(attr) => (UPDATE_MESSAGE, 5, attr.clone()),
            InvalidOrigin(attr) => (UPDATE_MESSAGE, 6, attr.clone()),
            InvalidNextHop(attr) => (UPDATE_MESSAGE, 8, attr.clone()),
            OptionalAttribute(attr) => (UPDATE_MESSAGE, 9, attr.clone()),
            InvalidNetworkField => (UPDATE_MESSAGE, 10, none()),
            MalformedAsPath => (UPDATE_MESSAGE, 11, none()),
        };
        Notification::new(code, subcode, data)
    }
}

fn copy(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(data)
}

/// A message that cannot be encoded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("message of {len} bytes exceeds the maximum of {max}")]
    MessageTooLong { len: usize, max: usize },
    #[error("attribute type {0} exceeds 65535 bytes")]
    AttributeTooLong(u8),
    #[error("OPEN optional parameters exceed 255 bytes")]
    OptionalParametersTooLong,
    /// IPv6 routes without an MP_REACH next hop, or IPv4 routes with neither
    /// NEXT_HOP nor a usable IPv6 next hop (RFC 8950).
    #[error("routes without a next hop for their family")]
    MissingNextHop,
}
