use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{DecodeError, EncodeError};

const MARKER: [u8; 16] = [0xff; 16];

/// Marker (16) + length (2) + type (1).
pub const HEADER_LEN: usize = 19;
/// Maximum message size without the Extended Message capability (RFC 4271).
pub const MAX_MESSAGE_LEN: usize = 4096;
/// Maximum message size with the Extended Message capability (RFC 8654).
pub const MAX_EXTENDED_MESSAGE_LEN: usize = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Open,
            2 => Self::Update,
            3 => Self::Notification,
            4 => Self::Keepalive,
            5 => Self::RouteRefresh,
            _ => return None,
        })
    }

    /// Smallest valid message of this type, header included.
    fn min_len(self) -> usize {
        match self {
            Self::Open => 29,
            Self::Update => 23,
            Self::Notification => 21,
            Self::Keepalive => HEADER_LEN,
            Self::RouteRefresh => 23,
        }
    }
}

/// Cuts the next complete message off the front of `buf`.
///
/// Returns `Ok(None)` until a whole message is buffered. The header is
/// validated as soon as it has arrived, so a garbage length is rejected
/// without waiting for its body. The returned body excludes the header.
pub fn split_message(
    buf: &mut BytesMut,
    max_len: usize,
) -> Result<Option<(MessageType, Bytes)>, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    if buf[..16] != MARKER {
        return Err(DecodeError::ConnectionNotSynchronized);
    }
    let len = u16::from_be_bytes([buf[16], buf[17]]);
    let kind = MessageType::from_u8(buf[18]).ok_or(DecodeError::BadMessageType(buf[18]))?;

    let size = usize::from(len);
    let valid = match kind {
        MessageType::Keepalive => size == HEADER_LEN,
        // RFC 8654: OPEN never exceeds 4096 bytes, even with extended messages.
        MessageType::Open => size >= kind.min_len() && size <= max_len.min(MAX_MESSAGE_LEN),
        _ => size >= kind.min_len() && size <= max_len,
    };
    if !valid {
        return Err(DecodeError::BadMessageLength(len));
    }
    if buf.len() < size {
        return Ok(None);
    }

    let mut message = buf.split_to(size);
    message.advance(HEADER_LEN);
    Ok(Some((kind, message.freeze())))
}

/// Writes a header with a placeholder length; returns the message start.
pub(crate) fn begin(buf: &mut BytesMut, kind: MessageType) -> usize {
    let start = buf.len();
    buf.put_slice(&MARKER);
    buf.put_u16(0);
    buf.put_u8(kind as u8);
    start
}

/// Fills in the length of the message that starts at `start`.
pub(crate) fn finish(buf: &mut BytesMut, start: usize, max_len: usize) -> Result<(), EncodeError> {
    let len = buf.len() - start;
    if len > max_len {
        return Err(EncodeError::MessageTooLong { len, max: max_len });
    }
    patch_u16(buf, start + 16, len);
    Ok(())
}

/// Overwrites the 2-octet field at `pos` with `value`. Callers check limits;
/// an oversized value is caught by the final message length check.
pub(crate) fn patch_u16(buf: &mut BytesMut, pos: usize, value: usize) {
    let value = u16::try_from(value).unwrap_or(u16::MAX);
    buf[pos..pos + 2].copy_from_slice(&value.to_be_bytes());
}
