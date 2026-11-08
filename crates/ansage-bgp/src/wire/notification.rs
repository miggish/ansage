use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};

use super::{DecodeError, body_len_field, reader::Reader};

/// NOTIFICATION error codes (RFC 4271 §4.5, RFC 7313).
pub mod error_code {
    pub const MESSAGE_HEADER: u8 = 1;
    pub const OPEN_MESSAGE: u8 = 2;
    pub const UPDATE_MESSAGE: u8 = 3;
    pub const HOLD_TIMER_EXPIRED: u8 = 4;
    pub const FSM: u8 = 5;
    pub const CEASE: u8 = 6;
    pub const ROUTE_REFRESH: u8 = 7;
}

/// Cease subcodes (RFC 4486, RFC 8538).
pub mod cease_subcode {
    pub const MAX_PREFIXES_REACHED: u8 = 1;
    pub const ADMINISTRATIVE_SHUTDOWN: u8 = 2;
    pub const PEER_DECONFIGURED: u8 = 3;
    pub const ADMINISTRATIVE_RESET: u8 = 4;
    pub const CONNECTION_REJECTED: u8 = 5;
    pub const OTHER_CONFIGURATION_CHANGE: u8 = 6;
    pub const CONNECTION_COLLISION_RESOLUTION: u8 = 7;
    pub const OUT_OF_RESOURCES: u8 = 8;
    pub const HARD_RESET: u8 = 9;
}

/// RFC 9003 §3: the limit for peers that may only know RFC 8203.
const SHUTDOWN_TEXT_MAX: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub code: u8,
    pub subcode: u8,
    pub data: Bytes,
}

impl Notification {
    pub fn new(code: u8, subcode: u8, data: Bytes) -> Self {
        Self {
            code,
            subcode,
            data,
        }
    }

    /// Cease / Administrative Shutdown with a shutdown communication
    /// (RFC 9003), cut to 128 bytes on a character boundary: whether the
    /// peer accepts the 255 bytes of RFC 9003 is unknown, and RFC 8203
    /// speakers treat longer texts as an error (RFC 9003 §3).
    pub fn admin_shutdown(reason: &str) -> Self {
        let mut end = reason.len().min(SHUTDOWN_TEXT_MAX);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        let mut data = BytesMut::with_capacity(end + 1);
        data.put_u8(end as u8);
        data.put_slice(&reason.as_bytes()[..end]);
        Self::new(
            error_code::CEASE,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            data.freeze(),
        )
    }

    /// Cease / Hard Reset (RFC 8538 §3) wrapping another NOTIFICATION: the
    /// data is the inner error code, subcode and data. A peer with the N-bit
    /// drops our routes at once only on a Hard Reset; other NOTIFICATIONs
    /// keep them.
    pub fn hard_reset(inner: &Notification) -> Self {
        let mut data = BytesMut::with_capacity(2 + inner.data.len());
        data.put_u8(inner.code);
        data.put_u8(inner.subcode);
        data.put_slice(&inner.data);
        Self::new(error_code::CEASE, cease_subcode::HARD_RESET, data.freeze())
    }

    pub fn is_hard_reset(&self) -> bool {
        self.code == error_code::CEASE && self.subcode == cease_subcode::HARD_RESET
    }

    /// The NOTIFICATION inside a Hard Reset, if this is one with at least
    /// a code and subcode.
    pub fn hard_reset_inner(&self) -> Option<Notification> {
        let [code, subcode, ..] = self.data[..] else {
            return None;
        };
        self.is_hard_reset()
            .then(|| Self::new(code, subcode, self.data.slice(2..)))
    }

    /// Cuts the data so the whole message fits in `max_len` bytes. A
    /// NOTIFICATION must always go out (RFC 4271 §6), and never over 4096
    /// bytes to a peer without extended messages (RFC 8654 §5).
    pub fn truncated(mut self, max_len: usize) -> Self {
        let room = max_len.saturating_sub(super::HEADER_LEN + 2);
        self.data.truncate(room);
        self
    }

    /// The operator's text of an Administrative Shutdown or Reset (RFC 9003
    /// §2): a length byte, then UTF-8. Invalid UTF-8 is replaced, a length
    /// beyond the data is cut to the data.
    /// A Hard Reset is read through to the Cease it wraps.
    pub fn shutdown_text(&self) -> Option<String> {
        if let Some(inner) = self.hard_reset_inner() {
            return inner.shutdown_text();
        }
        let shutdown = self.code == error_code::CEASE
            && matches!(
                self.subcode,
                cease_subcode::ADMINISTRATIVE_SHUTDOWN | cease_subcode::ADMINISTRATIVE_RESET
            );
        let (&len, rest) = self.data.split_first().filter(|_| shutdown)?;
        let text = &rest[..usize::from(len).min(rest.len())];
        (!text.is_empty()).then(|| String::from_utf8_lossy(text).into_owned())
    }

    pub fn hold_timer_expired() -> Self {
        Self::new(error_code::HOLD_TIMER_EXPIRED, 0, Bytes::new())
    }

    pub(crate) fn decode(body: Bytes) -> Result<Self, DecodeError> {
        let mut r = Reader::new(
            body.clone(),
            DecodeError::BadMessageLength(body_len_field(&body)),
        );
        let code = r.u8()?;
        let subcode = r.u8()?;
        Ok(Self::new(code, subcode, r.rest()))
    }

    pub(crate) fn encode_body(&self, buf: &mut BytesMut) {
        buf.put_u8(self.code);
        buf.put_u8(self.subcode);
        buf.put_slice(&self.data);
    }
}

impl fmt::Display for Notification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.code {
            error_code::MESSAGE_HEADER => "message header error",
            error_code::OPEN_MESSAGE => "OPEN message error",
            error_code::UPDATE_MESSAGE => "UPDATE message error",
            error_code::HOLD_TIMER_EXPIRED => "hold timer expired",
            error_code::FSM => "finite state machine error",
            error_code::CEASE => "cease",
            error_code::ROUTE_REFRESH => "ROUTE-REFRESH message error",
            _ => "unknown error",
        };
        write!(f, "{name} ({}/{})", self.code, self.subcode)
    }
}
