use bytes::{BufMut, Bytes, BytesMut};

use super::{Afi, DecodeError, Safi, body_len_field, reader::Reader};

/// ROUTE-REFRESH message (RFC 2918). `subtype` is the reserved octet that
/// enhanced route refresh (RFC 7313) uses; 0 for a plain refresh request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefresh {
    pub afi: Afi,
    pub subtype: u8,
    pub safi: Safi,
}

impl RouteRefresh {
    /// Trailing ORF entries (RFC 5291) are ignored; we never negotiate ORF.
    pub(crate) fn decode(body: Bytes) -> Result<Self, DecodeError> {
        let mut r = Reader::new(
            body.clone(),
            DecodeError::BadMessageLength(body_len_field(&body)),
        );
        Ok(Self {
            afi: Afi(r.u16()?),
            subtype: r.u8()?,
            safi: Safi(r.u8()?),
        })
    }

    pub(crate) fn encode_body(&self, buf: &mut BytesMut) {
        buf.put_u16(self.afi.0);
        buf.put_u8(self.subtype);
        buf.put_u8(self.safi.0);
    }
}
