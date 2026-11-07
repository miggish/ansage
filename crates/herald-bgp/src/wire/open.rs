use std::net::Ipv4Addr;

use bytes::{BufMut, Bytes, BytesMut};

use super::{Afi, DecodeError, EncodeError, Safi, reader::Reader};

pub const BGP_VERSION: u8 = 4;
/// Placeholder in 2-octet AS fields for an ASN that needs 4 octets (RFC 6793).
pub const AS_TRANS: u16 = 23456;

const PARAM_CAPABILITIES: u8 = 2;
/// RFC 9072: marks the extended optional parameters format.
const PARAM_EXTENDED: u8 = 255;

const CAP_MULTIPROTOCOL: u8 = 1;
const CAP_ROUTE_REFRESH: u8 = 2;
const CAP_EXTENDED_MESSAGE: u8 = 6;
const CAP_GRACEFUL_RESTART: u8 = 64;
const CAP_FOUR_OCTET_AS: u8 = 65;

/// BGP capability (RFC 5492).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// RFC 4760
    Multiprotocol {
        afi: Afi,
        safi: Safi,
    },
    /// RFC 2918
    RouteRefresh,
    /// RFC 8654
    ExtendedMessage,
    /// RFC 4724, N-bit from RFC 8538
    GracefulRestart(GracefulRestart),
    /// RFC 6793
    FourOctetAs(u32),
    Unknown {
        code: u8,
        value: Bytes,
    },
}

impl Capability {
    fn decode(code: u8, value: Bytes) -> Result<Self, DecodeError> {
        let mut r = Reader::new(value, DecodeError::MalformedOpen);
        let cap = match code {
            CAP_MULTIPROTOCOL => {
                let afi = Afi(r.u16()?);
                let _reserved = r.u8()?;
                let safi = Safi(r.u8()?);
                Capability::Multiprotocol { afi, safi }
            }
            CAP_ROUTE_REFRESH => Capability::RouteRefresh,
            CAP_EXTENDED_MESSAGE => Capability::ExtendedMessage,
            CAP_GRACEFUL_RESTART => Capability::GracefulRestart(GracefulRestart::decode(&mut r)?),
            CAP_FOUR_OCTET_AS => Capability::FourOctetAs(r.u32()?),
            _ => {
                return Ok(Capability::Unknown {
                    code,
                    value: r.rest(),
                });
            }
        };
        r.finish()?;
        Ok(cap)
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Capability::Multiprotocol { afi, safi } => {
                buf.put_slice(&[CAP_MULTIPROTOCOL, 4]);
                buf.put_u16(afi.0);
                buf.put_u8(0);
                buf.put_u8(safi.0);
            }
            Capability::RouteRefresh => buf.put_slice(&[CAP_ROUTE_REFRESH, 0]),
            Capability::ExtendedMessage => buf.put_slice(&[CAP_EXTENDED_MESSAGE, 0]),
            Capability::GracefulRestart(gr) => gr.encode(buf),
            Capability::FourOctetAs(asn) => {
                buf.put_slice(&[CAP_FOUR_OCTET_AS, 4]);
                buf.put_u32(*asn);
            }
            Capability::Unknown { code, value } => {
                // Oversized values fail the parameter length check in Open::encode_body.
                buf.put_u8(*code);
                buf.put_u8(u8::try_from(value.len()).unwrap_or(u8::MAX));
                buf.put_slice(value);
            }
        }
    }
}

/// Graceful Restart capability (RFC 4724 §3, N-bit RFC 8538 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GracefulRestart {
    /// R: the speaker has just restarted (RFC 4724 §3: the peer must not wait
    /// for its End-of-RIB before sending its own routes).
    pub restarting: bool,
    /// N: the speaker supports Graceful Restart for NOTIFICATIONs
    /// (RFC 8538): only Cease / Hard Reset ends the routes at once.
    pub notification: bool,
    /// Seconds the peer should keep our routes after a session loss, 12 bits.
    pub restart_time: u16,
    pub families: Vec<GrFamily>,
}

/// An address family in the Graceful Restart capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrFamily {
    pub afi: Afi,
    pub safi: Safi,
    /// F: forwarding state for this family was kept across the restart.
    pub forwarding: bool,
}

impl GracefulRestart {
    const RESTARTING: u16 = 0x8000;
    const NOTIFICATION: u16 = 0x4000;
    pub const MAX_RESTART_TIME: u16 = 0x0fff;
    const FORWARDING: u8 = 0x80;

    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let flags = r.u16()?;
        let mut families = Vec::new();
        // Each family is 4 bytes; a partial one fails the reader.
        while !r.is_empty() {
            let afi = Afi(r.u16()?);
            let safi = Safi(r.u8()?);
            let forwarding = r.u8()? & Self::FORWARDING != 0;
            families.push(GrFamily {
                afi,
                safi,
                forwarding,
            });
        }
        Ok(Self {
            restarting: flags & Self::RESTARTING != 0,
            notification: flags & Self::NOTIFICATION != 0,
            restart_time: flags & Self::MAX_RESTART_TIME,
            families,
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
        let mut flags = self.restart_time.min(Self::MAX_RESTART_TIME);
        if self.restarting {
            flags |= Self::RESTARTING;
        }
        if self.notification {
            flags |= Self::NOTIFICATION;
        }
        // Oversized family lists fail the parameter length check in Open::encode_body.
        let len = 2 + 4 * self.families.len();
        buf.put_u8(CAP_GRACEFUL_RESTART);
        buf.put_u8(u8::try_from(len).unwrap_or(u8::MAX));
        buf.put_u16(flags);
        for f in &self.families {
            buf.put_u16(f.afi.0);
            buf.put_u8(f.safi.0);
            buf.put_u8(if f.forwarding { Self::FORWARDING } else { 0 });
        }
    }
}

/// OPEN message, fields as on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    /// The 2-octet "My Autonomous System" field: [`AS_TRANS`] when the real
    /// ASN needs 4 octets. Use [`Open::asn`] for the speaker's ASN.
    pub my_as: u16,
    pub hold_time: u16,
    pub bgp_id: Ipv4Addr,
    pub capabilities: Vec<Capability>,
}

impl Open {
    /// Builds an OPEN for `asn`, filling `my_as` and adding the 4-octet AS
    /// capability unless `capabilities` already has it.
    pub fn new(
        asn: u32,
        hold_time: u16,
        bgp_id: Ipv4Addr,
        mut capabilities: Vec<Capability>,
    ) -> Self {
        if !capabilities
            .iter()
            .any(|c| matches!(c, Capability::FourOctetAs(_)))
        {
            capabilities.push(Capability::FourOctetAs(asn));
        }
        Self {
            my_as: u16::try_from(asn).unwrap_or(AS_TRANS),
            hold_time,
            bgp_id,
            capabilities,
        }
    }

    /// The speaker's ASN: from the 4-octet AS capability if present, else
    /// `my_as`.
    pub fn asn(&self) -> u32 {
        self.capabilities
            .iter()
            .find_map(|c| match c {
                Capability::FourOctetAs(asn) => Some(*asn),
                _ => None,
            })
            .unwrap_or(u32::from(self.my_as))
    }

    pub(crate) fn decode(body: Bytes) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body, DecodeError::MalformedOpen);
        let version = r.u8()?;
        if version != BGP_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let my_as = r.u16()?;
        let hold_time = r.u16()?;
        if hold_time == 1 || hold_time == 2 {
            return Err(DecodeError::UnacceptableHoldTime(hold_time));
        }
        let bgp_id = Ipv4Addr::from(r.u32()?);
        if bgp_id.is_unspecified() {
            return Err(DecodeError::BadBgpIdentifier);
        }

        // RFC 9072 §2/§3: a first parameter of type 255 means the extended
        // format, whatever the (non-extended) length says, as long as it is
        // not zero.
        let mut params_len = usize::from(r.u8()?);
        let extended = params_len != 0 && r.peek_u8() == Some(PARAM_EXTENDED);
        if extended {
            r.u8()?;
            params_len = usize::from(r.u16()?);
        }
        let mut params = Reader::new(r.bytes(params_len)?, DecodeError::MalformedOpen);
        r.finish()?;

        let mut capabilities = Vec::with_capacity(params_len);
        while !params.is_empty() {
            let kind = params.u8()?;
            let len = if extended {
                usize::from(params.u16()?)
            } else {
                usize::from(params.u8()?)
            };
            let value = params.bytes(len)?;
            if kind != PARAM_CAPABILITIES {
                return Err(DecodeError::UnsupportedOptionalParameter(kind));
            }
            let mut caps = Reader::new(value, DecodeError::MalformedOpen);
            while !caps.is_empty() {
                let code = caps.u8()?;
                let len = usize::from(caps.u8()?);
                capabilities.push(Capability::decode(code, caps.bytes(len)?)?);
            }
        }

        Ok(Self {
            my_as,
            hold_time,
            bgp_id,
            capabilities,
        })
    }

    /// All capabilities go into one optional parameter.
    pub(crate) fn encode_body(&self, buf: &mut BytesMut) -> Result<(), EncodeError> {
        buf.put_u8(BGP_VERSION);
        buf.put_u16(self.my_as);
        buf.put_u16(self.hold_time);
        buf.put_u32(self.bgp_id.into());
        if self.capabilities.is_empty() {
            buf.put_u8(0);
            return Ok(());
        }

        let start = buf.len();
        buf.put_slice(&[0, PARAM_CAPABILITIES, 0]);
        for cap in &self.capabilities {
            cap.encode(buf);
        }
        let caps_len = buf.len() - start - 3;
        let (Ok(params_len), Ok(caps_len)) = (u8::try_from(caps_len + 2), u8::try_from(caps_len))
        else {
            return Err(EncodeError::OptionalParametersTooLong);
        };
        buf[start] = params_len;
        buf[start + 2] = caps_len;
        Ok(())
    }
}
