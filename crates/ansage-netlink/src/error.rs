use std::{fmt, io};

use thiserror::Error;

use super::{
    Body, HEADER_LEN, Header, NLM_F_ACK_TLVS, NLM_F_CAPPED,
    attr::{attrs, u32_at, value_str, value_u32},
};

/// A message from the kernel that does not have the expected layout.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("netlink message truncated")]
    Truncated,
    #[error("bad netlink message length {0}")]
    BadLength(u32),
    #[error("netlink message type {0} too short")]
    Short(u16),
    #[error("bad attribute {attr} in netlink message type {kind}")]
    Attribute { kind: u16, attr: u16 },
    #[error("netlink message type {kind} without attribute {attr}")]
    Missing { kind: u16, attr: u16 },
    #[error("unsupported address family {0}")]
    Family(u8),
    #[error("prefix length {0} out of range")]
    PrefixLength(u8),
}

/// The kernel refused a request (NLMSG_ERROR with an errno).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelError {
    /// Positive errno, e.g. `libc::EEXIST`.
    pub errno: i32,
    /// Extended ACK text (NLMSGERR_ATTR_MSG), e.g. "Nexthop id does not exist".
    pub message: Option<String>,
    /// Offset of the offending attribute in the request (NLMSGERR_ATTR_OFFS).
    pub offset: Option<u32>,
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let os = io::Error::from_raw_os_error(self.errno);
        match &self.message {
            Some(m) => write!(f, "{m} ({os})"),
            None => write!(f, "{os}"),
        }
    }
}

impl std::error::Error for KernelError {}

const NLMSGERR_ATTR_MSG: u16 = 1;
const NLMSGERR_ATTR_OFFS: u16 = 2;

/// `struct nlmsgerr`: int error, then the request's header (and its body
/// unless NLM_F_CAPPED), then extended ACK attributes if NLM_F_ACK_TLVS.
pub(crate) fn decode_error(header: &Header, body: &[u8]) -> Result<Body, DecodeError> {
    let short = DecodeError::Short(header.kind);
    if body.len() < 4 + HEADER_LEN {
        return Err(short);
    }
    let errno = (u32_at(body, 0) as i32).wrapping_neg();
    if errno == 0 {
        return Ok(Body::Ack);
    }
    let mut tlvs = 4 + HEADER_LEN;
    if header.flags & NLM_F_CAPPED == 0 {
        // The request is echoed in full; its own length says how long.
        let echoed = u32_at(body, 4) as usize;
        tlvs = 4 + echoed.max(HEADER_LEN);
        if tlvs > body.len() {
            return Err(short);
        }
        tlvs = super::attr::align(tlvs).min(body.len());
    }
    Ok(Body::Error(kernel_error(header, errno, &body[tlvs..])?))
}

/// NLMSG_DONE: int error (0 = the dump completed), then extended ACK
/// attributes if NLM_F_ACK_TLVS.
pub(crate) fn decode_done(header: &Header, body: &[u8]) -> Result<Body, DecodeError> {
    // Very old kernels sent an empty DONE.
    if body.len() < 4 {
        return Ok(Body::Done);
    }
    let errno = (u32_at(body, 0) as i32).wrapping_neg();
    if errno == 0 {
        return Ok(Body::Done);
    }
    Ok(Body::Error(kernel_error(header, errno, &body[4..])?))
}

fn kernel_error(header: &Header, errno: i32, tlvs: &[u8]) -> Result<KernelError, DecodeError> {
    let mut err = KernelError {
        errno,
        message: None,
        offset: None,
    };
    if header.flags & NLM_F_ACK_TLVS == 0 {
        return Ok(err);
    }
    for attr in attrs(tlvs) {
        let (kind, value) = attr.map_err(|bad| DecodeError::Attribute {
            kind: header.kind,
            attr: bad.0,
        })?;
        match kind {
            NLMSGERR_ATTR_MSG => err.message = Some(value_str(value)),
            NLMSGERR_ATTR_OFFS => err.offset = value_u32(value),
            _ => {}
        }
    }
    Ok(err)
}
