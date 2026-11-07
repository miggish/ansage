use bytes::{Buf, Bytes};

use super::DecodeError;

/// Bounds-checked reader over a `Bytes` buffer.
///
/// `bytes::Buf` panics when reading past the end; this returns the error the
/// reader was created with instead, so each context maps truncation to the
/// NOTIFICATION it calls for (e.g. Attribute Length Error inside an attribute).
pub(crate) struct Reader {
    buf: Bytes,
    err: DecodeError,
}

impl Reader {
    pub(crate) fn new(buf: Bytes, err: DecodeError) -> Self {
        Self { buf, err }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// The unread rest without consuming it (reference counted, no copy).
    pub(crate) fn peek_rest(&self) -> Bytes {
        self.buf.clone()
    }

    pub(crate) fn peek_u8(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    /// The error this reader reports, for format violations found by the
    /// caller.
    pub(crate) fn fail<T>(&self) -> Result<T, DecodeError> {
        Err(self.err.clone())
    }

    fn need(&self, n: usize) -> Result<(), DecodeError> {
        if self.buf.len() < n {
            self.fail()
        } else {
            Ok(())
        }
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        self.need(1)?;
        Ok(self.buf.get_u8())
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        self.need(2)?;
        Ok(self.buf.get_u16())
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        self.need(4)?;
        Ok(self.buf.get_u32())
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<Bytes, DecodeError> {
        self.need(n)?;
        Ok(self.buf.split_to(n))
    }

    pub(crate) fn fill(&mut self, dst: &mut [u8]) -> Result<(), DecodeError> {
        self.need(dst.len())?;
        self.buf.copy_to_slice(dst);
        Ok(())
    }

    pub(crate) fn rest(&mut self) -> Bytes {
        std::mem::take(&mut self.buf)
    }

    /// Fails if anything is left unread.
    pub(crate) fn finish(&self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            self.fail()
        }
    }
}
