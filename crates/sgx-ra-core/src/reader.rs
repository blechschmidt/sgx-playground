//! Bounds-checked little-endian cursor used by the SGX structure parsers.

use crate::sgx::ParseError;

/// A forward-only cursor over a byte slice. Every read is bounds-checked and
/// reports which structure was truncated.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, pos: 0, what }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        if self.remaining() < len {
            return Err(ParseError::Truncated {
                what: self.what,
                needed: self.pos.saturating_add(len),
                available: self.buf.len(),
            });
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u16_le(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32_le(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Fails unless the whole input has been consumed.
    pub(crate) fn finish(self) -> Result<(), ParseError> {
        match self.remaining() {
            0 => Ok(()),
            extra => Err(ParseError::TrailingBytes {
                what: self.what,
                extra,
            }),
        }
    }
}

/// Copies `N` bytes starting at `offset` out of a buffer whose length the
/// caller has already validated.
pub(crate) fn array_at<const N: usize>(buf: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[offset..offset + N]);
    out
}

pub(crate) fn u16_le_at(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(array_at(buf, offset))
}

pub(crate) fn u32_le_at(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(array_at(buf, offset))
}

pub(crate) fn u64_le_at(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(array_at(buf, offset))
}
