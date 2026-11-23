//! Minimal lowercase hex encoding/decoding for measurements and diagnostics.

use core::fmt;

/// Error returned by [`decode_into`] and the `from_hex` constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The input has the wrong number of hex digits.
    InvalidLength {
        /// Number of hex digits expected.
        expected: usize,
        /// Number of hex digits found.
        actual: usize,
    },
    /// The input contains a character outside `[0-9a-fA-F]`.
    InvalidCharacter {
        /// Byte offset of the offending character in the input.
        index: usize,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} hex digits, got {actual}")
            }
            Self::InvalidCharacter { index } => {
                write!(f, "invalid hex character at offset {index}")
            }
        }
    }
}

impl core::error::Error for HexError {}

/// Decodes `input` into exactly `out.len()` bytes. Surrounding whitespace is
/// ignored; an optional `0x` prefix is accepted.
pub fn decode_into(input: &str, out: &mut [u8]) -> Result<(), HexError> {
    let trimmed = input.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .as_bytes();
    if digits.len() != out.len() * 2 {
        return Err(HexError::InvalidLength {
            expected: out.len() * 2,
            actual: digits.len(),
        });
    }
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = nibble(digits[2 * i]).ok_or(HexError::InvalidCharacter { index: 2 * i })?;
        let lo =
            nibble(digits[2 * i + 1]).ok_or(HexError::InvalidCharacter { index: 2 * i + 1 })?;
        *byte = (hi << 4) | lo;
    }
    Ok(())
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `Display` adapter printing a byte slice as lowercase hex.
#[derive(Debug, Clone, Copy)]
pub struct Hex<'a>(pub &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn roundtrip() {
        let mut out = [0u8; 4];
        decode_into(" 0xDEADbeef\n", &mut out).unwrap();
        assert_eq!(out, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(Hex(&out).to_string(), "deadbeef");
    }

    #[test]
    fn rejects_bad_input() {
        let mut out = [0u8; 2];
        assert_eq!(
            decode_into("abc", &mut out),
            Err(HexError::InvalidLength {
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            decode_into("ab0g", &mut out),
            Err(HexError::InvalidCharacter { index: 3 })
        );
    }
}
