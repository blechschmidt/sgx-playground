//! SGX data structures: DCAP quotes, report bodies and enclave signature
//! structures.
//!
//! The parsers use explicit offsets (see `docs/PROTOCOL.md` §3) rather than
//! `repr(C)` transmutes, validate every length field, and reject trailing
//! bytes. Parsing only establishes *structure*; nothing in this module checks
//! a signature. Cryptographic verification lives in `sgx-ra-verifier`.

use core::fmt;

use crate::hex::{self, Hex, HexError};

pub mod css;
pub mod quote;
pub mod report;

pub use css::{Gendata, Sigstruct, SigstructBody, SigstructHeader};
pub use quote::{CertificationData, Quote, QuoteHeader, QuoteSignature};
pub use report::{Attributes, Report, ReportBody, TargetInfo};

/// A 256-bit SGX measurement: MRENCLAVE or MRSIGNER.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Measurement(pub [u8; 32]);

impl Measurement {
    /// Parses 64 hex digits (optionally `0x`-prefixed).
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        let mut out = [0u8; 32];
        hex::decode_into(s, &mut out)?;
        Ok(Self(out))
    }

    /// The raw measurement bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Measurement {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hex(&self.0).fmt(f)
    }
}

impl fmt::Debug for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Measurement({self})")
    }
}

/// The 64 bytes of user data an enclave binds into its report
/// (`REPORTDATA`). The framework puts a hash of the enclave's channel key here.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReportData(pub [u8; 64]);

impl ReportData {
    /// All-zero report data.
    pub const ZERO: Self = Self([0u8; 64]);

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Default for ReportData {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 64]> for ReportData {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for ReportData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReportData({})", Hex(&self.0))
    }
}

/// Error returned by every parser in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input ended before the structure was complete.
    Truncated {
        /// Structure being parsed.
        what: &'static str,
        /// Bytes required up to and including the failing field.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// The structure was complete but more input followed.
    TrailingBytes {
        /// Structure being parsed.
        what: &'static str,
        /// Number of unexpected bytes.
        extra: usize,
    },
    /// The input does not have the fixed size of the structure.
    InvalidSize {
        /// Structure being parsed.
        what: &'static str,
        /// Required size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },
    /// A quote version other than 3 or 4.
    UnsupportedQuoteVersion(u16),
    /// An attestation key type other than ECDSA-256-with-P-256.
    UnsupportedAttestationKeyType(u16),
    /// A TEE type other than SGX (e.g. a TDX quote).
    UnsupportedTeeType(u32),
    /// A v4 quote whose outer certification data is not QE report
    /// certification data (type 6), so the QE report cannot be located.
    UnexpectedCertificationDataType {
        /// Type required at this position.
        expected: u16,
        /// Type found.
        actual: u16,
    },
    /// A fixed magic value (e.g. the SIGSTRUCT header) does not match.
    BadMagic {
        /// Field whose magic value is wrong.
        what: &'static str,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                what,
                needed,
                available,
            } => write!(f, "{what} truncated: need {needed} bytes, have {available}"),
            Self::TrailingBytes { what, extra } => {
                write!(f, "{what} followed by {extra} unexpected trailing bytes")
            }
            Self::InvalidSize {
                what,
                expected,
                actual,
            } => write!(f, "{what} must be {expected} bytes, got {actual}"),
            Self::UnsupportedQuoteVersion(v) => write!(f, "unsupported quote version {v}"),
            Self::UnsupportedAttestationKeyType(t) => {
                write!(
                    f,
                    "unsupported attestation key type {t} (expected 2 = ECDSA P-256)"
                )
            }
            Self::UnsupportedTeeType(t) => {
                write!(f, "unsupported TEE type {t:#x} (expected 0 = SGX)")
            }
            Self::UnexpectedCertificationDataType { expected, actual } => write!(
                f,
                "unexpected certification data type {actual} (expected {expected})"
            ),
            Self::BadMagic { what } => write!(f, "{what} has a wrong magic value"),
        }
    }
}

impl core::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn measurement_hex_roundtrip() {
        let hex = "ed92b9ba8521bec3c3b2eacdf67846d275dd655965280028e05bf1a5f318434c";
        let m = Measurement::from_hex(hex).unwrap();
        assert_eq!(m.to_string(), hex);
        assert!(Measurement::from_hex("00").is_err());
    }
}
