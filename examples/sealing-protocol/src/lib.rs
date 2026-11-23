//! Application messages of the sealing example, shared by
//! `sealing-enclave` and `sealing-client`. They travel as plaintext of the
//! attested channel's records (at most `MAX_RECORD_PLAINTEXT` bytes).
//!
//! | request | response |
//! |---------|----------|
//! | `01 ‖ chal_pub[32]` (identity) | `01 ‖ IdentityAssertion` (67 bytes) |
//! | `02 ‖ data` (seal)              | `02 ‖ blob` sealed to MRENCLAVE |
//! | `03 ‖ blob` (unseal)            | `03 ‖ data` |
//!
//! Any request can instead be answered with `7f ‖ code` ([`ErrorCode`]);
//! the session stays open. Only facts the client may learn are reported:
//! the code says *that* an operation failed, never anything derived from
//! secret data.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use sgx_ra_core::handshake::{MAX_RECORD_PLAINTEXT, PUBLIC_KEY_LEN};
use sgx_ra_core::identity::{IDENTITY_ASSERTION_LEN, IdentityAssertion};

/// Request/response tag: long-term identity.
pub const IDENTITY: u8 = 0x01;
/// Request/response tag: seal client data.
pub const SEAL: u8 = 0x02;
/// Request/response tag: unseal client data.
pub const UNSEAL: u8 = 0x03;
/// Response tag: error.
pub const ERROR: u8 = 0x7f;

/// Additional data bound into every client-data blob, so that blobs of
/// other purposes (such as the sealed identity key) are never returned by
/// UNSEAL.
pub const CLIENT_DATA_AAD: &[u8] = b"sealing-enclave/v1/client-data";

/// `sizeof(sgx_sealed_data_t)`.
const SEALED_HEADER_LEN: usize = 560;

/// Largest input of a SEAL request whose blob still fits in one response.
pub const MAX_SEAL_INPUT: usize =
    MAX_RECORD_PLAINTEXT - 1 - SEALED_HEADER_LEN - CLIENT_DATA_AAD.len();

/// Why a request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// Unknown tag or wrong length.
    BadRequest = 1,
    /// The long-term identity could not be established (e.g. a stored blob
    /// that does not open on this enclave: fail closed).
    IdentityUnavailable = 2,
    /// Sealing failed, or the input exceeds [`MAX_SEAL_INPUT`].
    SealFailed = 3,
    /// The blob did not open in this enclave (other enclave, other CPU,
    /// tampered, or not a client-data blob).
    UnsealFailed = 4,
}

impl ErrorCode {
    /// Decodes a code byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::BadRequest,
            2 => Self::IdentityUnavailable,
            3 => Self::SealFailed,
            4 => Self::UnsealFailed,
            _ => return None,
        })
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadRequest => "bad request",
            Self::IdentityUnavailable => "long-term identity unavailable",
            Self::SealFailed => "sealing failed",
            Self::UnsealFailed => "blob does not unseal in this enclave",
        })
    }
}

/// A decoded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request<'a> {
    /// Prove the long-term identity against this challenge key.
    Identity([u8; PUBLIC_KEY_LEN]),
    /// Seal these bytes.
    Seal(&'a [u8]),
    /// Unseal this blob.
    Unseal(&'a [u8]),
}

impl<'a> Request<'a> {
    /// Decodes a request.
    pub fn decode(buf: &'a [u8]) -> Result<Self, ErrorCode> {
        match buf.split_first() {
            Some((&IDENTITY, rest)) => rest
                .try_into()
                .map(Self::Identity)
                .map_err(|_| ErrorCode::BadRequest),
            Some((&SEAL, rest)) if !rest.is_empty() => Ok(Self::Seal(rest)),
            Some((&UNSEAL, rest)) if !rest.is_empty() => Ok(Self::Unseal(rest)),
            _ => Err(ErrorCode::BadRequest),
        }
    }

    /// Encodes the request.
    pub fn encode(&self) -> Vec<u8> {
        let (tag, body): (u8, &[u8]) = match self {
            Self::Identity(challenge) => (IDENTITY, challenge),
            Self::Seal(data) => (SEAL, data),
            Self::Unseal(blob) => (UNSEAL, blob),
        };
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(tag);
        out.extend_from_slice(body);
        out
    }
}

/// A decoded response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The identity assertion.
    Identity(IdentityAssertion),
    /// A sealed blob.
    Sealed(Vec<u8>),
    /// Unsealed data.
    Unsealed(Vec<u8>),
    /// The request failed.
    Error(ErrorCode),
}

/// The response did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedResponse;

impl fmt::Display for MalformedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed response from the sealing enclave")
    }
}

impl core::error::Error for MalformedResponse {}

impl Response {
    /// Appends the encoded response to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Identity(a) => {
                out.push(IDENTITY);
                out.extend_from_slice(&a.encode());
            }
            Self::Sealed(blob) => {
                out.push(SEAL);
                out.extend_from_slice(blob);
            }
            Self::Unsealed(data) => {
                out.push(UNSEAL);
                out.extend_from_slice(data);
            }
            Self::Error(code) => out.extend_from_slice(&[ERROR, *code as u8]),
        }
    }

    /// Decodes a response.
    pub fn decode(buf: &[u8]) -> Result<Self, MalformedResponse> {
        match buf.split_first() {
            Some((&IDENTITY, rest)) if rest.len() == IDENTITY_ASSERTION_LEN => {
                IdentityAssertion::decode(rest)
                    .map(Self::Identity)
                    .map_err(|_| MalformedResponse)
            }
            Some((&SEAL, rest)) if !rest.is_empty() => Ok(Self::Sealed(rest.to_vec())),
            Some((&UNSEAL, rest)) if !rest.is_empty() => Ok(Self::Unsealed(rest.to_vec())),
            Some((&ERROR, [code])) => ErrorCode::from_byte(*code)
                .map(Self::Error)
                .ok_or(MalformedResponse),
            _ => Err(MalformedResponse),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;
    use sgx_ra_core::identity::IdentityOrigin;
    use sgx_ra_core::storage::KeyPolicy;

    #[test]
    fn requests_roundtrip() {
        for r in [
            Request::Identity([4; 32]),
            Request::Seal(b"data"),
            Request::Unseal(b"blob"),
        ] {
            assert_eq!(Request::decode(&r.encode()).unwrap(), r);
        }
        for bad in [
            &[][..],
            &[IDENTITY; 32],
            &[IDENTITY; 34],
            &[SEAL],
            &[UNSEAL],
            &[9, 9],
        ] {
            assert_eq!(Request::decode(bad), Err(ErrorCode::BadRequest));
        }
    }

    #[test]
    fn responses_roundtrip() {
        let assertion = IdentityAssertion {
            origin: IdentityOrigin::Restored,
            policy: KeyPolicy::MrEnclave,
            public_key: [1; 32],
            proof: [2; 32],
        };
        for r in [
            Response::Identity(assertion),
            Response::Sealed(vec![1, 2]),
            Response::Unsealed(vec![3]),
            Response::Error(ErrorCode::UnsealFailed),
        ] {
            let mut out = Vec::new();
            r.encode_into(&mut out);
            assert_eq!(Response::decode(&out).unwrap(), r);
        }
        for bad in [
            &[][..],
            &[ERROR],
            &[ERROR, 0],
            &[ERROR, 1, 1],
            &[IDENTITY, 1],
            &[SEAL],
        ] {
            assert_eq!(Response::decode(bad), Err(MalformedResponse));
        }
    }

    #[test]
    fn largest_seal_fits_one_record() {
        assert_eq!(
            1 + SEALED_HEADER_LEN + CLIENT_DATA_AAD.len() + MAX_SEAL_INPUT,
            MAX_RECORD_PLAINTEXT
        );
        // ... and its request fits too.
        const { assert!(MAX_SEAL_INPUT < MAX_RECORD_PLAINTEXT) };
    }
}
