//! Binding of the enclave's channel key to its attestation report
//! (`docs/PROTOCOL.md` §6.2).
//!
//! ```text
//! report_data[ 0..32] = SHA-256( "SGXRA-v1/report-data" ‖ 0x00 ‖ version ‖ ek_pub )
//! report_data[32..64] = 0x00 × 32
//! ```
//!
//! # Why SHA-256, zero-padded, rather than SHA-512
//!
//! Both fill `REPORTDATA` with a collision-resistant commitment to `ek_pub`.
//! SHA-256 was chosen because:
//!
//! * Its 128-bit collision resistance matches the 128-bit security level of
//!   X25519 and ChaCha20-Poly1305; SHA-512 adds no meaningful strength to
//!   the channel as a whole.
//! * It is the only hash the protocol uses (transcript, HKDF, HMAC), so the
//!   enclave links one hash implementation.
//! * The upper 32 bytes stay free. The verifier requires them to be zero
//!   today, so a later protocol version can define them (for example a hash
//!   of enclave configuration) without the two versions being confusable.
//!
//! The domain separator, its `0x00` terminator and the version byte make
//! sure a report_data value produced by this protocol cannot be mistaken
//! for one produced by any other use of `REPORTDATA` (such as the
//! blueprint's `SHA-256(64 zero bytes)`), nor by a different protocol
//! version.

use core::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::handshake::{PROTOCOL_VERSION, PUBLIC_KEY_LEN};
use crate::sgx::ReportData;

/// Domain separator for the report_data commitment.
pub const REPORT_DATA_LABEL: &[u8] = b"SGXRA-v1/report-data";

/// The report_data commitment to an enclave channel public key.
pub fn report_data_for(enclave_public: &[u8; PUBLIC_KEY_LEN]) -> ReportData {
    let digest = Sha256::new()
        .chain_update(REPORT_DATA_LABEL)
        .chain_update([0x00, PROTOCOL_VERSION])
        .chain_update(enclave_public)
        .finalize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&digest);
    ReportData(out)
}

/// The attested report_data does not commit to the presented key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingError;

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("enclave public key is not bound to the attested report_data")
    }
}

impl core::error::Error for BindingError {}

/// Checks that `attested` is exactly [`report_data_for`]`(enclave_public)`,
/// including the 32 reserved zero bytes. The comparison is constant-time.
pub fn check_report_data(
    attested: &ReportData,
    enclave_public: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), BindingError> {
    let expected = report_data_for(enclave_public);
    if bool::from(attested.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        Err(BindingError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn known_answer() {
        // SHA-256("SGXRA-v1/report-data" ‖ 00 ‖ 01 ‖ 00×32), computed
        // independently with Python's hashlib.
        let rd = report_data_for(&[0u8; 32]);
        assert_eq!(
            crate::hex::Hex(&rd.0[..32]).to_string(),
            "ed14eda44c14207ae3d3e792d059607861f877d2ea2d6a34eef4826ab44b7861"
        );
        assert_eq!(rd.0[32..], [0u8; 32]);
    }

    #[test]
    fn binding_is_exact() {
        let key = [7u8; 32];
        let rd = report_data_for(&key);
        assert_eq!(check_report_data(&rd, &key), Ok(()));

        let mut other = key;
        other[31] ^= 1;
        assert_eq!(check_report_data(&rd, &other), Err(BindingError));

        // The reserved half must be zero.
        let mut padded = rd;
        padded.0[63] = 1;
        assert_eq!(check_report_data(&padded, &key), Err(BindingError));

        // The blueprint's constant report_data binds nothing.
        let mut blueprint = ReportData::ZERO;
        blueprint.0[..32].copy_from_slice(&Sha256::digest([0u8; 64]));
        assert_eq!(check_report_data(&blueprint, &[0u8; 32]), Err(BindingError));
    }
}
