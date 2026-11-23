//! DCAP quote verification for the `sgx-ra` framework.
//!
//! [`DcapVerifier`] implements [`sgx_ra_core::Verifier`] for Intel SGX DCAP
//! ECDSA quotes (`docs/PROTOCOL.md` §6.6):
//!
//! 1. strict quote parsing; Intel QE vendor; PCK chain as certification
//!    data (type 5);
//! 2. PCK chain → **pinned** Intel SGX Root CA ([`INTEL_SGX_ROOT_CA_DER`]),
//!    validity periods, basic constraints / key usage, Root CA CRL and PCK
//!    CRL (both signature-checked and current), leaf *and* intermediate
//!    revocation;
//! 3. TCB Info and QE Identity signatures under the Intel SGX TCB Signing
//!    certificate (which must chain to the pinned root and not be revoked),
//!    freshness (`nextUpdate`, optional grace), FMSPC / PCE-ID match;
//! 4. QE report signature under the PCK key, QE report vs. QE Identity
//!    (MRSIGNER, ISVPRODID, masked MISCSELECT / attributes, TCB level), and
//!    `qe_report.report_data == SHA-256(attestation key ‖ QE auth data) ‖ 0³²`;
//! 5. quote signature (header ‖ enclave report body) under the attestation
//!    key;
//! 6. TCB level evaluation and QE/platform status convergence; `Revoked`
//!    is always rejected;
//!
//! and finally applies the caller's [`sgx_ra_core::Policy`] (normally
//! [`sgx_ra_core::EnclavePolicy`]: no DEBUG, expected MRENCLAVE, optional
//! MRSIGNER / ISVPRODID / minimum ISVSVN, allowed TCB statuses).
//!
//! Collateral comes from a [`CollateralSource`]; this crate does no I/O.
//! The PCCS / Intel PCS client lives in `sgx-ra-client`.
//!
//! Security decisions:
//!
//! * The only trust anchor is the compiled-in Intel SGX Root CA. Roots
//!   delivered in the quote or in issuer-chain headers must be byte-equal
//!   to it; collateral servers are untrusted.
//! * Only ECDSA P-256 / SHA-256 is accepted anywhere in the chain.
//! * Certificates get no expiry grace. Collateral (CRLs, TCB Info, QE
//!   Identity) gets none by default; [`VerifierOptions::collateral_grace`]
//!   can relax that explicitly. Up to [`pki::CLOCK_SKEW_SECS`] of clock
//!   skew is tolerated for *not-yet-valid* checks only.
//! * The report_data ↔ channel key binding is checked by the handshake
//!   (`sgx_ra_core::binding`), against the [`VerifiedClaims`] this verifier
//!   returns.
//!
//! [`VerifiedClaims`]: sgx_ra_core::VerifiedClaims

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod collateral;
mod error;
pub mod pck;
pub mod pki;
pub mod tcb;
mod verify;

#[cfg(test)]
mod tests_dcap;

use sgx_ra_core::sgx::quote::{CERT_DATA_PCK_CERT_CHAIN, INTEL_QE_VENDOR_ID, Quote};

pub use collateral::{
    Collateral, CollateralRequest, CollateralSource, PckCa, SourceError, StaticCollateral,
};
pub use error::VerifyError;
pub use pki::{INTEL_SGX_ROOT_CA_DER, INTEL_SGX_ROOT_CA_SHA256};
pub use tcb::{TcbGap, TcbShortfall};
pub use verify::{DcapVerifier, VerifiedQuote, VerifierOptions, collateral_request, verify_quote};

/// Parses `raw` and applies the structural checks of `docs/PROTOCOL.md`
/// §6.6 step 1 that go beyond well-formedness: Intel QE vendor id and an
/// embedded PCK certificate chain.
///
/// Passing this check says nothing about authenticity.
pub fn parse_and_check_structure(raw: &[u8]) -> Result<Quote<'_>, VerifyError> {
    let quote = Quote::parse(raw)?;
    if quote.header().qe_vendor_id != INTEL_QE_VENDOR_ID {
        return Err(VerifyError::UntrustedQeVendor(quote.header().qe_vendor_id));
    }
    let cert_type = quote.signature().certification.cert_type;
    if cert_type != CERT_DATA_PCK_CERT_CHAIN {
        return Err(VerifyError::UnsupportedCertificationData(cert_type));
    }
    Ok(quote)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");

    #[test]
    fn fixture_passes_structural_checks() {
        let quote = parse_and_check_structure(QUOTE_V3).unwrap();
        assert_eq!(quote.header().version, 3);
    }

    #[test]
    fn rejects_foreign_qe_vendor() {
        let mut q = QUOTE_V3.to_vec();
        q[12] ^= 0xff;
        assert!(matches!(
            parse_and_check_structure(&q),
            Err(VerifyError::UntrustedQeVendor(_))
        ));
    }

    #[test]
    fn rejects_non_pck_chain_certification_data() {
        let mut q = QUOTE_V3.to_vec();
        // cert_type sits right before the 4-byte length of the 3682-byte chain.
        let off = q.len() - 3682 - 6;
        q[off..off + 2].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            parse_and_check_structure(&q),
            Err(VerifyError::UnsupportedCertificationData(3))
        );
    }
}
