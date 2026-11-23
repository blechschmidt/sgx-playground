//! The verifier's error type.

use std::fmt;

use sgx_ra_core::PolicyViolation;
use sgx_ra_core::hex::Hex;
use sgx_ra_core::sgx::ParseError;
use sgx_ra_core::sgx::quote::CERT_DATA_PCK_CERT_CHAIN;

/// Verification failures.
///
/// Every variant means "do not trust this enclave". The variants exist for
/// diagnostics only; callers must not treat any of them as recoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The quote is malformed.
    Parse(ParseError),
    /// The quote was produced by a non-Intel quoting enclave.
    UntrustedQeVendor([u8; 16]),
    /// The quote does not embed a PCK certificate chain.
    UnsupportedCertificationData(u16),
    /// A certificate or certificate chain is malformed or does not chain as
    /// required (`what` names the chain or certificate).
    Certificate {
        /// The certificate or chain concerned.
        what: &'static str,
        /// Details.
        reason: String,
    },
    /// The chain does not end at the pinned Intel SGX Root CA.
    UntrustedRoot {
        /// The chain concerned.
        what: &'static str,
    },
    /// A certificate, CRL or collateral document is outside its validity
    /// period at verification time.
    Expired {
        /// The object concerned.
        what: &'static str,
        /// Start of the validity period (Unix seconds).
        not_before: i64,
        /// End of the validity period (Unix seconds), grace included.
        not_after: i64,
        /// Verification time (Unix seconds).
        now: i64,
    },
    /// A certificate in the chain is listed on its issuer's CRL.
    Revoked {
        /// The certificate concerned.
        what: &'static str,
        /// Its serial number (hex).
        serial: String,
    },
    /// A CRL is malformed or not issued by the expected CA.
    Crl {
        /// The CRL concerned.
        what: &'static str,
        /// Details.
        reason: String,
    },
    /// An ECDSA signature does not verify.
    BadSignature {
        /// The signed object.
        what: &'static str,
    },
    /// The QE report does not commit to the attestation key and QE
    /// authentication data.
    QeReportDataMismatch,
    /// A collateral document (TCB Info, QE Identity) is malformed or does
    /// not belong to this platform.
    Collateral {
        /// The document concerned.
        what: &'static str,
        /// Details.
        reason: String,
    },
    /// The quoting enclave does not match the signed QE Identity.
    QeIdentityMismatch {
        /// The mismatching field.
        field: &'static str,
    },
    /// No TCB level of the signed TCB Info / QE Identity covers the
    /// platform's (or QE's) security versions.
    TcbLevelNotFound {
        /// `"platform"` or `"quoting enclave"`.
        what: &'static str,
    },
    /// Intel has revoked the platform's or the quoting enclave's TCB. This
    /// is never acceptable, independent of the policy.
    TcbRevoked,
    /// Collateral could not be obtained (network, PCCS error, …).
    CollateralUnavailable(String),
    /// The verified claims were rejected by the policy.
    Policy(PolicyViolation),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "malformed quote: {e}"),
            Self::UntrustedQeVendor(id) => {
                write!(f, "quoting enclave vendor {} is not Intel", Hex(id))
            }
            Self::UnsupportedCertificationData(t) => write!(
                f,
                "certification data type {t} is not a PCK certificate chain ({CERT_DATA_PCK_CERT_CHAIN})"
            ),
            Self::Certificate { what, reason } => write!(f, "{what}: {reason}"),
            Self::UntrustedRoot { what } => {
                write!(f, "{what} does not end at the pinned Intel SGX Root CA")
            }
            Self::Expired {
                what,
                not_before,
                not_after,
                now,
            } => write!(
                f,
                "{what} is not valid at {now} (valid from {not_before} to {not_after}, Unix time)"
            ),
            Self::Revoked { what, serial } => write!(f, "{what} (serial {serial}) is revoked"),
            Self::Crl { what, reason } => write!(f, "{what}: {reason}"),
            Self::BadSignature { what } => write!(f, "invalid signature on {what}"),
            Self::QeReportDataMismatch => f.write_str(
                "QE report data does not equal SHA-256(attestation key || QE auth data)",
            ),
            Self::Collateral { what, reason } => write!(f, "{what}: {reason}"),
            Self::QeIdentityMismatch { field } => {
                write!(f, "quoting enclave does not match QE Identity ({field})")
            }
            Self::TcbLevelNotFound { what } => {
                write!(f, "no TCB level matches the {what}")
            }
            Self::TcbRevoked => f.write_str("Intel has revoked the platform TCB"),
            Self::CollateralUnavailable(e) => write!(f, "cannot obtain collateral: {e}"),
            Self::Policy(v) => write!(f, "policy rejected the enclave: {v}"),
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::Policy(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ParseError> for VerifyError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<PolicyViolation> for VerifyError {
    fn from(v: PolicyViolation) -> Self {
        Self::Policy(v)
    }
}

pub(crate) fn cert_err(what: &'static str, reason: impl Into<String>) -> VerifyError {
    VerifyError::Certificate {
        what,
        reason: reason.into(),
    }
}

pub(crate) fn crl_err(what: &'static str, reason: impl Into<String>) -> VerifyError {
    VerifyError::Crl {
        what,
        reason: reason.into(),
    }
}

pub(crate) fn collateral_err(what: &'static str, reason: impl Into<String>) -> VerifyError {
    VerifyError::Collateral {
        what,
        reason: reason.into(),
    }
}
