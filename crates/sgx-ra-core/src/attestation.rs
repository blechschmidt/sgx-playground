//! The reusable attestation interfaces of the framework.
//!
//! * An [`Attester`] runs inside the TEE and produces evidence that binds
//!   64 bytes of caller-chosen [`ReportData`] to the enclave's identity.
//! * A [`Verifier`] runs on the relying party. It checks evidence
//!   cryptographically, evaluates it against a [`Policy`], and only then
//!   returns [`VerifiedClaims`].
//! * A [`Policy`] decides whether verified claims are acceptable.
//!   [`EnclavePolicy`] is the standard policy: an expected MRENCLAVE, optional
//!   MRSIGNER / ISVPRODID / minimum ISVSVN, an allowed set of platform TCB
//!   statuses, and debug enclaves always rejected.
//!
//! The secure channel ([`crate::channel::SecureChannel`]) is built on top:
//! the enclave puts a hash of its channel key into the report data, and the
//! client checks that binding against the verified claims.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::sgx::{Attributes, Measurement, ReportBody, ReportData};

/// Produces attestation evidence inside a TEE.
///
/// For SGX the evidence is a local report targeted at the quoting enclave;
/// the untrusted host turns it into a DCAP quote. Implementations must put
/// `report_data` into the evidence verbatim, since it is what binds keys to
/// the measured code.
pub trait Attester {
    /// The evidence type (e.g. [`crate::sgx::Report`]).
    type Evidence;
    /// Error type.
    type Error: fmt::Debug + fmt::Display;

    /// Produces evidence over the given report data.
    fn attest(&mut self, report_data: &ReportData) -> Result<Self::Evidence, Self::Error>;
}

/// Verifies attestation evidence and evaluates it against a policy.
///
/// Contract: an implementation returns `Ok` only if the evidence is
/// authentic (signature chain to a pinned root of trust, valid collateral)
/// **and** `policy.check` accepted the resulting claims. Policy rejections
/// are reported through `From<PolicyViolation>`.
pub trait Verifier {
    /// Error type; must be able to carry policy rejections.
    type Error: fmt::Debug + fmt::Display + From<PolicyViolation>;

    /// Verifies `evidence` (for SGX: a raw DCAP quote).
    fn verify(&self, evidence: &[u8], policy: &dyn Policy) -> Result<VerifiedClaims, Self::Error>;
}

/// Decides whether cryptographically verified claims are acceptable.
pub trait Policy {
    /// Returns `Ok(())` if the claims are acceptable.
    fn check(&self, claims: &VerifiedClaims) -> Result<(), PolicyViolation>;
}

impl<P: Policy + ?Sized> Policy for &P {
    fn check(&self, claims: &VerifiedClaims) -> Result<(), PolicyViolation> {
        (**self).check(claims)
    }
}

impl<P: Policy + ?Sized> Policy for alloc::boxed::Box<P> {
    fn check(&self, claims: &VerifiedClaims) -> Result<(), PolicyViolation> {
        (**self).check(claims)
    }
}

/// Platform TCB status as reported by Intel's TCB Info for the quoting
/// platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcbStatus {
    /// Fully patched.
    UpToDate,
    /// Patched, but software mitigations are needed (see advisories).
    SwHardeningNeeded,
    /// Patched, but the platform configuration needs changes.
    ConfigurationNeeded,
    /// Both of the above.
    ConfigurationAndSwHardeningNeeded,
    /// Microcode or SVNs are out of date.
    OutOfDate,
    /// Out of date and configuration changes needed.
    OutOfDateConfigurationNeeded,
    /// The platform's keys have been revoked.
    Revoked,
}

impl TcbStatus {
    /// All statuses, in declaration order.
    pub const ALL: [Self; 7] = [
        Self::UpToDate,
        Self::SwHardeningNeeded,
        Self::ConfigurationNeeded,
        Self::ConfigurationAndSwHardeningNeeded,
        Self::OutOfDate,
        Self::OutOfDateConfigurationNeeded,
        Self::Revoked,
    ];

    /// The name used in Intel's TCB Info JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UpToDate => "UpToDate",
            Self::SwHardeningNeeded => "SWHardeningNeeded",
            Self::ConfigurationNeeded => "ConfigurationNeeded",
            Self::ConfigurationAndSwHardeningNeeded => "ConfigurationAndSWHardeningNeeded",
            Self::OutOfDate => "OutOfDate",
            Self::OutOfDateConfigurationNeeded => "OutOfDateConfigurationNeeded",
            Self::Revoked => "Revoked",
        }
    }

    /// Parses the name used in Intel's TCB Info JSON.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == name)
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

impl fmt::Display for TcbStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of [`TcbStatus`] values.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TcbStatusSet(u8);

impl TcbStatusSet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);

    /// The set containing only [`TcbStatus::UpToDate`].
    pub fn up_to_date_only() -> Self {
        Self::EMPTY.with(TcbStatus::UpToDate)
    }

    /// Returns the set with `status` added.
    #[must_use]
    pub fn with(self, status: TcbStatus) -> Self {
        Self(self.0 | status.bit())
    }

    /// Whether `status` is in the set.
    pub fn contains(&self, status: TcbStatus) -> bool {
        self.0 & status.bit() != 0
    }
}

impl fmt::Debug for TcbStatusSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(TcbStatus::ALL.iter().filter(|s| self.contains(**s)))
            .finish()
    }
}

/// The identity fields of an enclave report that policies match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnclaveIdentity {
    /// Code identity.
    pub mr_enclave: Measurement,
    /// Signer identity.
    pub mr_signer: Measurement,
    /// Product id assigned by the signer.
    pub isv_prod_id: u16,
    /// Security version assigned by the signer.
    pub isv_svn: u16,
    /// Enclave attributes (DEBUG, MODE64BIT, …).
    pub attributes: Attributes,
    /// `MISCSELECT`.
    pub misc_select: u32,
}

impl From<&ReportBody> for EnclaveIdentity {
    fn from(body: &ReportBody) -> Self {
        Self {
            mr_enclave: body.mr_enclave(),
            mr_signer: body.mr_signer(),
            isv_prod_id: body.isv_prod_id(),
            isv_svn: body.isv_svn(),
            attributes: body.attributes(),
            misc_select: body.misc_select(),
        }
    }
}

/// What a [`Verifier`] established about the attested enclave.
///
/// A value of this type should only be produced by a verifier after
/// successful cryptographic verification; the fields are private so that
/// holding one is a meaningful signal in API boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaims {
    report_body: ReportBody,
    tcb_status: TcbStatus,
    advisory_ids: Vec<String>,
}

impl VerifiedClaims {
    /// Creates claims. To be called by [`Verifier`] implementations once the
    /// evidence carrying `report_body` has been authenticated.
    pub fn new(report_body: ReportBody, tcb_status: TcbStatus, advisory_ids: Vec<String>) -> Self {
        Self {
            report_body,
            tcb_status,
            advisory_ids,
        }
    }

    /// The authenticated enclave report body (hashed into the channel
    /// transcript).
    pub fn report_body(&self) -> &ReportBody {
        &self.report_body
    }

    /// The enclave identity.
    pub fn identity(&self) -> EnclaveIdentity {
        EnclaveIdentity::from(&self.report_body)
    }

    /// The 64 bytes the enclave bound into its report.
    pub fn report_data(&self) -> ReportData {
        self.report_body.report_data()
    }

    /// The platform's TCB status.
    pub fn tcb_status(&self) -> TcbStatus {
        self.tcb_status
    }

    /// Intel security advisories (`INTEL-SA-…`) applicable to the platform.
    pub fn advisory_ids(&self) -> &[String] {
        &self.advisory_ids
    }
}

/// Reasons a [`Policy`] rejects claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyViolation {
    /// The enclave runs in debug mode; its memory is not confidential.
    DebugEnclave,
    /// The enclave is not a 64-bit enclave.
    NotMode64Bit,
    /// MRENCLAVE differs from the expected (reproducibly built) value.
    MrEnclaveMismatch {
        /// Expected value.
        expected: Measurement,
        /// Attested value.
        actual: Measurement,
    },
    /// MRSIGNER differs from the expected value.
    MrSignerMismatch {
        /// Expected value.
        expected: Measurement,
        /// Attested value.
        actual: Measurement,
    },
    /// ISVPRODID differs from the expected value.
    IsvProdIdMismatch {
        /// Expected value.
        expected: u16,
        /// Attested value.
        actual: u16,
    },
    /// ISVSVN is below the required minimum.
    IsvSvnTooLow {
        /// Required minimum.
        minimum: u16,
        /// Attested value.
        actual: u16,
    },
    /// The platform's TCB status is not in the allowed set.
    TcbStatusNotAllowed(TcbStatus),
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DebugEnclave => f.write_str("enclave runs in debug mode"),
            Self::NotMode64Bit => f.write_str("enclave is not a 64-bit enclave"),
            Self::MrEnclaveMismatch { expected, actual } => {
                write!(f, "MRENCLAVE mismatch: expected {expected}, got {actual}")
            }
            Self::MrSignerMismatch { expected, actual } => {
                write!(f, "MRSIGNER mismatch: expected {expected}, got {actual}")
            }
            Self::IsvProdIdMismatch { expected, actual } => {
                write!(f, "ISVPRODID mismatch: expected {expected}, got {actual}")
            }
            Self::IsvSvnTooLow { minimum, actual } => {
                write!(f, "ISVSVN {actual} is below the required minimum {minimum}")
            }
            Self::TcbStatusNotAllowed(s) => write!(f, "platform TCB status {s} is not allowed"),
        }
    }
}

impl core::error::Error for PolicyViolation {}

/// The standard enclave policy.
///
/// Debug enclaves are always rejected and the enclave must be 64-bit; there
/// is deliberately no switch to relax this. By default only the
/// `UpToDate` TCB status is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclavePolicy {
    mr_enclave: Measurement,
    mr_signer: Option<Measurement>,
    isv_prod_id: Option<u16>,
    min_isv_svn: Option<u16>,
    allowed_tcb_statuses: TcbStatusSet,
}

impl EnclavePolicy {
    /// A policy accepting exactly the enclave with this MRENCLAVE.
    pub fn new(mr_enclave: Measurement) -> Self {
        Self {
            mr_enclave,
            mr_signer: None,
            isv_prod_id: None,
            min_isv_svn: None,
            allowed_tcb_statuses: TcbStatusSet::up_to_date_only(),
        }
    }

    /// Additionally requires this MRSIGNER.
    #[must_use]
    pub fn with_mr_signer(mut self, mr_signer: Measurement) -> Self {
        self.mr_signer = Some(mr_signer);
        self
    }

    /// Additionally requires this ISVPRODID.
    #[must_use]
    pub fn with_isv_prod_id(mut self, isv_prod_id: u16) -> Self {
        self.isv_prod_id = Some(isv_prod_id);
        self
    }

    /// Additionally requires ISVSVN ≥ `min_isv_svn`.
    #[must_use]
    pub fn with_min_isv_svn(mut self, min_isv_svn: u16) -> Self {
        self.min_isv_svn = Some(min_isv_svn);
        self
    }

    /// Also accepts platforms with the given TCB status.
    #[must_use]
    pub fn allow_tcb_status(mut self, status: TcbStatus) -> Self {
        self.allowed_tcb_statuses = self.allowed_tcb_statuses.with(status);
        self
    }

    /// The expected MRENCLAVE.
    pub fn mr_enclave(&self) -> Measurement {
        self.mr_enclave
    }

    /// The expected MRSIGNER, if any.
    pub fn mr_signer(&self) -> Option<Measurement> {
        self.mr_signer
    }

    /// The expected ISVPRODID, if any.
    pub fn isv_prod_id(&self) -> Option<u16> {
        self.isv_prod_id
    }

    /// The minimum ISVSVN, if any.
    pub fn min_isv_svn(&self) -> Option<u16> {
        self.min_isv_svn
    }

    /// The accepted TCB statuses.
    pub fn allowed_tcb_statuses(&self) -> TcbStatusSet {
        self.allowed_tcb_statuses
    }
}

/// The checks every acceptable enclave passes, whatever the [`Policy`]:
/// the DEBUG attribute is clear (otherwise the host can read and modify
/// enclave memory, so nothing the enclave holds is confidential) and the
/// enclave runs in 64-bit mode.
///
/// [`EnclavePolicy`] starts with this check, and verifiers call it before
/// any caller-supplied policy, so a custom [`Policy`] cannot accidentally
/// admit a debug enclave (`docs/THREAT_MODEL.md`).
pub fn check_baseline(claims: &VerifiedClaims) -> Result<(), PolicyViolation> {
    let attributes = claims.report_body().attributes();
    if attributes.is_debug() {
        return Err(PolicyViolation::DebugEnclave);
    }
    if !attributes.is_mode64bit() {
        return Err(PolicyViolation::NotMode64Bit);
    }
    Ok(())
}

impl Policy for EnclavePolicy {
    fn check(&self, claims: &VerifiedClaims) -> Result<(), PolicyViolation> {
        check_baseline(claims)?;
        let id = claims.identity();
        if id.mr_enclave != self.mr_enclave {
            return Err(PolicyViolation::MrEnclaveMismatch {
                expected: self.mr_enclave,
                actual: id.mr_enclave,
            });
        }
        if let Some(expected) = self.mr_signer
            && id.mr_signer != expected
        {
            return Err(PolicyViolation::MrSignerMismatch {
                expected,
                actual: id.mr_signer,
            });
        }
        if let Some(expected) = self.isv_prod_id
            && id.isv_prod_id != expected
        {
            return Err(PolicyViolation::IsvProdIdMismatch {
                expected,
                actual: id.isv_prod_id,
            });
        }
        if let Some(minimum) = self.min_isv_svn
            && id.isv_svn < minimum
        {
            return Err(PolicyViolation::IsvSvnTooLow {
                minimum,
                actual: id.isv_svn,
            });
        }
        if !self.allowed_tcb_statuses.contains(claims.tcb_status()) {
            return Err(PolicyViolation::TcbStatusNotAllowed(claims.tcb_status()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sgx::Quote;
    use alloc::boxed::Box;

    const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");

    fn fixture_claims(status: TcbStatus) -> VerifiedClaims {
        // Test-only: treat the parsed fixture as if it had been verified.
        let quote = Quote::parse(QUOTE_V3).unwrap();
        VerifiedClaims::new(*quote.report_body(), status, Vec::new())
    }

    fn fixture_policy() -> EnclavePolicy {
        let body = *Quote::parse(QUOTE_V3).unwrap().report_body();
        EnclavePolicy::new(body.mr_enclave())
    }

    #[test]
    fn accepts_matching_enclave() {
        let claims = fixture_claims(TcbStatus::UpToDate);
        let body = claims.report_body();
        let policy = fixture_policy()
            .with_mr_signer(body.mr_signer())
            .with_isv_prod_id(1)
            .with_min_isv_svn(10);
        assert_eq!(policy.check(&claims), Ok(()));
        // Through the blanket impls / trait objects.
        let dyn_policy: Box<dyn Policy> = Box::new(policy.clone());
        assert_eq!(dyn_policy.check(&claims), Ok(()));
        fn check_generic<P: Policy>(
            policy: P,
            claims: &VerifiedClaims,
        ) -> Result<(), PolicyViolation> {
            policy.check(claims)
        }
        assert_eq!(check_generic(&policy, &claims), Ok(()));
    }

    #[test]
    fn rejects_each_mismatch() {
        let claims = fixture_claims(TcbStatus::UpToDate);
        let other = Measurement([0x11; 32]);
        let actual = claims.identity();

        assert_eq!(
            EnclavePolicy::new(other).check(&claims),
            Err(PolicyViolation::MrEnclaveMismatch {
                expected: other,
                actual: actual.mr_enclave
            })
        );
        assert_eq!(
            fixture_policy().with_mr_signer(other).check(&claims),
            Err(PolicyViolation::MrSignerMismatch {
                expected: other,
                actual: actual.mr_signer
            })
        );
        assert_eq!(
            fixture_policy().with_isv_prod_id(2).check(&claims),
            Err(PolicyViolation::IsvProdIdMismatch {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            fixture_policy().with_min_isv_svn(11).check(&claims),
            Err(PolicyViolation::IsvSvnTooLow {
                minimum: 11,
                actual: 10
            })
        );
    }

    #[test]
    fn tcb_status_policy() {
        let claims = fixture_claims(TcbStatus::SwHardeningNeeded);
        assert_eq!(
            fixture_policy().check(&claims),
            Err(PolicyViolation::TcbStatusNotAllowed(
                TcbStatus::SwHardeningNeeded
            ))
        );
        assert_eq!(
            fixture_policy()
                .allow_tcb_status(TcbStatus::SwHardeningNeeded)
                .check(&claims),
            Ok(())
        );
        for s in TcbStatus::ALL {
            assert_eq!(TcbStatus::from_name(s.as_str()), Some(s));
        }
        assert_eq!(
            TcbStatus::from_name("SWHardeningNeeded"),
            Some(TcbStatus::SwHardeningNeeded)
        );
        assert_eq!(TcbStatus::from_name("bogus"), None);
    }

    #[test]
    fn debug_and_mode32_are_always_rejected() {
        let mut raw = *Quote::parse(QUOTE_V3).unwrap().report_body().as_bytes();
        raw[48] |= Attributes::FLAG_DEBUG as u8;
        let debug =
            VerifiedClaims::new(ReportBody::from_array(raw), TcbStatus::UpToDate, Vec::new());
        assert_eq!(
            fixture_policy().check(&debug),
            Err(PolicyViolation::DebugEnclave)
        );

        let mut raw = *Quote::parse(QUOTE_V3).unwrap().report_body().as_bytes();
        raw[48] &= !(Attributes::FLAG_MODE64BIT as u8);
        let m32 = VerifiedClaims::new(ReportBody::from_array(raw), TcbStatus::UpToDate, Vec::new());
        assert_eq!(
            fixture_policy().check(&m32),
            Err(PolicyViolation::NotMode64Bit)
        );
    }
}
