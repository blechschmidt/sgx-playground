//! DCAP ECDSA quote verification (`docs/PROTOCOL.md` §6.6 steps 1–6).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sgx_ra_core::attestation::{Policy, TcbStatus, VerifiedClaims, Verifier, check_baseline};
use sgx_ra_core::sgx::Quote;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::collateral::{Collateral, CollateralRequest, CollateralSource, PckCa};
use crate::error::{VerifyError, cert_err, collateral_err};
use crate::parse_and_check_structure;
use crate::pck::PckExtensions;
use crate::pki::{self, Cert, Role, TrustAnchor};
use crate::tcb::{QeIdentity, TcbInfo, converge_tcb_status, verify_tcb_signer};

/// Verification options.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifierOptions {
    /// How long past `nextUpdate` CRLs, TCB Info and QE Identity are still
    /// accepted. Default: zero (no grace). Certificates never get grace.
    pub collateral_grace: Duration,
    /// Fixed verification time (Unix seconds) instead of the system clock,
    /// e.g. to re-verify recorded evidence as of the time it was received.
    pub fixed_time: Option<i64>,
}

impl VerifierOptions {
    fn now(&self) -> i64 {
        self.fixed_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        })
    }

    fn grace_secs(&self) -> i64 {
        i64::try_from(self.collateral_grace.as_secs()).unwrap_or(i64::MAX)
    }
}

/// Everything established while verifying a quote. The [`VerifiedClaims`]
/// are what policies and the secure channel consume; the rest is for
/// logging and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    /// The authenticated enclave report and the converged TCB status.
    pub claims: VerifiedClaims,
    /// The platform's PCK certificate fields.
    pub pck: PckExtensions,
    /// Which PCK CA issued the PCK certificate.
    pub pck_ca: PckCa,
    /// TCB status of the platform alone (from TCB Info).
    pub platform_tcb_status: TcbStatus,
    /// TCB date of the matched platform TCB level.
    pub platform_tcb_date: String,
    /// TCB status of the quoting enclave alone (from QE Identity).
    pub qe_tcb_status: TcbStatus,
    /// TCB evaluation data number of the TCB Info used.
    pub tcb_evaluation_data_number: u32,
    /// Earliest `nextUpdate` of the collateral used (Unix seconds).
    pub collateral_expiry: i64,
}

/// Determines which collateral a quote needs: parses the quote and its PCK
/// leaf certificate (no signature checks yet).
pub fn collateral_request(raw_quote: &[u8]) -> Result<CollateralRequest, VerifyError> {
    let quote = parse_and_check_structure(raw_quote)?;
    let chain = PckChain::parse(quote.signature().certification.data)?;
    let leaf = Cert::parse(&chain.leaf, "PCK certificate")?;
    let intermediate = Cert::parse(&chain.intermediate, "PCK CA certificate")?;
    Ok(CollateralRequest {
        fmspc: PckExtensions::from_cert(&leaf)?.fmspc,
        pck_ca: pck_ca_of(&intermediate)?,
    })
}

/// Verifies a DCAP quote against `collateral` with the pinned Intel SGX
/// Root CA. Policy is **not** applied; see [`DcapVerifier`] for that.
pub fn verify_quote(
    raw_quote: &[u8],
    collateral: &Collateral,
    options: &VerifierOptions,
) -> Result<VerifiedQuote, VerifyError> {
    verify_quote_with_anchor(raw_quote, collateral, options, &TrustAnchor::intel())
}

/// The DER certificates of a quote's PCK chain.
struct PckChain {
    leaf: Vec<u8>,
    intermediate: Vec<u8>,
    root: Vec<u8>,
}

impl PckChain {
    fn parse(cert_data: &[u8]) -> Result<Self, VerifyError> {
        const WHAT: &str = "PCK certificate chain";
        let ders = pki::pem_certificates(cert_data, WHAT)?;
        let Ok([leaf, intermediate, root]) = <[Vec<u8>; 3]>::try_from(ders) else {
            return Err(cert_err(WHAT, "expected exactly 3 certificates"));
        };
        Ok(Self {
            leaf,
            intermediate,
            root,
        })
    }
}

fn pck_ca_of(intermediate: &Cert<'_>) -> Result<PckCa, VerifyError> {
    intermediate
        .common_name()
        .and_then(PckCa::from_common_name)
        .ok_or_else(|| cert_err("PCK CA certificate", "not an Intel SGX PCK CA"))
}

pub(crate) fn verify_quote_with_anchor(
    raw_quote: &[u8],
    collateral: &Collateral,
    options: &VerifierOptions,
    anchor: &TrustAnchor,
) -> Result<VerifiedQuote, VerifyError> {
    let now = options.now();
    let grace = options.grace_secs();

    // 1. Structure.
    let quote: Quote<'_> = parse_and_check_structure(raw_quote)?;
    let sig = quote.signature();

    // 2. PCK chain up to the pinned root, and revocation.
    let root = anchor.cert(now)?;
    let chain = PckChain::parse(sig.certification.data)?;
    anchor.require_pinned(&chain.root, "PCK certificate chain")?;

    const INTERMEDIATE: &str = "PCK CA certificate";
    let intermediate = Cert::parse(&chain.intermediate, INTERMEDIATE)?;
    intermediate.check_issued_by(&root, INTERMEDIATE)?;
    intermediate.check_validity(now, INTERMEDIATE)?;
    intermediate.check_role(Role::Ca { crl_signer: true }, INTERMEDIATE)?;
    let pck_ca = pck_ca_of(&intermediate)?;

    const LEAF: &str = "PCK certificate";
    let leaf = Cert::parse(&chain.leaf, LEAF)?;
    leaf.check_issued_by(&intermediate, LEAF)?;
    leaf.check_validity(now, LEAF)?;
    leaf.check_role(Role::EndEntity, LEAF)?;
    let pck = PckExtensions::from_cert(&leaf)?;

    let root_crl_der = pki::crl_to_der(&collateral.root_ca_crl)?;
    let root_crl = pki::verify_crl(&root_crl_der, &root, now, grace, "Root CA CRL")?;
    root_crl.check(&intermediate, INTERMEDIATE)?;

    let pck_crl_der = pki::crl_to_der(&collateral.pck_crl)?;
    let pck_crl = pki::verify_crl(&pck_crl_der, &intermediate, now, grace, "PCK CRL")?;
    pck_crl.check(&leaf, LEAF)?;

    // 4. QE report: signed by the PCK key and committing to the
    //    attestation key.
    let pck_key = leaf.p256_key(LEAF)?;
    pki::verify_raw_signature(
        &pck_key,
        sig.qe_report.as_bytes(),
        &sig.qe_report_signature,
        "QE report",
    )?;
    let mut expected_qe_rd = [0u8; 64];
    expected_qe_rd[..32].copy_from_slice(
        &Sha256::new()
            .chain_update(sig.attestation_key)
            .chain_update(sig.qe_auth_data)
            .finalize(),
    );
    let qe_rd = sig.qe_report.report_data();
    if !bool::from(qe_rd.as_bytes().ct_eq(&expected_qe_rd)) {
        return Err(VerifyError::QeReportDataMismatch);
    }

    // 5. Quote signature over header ‖ report body.
    let att_key = pki::raw_p256_key(&sig.attestation_key, "attestation key")?;
    pki::verify_raw_signature(&att_key, quote.signed_bytes(), &sig.signature, "quote")?;

    // 3. TCB Info and QE Identity, signed by the TCB signing certificate.
    let tcb_signer = verify_tcb_signer(
        &collateral.tcb_info_issuer_chain,
        anchor,
        &root,
        &root_crl,
        now,
        "TCB Info issuer chain",
    )?;
    let tcb_info = TcbInfo::verify_and_parse(&collateral.tcb_info, &tcb_signer)?;
    pki::check_window(
        "TCB Info",
        tcb_info.issue_date,
        tcb_info.next_update,
        now,
        grace,
    )?;
    if tcb_info.fmspc != pck.fmspc {
        return Err(collateral_err(
            "TCB Info",
            "FMSPC does not match the PCK certificate",
        ));
    }
    if tcb_info.pce_id != pck.pce_id {
        return Err(collateral_err(
            "TCB Info",
            "PCE-ID does not match the PCK certificate",
        ));
    }

    let qe_signer = verify_tcb_signer(
        &collateral.qe_identity_issuer_chain,
        anchor,
        &root,
        &root_crl,
        now,
        "QE Identity issuer chain",
    )?;
    let qe_identity = QeIdentity::verify_and_parse(&collateral.qe_identity, &qe_signer)?;
    pki::check_window(
        "QE Identity",
        qe_identity.issue_date,
        qe_identity.next_update,
        now,
        grace,
    )?;
    let qe_level = qe_identity.match_report(&sig.qe_report)?;

    // 6. TCB status.
    let platform_level = tcb_info
        .level_for(&pck.tcb.comp_svn, pck.tcb.pce_svn)
        .ok_or(VerifyError::TcbLevelNotFound { what: "platform" })?;
    let status = converge_tcb_status(platform_level.status, qe_level.status);
    if status == TcbStatus::Revoked {
        return Err(VerifyError::TcbRevoked);
    }
    let mut advisory_ids = platform_level.advisory_ids.clone();
    for id in &qe_level.advisory_ids {
        if !advisory_ids.contains(id) {
            advisory_ids.push(id.clone());
        }
    }

    Ok(VerifiedQuote {
        claims: VerifiedClaims::new(*quote.report_body(), status, advisory_ids),
        pck,
        pck_ca,
        platform_tcb_status: platform_level.status,
        platform_tcb_date: platform_level.tcb_date.clone(),
        qe_tcb_status: qe_level.status,
        tcb_evaluation_data_number: tcb_info.tcb_evaluation_data_number,
        collateral_expiry: tcb_info.next_update.min(qe_identity.next_update),
    })
}

/// The DCAP [`Verifier`]: fetches collateral from a [`CollateralSource`],
/// verifies the quote against the pinned Intel SGX Root CA, then applies
/// the policy.
#[derive(Debug, Clone)]
pub struct DcapVerifier<S> {
    source: S,
    options: VerifierOptions,
    anchor: TrustAnchor,
}

impl<S: CollateralSource> DcapVerifier<S> {
    /// A verifier using `source` for collateral and default options.
    pub fn new(source: S) -> Self {
        Self {
            source,
            options: VerifierOptions::default(),
            anchor: TrustAnchor::intel(),
        }
    }

    /// Replaces the options.
    #[must_use]
    pub fn with_options(mut self, options: VerifierOptions) -> Self {
        self.options = options;
        self
    }

    /// The options in use.
    pub fn options(&self) -> &VerifierOptions {
        &self.options
    }

    #[cfg(test)]
    pub(crate) fn with_anchor(mut self, anchor: TrustAnchor) -> Self {
        self.anchor = anchor;
        self
    }

    /// Verifies the quote, then checks the policy. Returns the full
    /// verification result.
    pub fn verify_detailed(
        &self,
        raw_quote: &[u8],
        policy: &dyn Policy,
    ) -> Result<VerifiedQuote, VerifyError> {
        let request = collateral_request(raw_quote)?;
        let collateral = self
            .source
            .fetch(&request)
            .map_err(|e| VerifyError::CollateralUnavailable(e.to_string()))?;
        let verified =
            verify_quote_with_anchor(raw_quote, &collateral, &self.options, &self.anchor)?;
        // Not left to the caller's policy: a debug enclave is never
        // confidential, whatever else a custom `Policy` accepts.
        check_baseline(&verified.claims)?;
        policy.check(&verified.claims)?;
        Ok(verified)
    }
}

impl<S: CollateralSource> Verifier for DcapVerifier<S> {
    type Error = VerifyError;

    fn verify(&self, evidence: &[u8], policy: &dyn Policy) -> Result<VerifiedClaims, VerifyError> {
        self.verify_detailed(evidence, policy).map(|v| v.claims)
    }
}
