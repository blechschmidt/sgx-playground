//! Verification collateral and where it comes from.
//!
//! Collateral is untrusted input: whoever serves it (PCCS, Intel PCS, a
//! file) is not a trust anchor. Every document is checked against the
//! pinned Intel SGX Root CA before it is used. A malicious server can only
//! withhold collateral or replay older documents that are still within
//! their signed validity period.

use std::fmt;

use sgx_ra_core::hex::Hex;

/// The CA that issued a PCK certificate (selects the PCK CRL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PckCa {
    /// `Intel SGX PCK Platform CA` (multi-package / server platforms).
    Platform,
    /// `Intel SGX PCK Processor CA`.
    Processor,
}

impl PckCa {
    /// The issuing CA's common name.
    pub fn common_name(self) -> &'static str {
        match self {
            Self::Platform => "Intel SGX PCK Platform CA",
            Self::Processor => "Intel SGX PCK Processor CA",
        }
    }

    /// The `ca` query parameter of the PCS / PCCS `pckcrl` endpoint.
    pub fn as_query(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Processor => "processor",
        }
    }

    pub(crate) fn from_common_name(cn: &str) -> Option<Self> {
        [Self::Platform, Self::Processor]
            .into_iter()
            .find(|ca| ca.common_name() == cn)
    }
}

impl fmt::Display for PckCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_query())
    }
}

/// Identifies the collateral a quote needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CollateralRequest {
    /// The platform's FMSPC, from the PCK certificate.
    pub fmspc: [u8; 6],
    /// The CA that issued the PCK certificate.
    pub pck_ca: PckCa,
}

impl CollateralRequest {
    /// The FMSPC as 12 lowercase hex digits (the `fmspc` query parameter).
    pub fn fmspc_hex(&self) -> String {
        Hex(&self.fmspc).to_string()
    }
}

/// The DCAP collateral for one quote, as served by a PCCS or Intel PCS.
///
/// All fields hold the raw response bodies (the issuer chains are the
/// URL-decoded PEM of the corresponding response headers).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Collateral {
    /// Intel SGX Root CA CRL (DER, PEM or hex-encoded DER).
    pub root_ca_crl: Vec<u8>,
    /// CRL of the PCK certificate's issuing CA (DER, PEM or hex).
    pub pck_crl: Vec<u8>,
    /// The TCB Info JSON document for the platform's FMSPC.
    pub tcb_info: Vec<u8>,
    /// PEM chain of the TCB Info signer (`TCB-Info-Issuer-Chain`).
    pub tcb_info_issuer_chain: Vec<u8>,
    /// The QE Identity JSON document.
    pub qe_identity: Vec<u8>,
    /// PEM chain of the QE Identity signer
    /// (`SGX-Enclave-Identity-Issuer-Chain`).
    pub qe_identity_issuer_chain: Vec<u8>,
}

impl fmt::Debug for Collateral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Collateral")
            .field("root_ca_crl", &self.root_ca_crl.len())
            .field("pck_crl", &self.pck_crl.len())
            .field("tcb_info", &self.tcb_info.len())
            .field("tcb_info_issuer_chain", &self.tcb_info_issuer_chain.len())
            .field("qe_identity", &self.qe_identity.len())
            .field(
                "qe_identity_issuer_chain",
                &self.qe_identity_issuer_chain.len(),
            )
            .finish()
    }
}

/// Error type of collateral sources.
pub type SourceError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Provides collateral for quotes (a PCCS client, Intel PCS, a cache, or
/// fixed recorded collateral).
pub trait CollateralSource {
    /// Fetches the collateral described by `request`.
    fn fetch(&self, request: &CollateralRequest) -> Result<Collateral, SourceError>;
}

impl<S: CollateralSource + ?Sized> CollateralSource for &S {
    fn fetch(&self, request: &CollateralRequest) -> Result<Collateral, SourceError> {
        (**self).fetch(request)
    }
}

impl<S: CollateralSource + ?Sized> CollateralSource for Box<S> {
    fn fetch(&self, request: &CollateralRequest) -> Result<Collateral, SourceError> {
        (**self).fetch(request)
    }
}

/// A source that always returns the same collateral (recorded collateral,
/// offline verification, tests).
#[derive(Debug, Clone)]
pub struct StaticCollateral(pub Collateral);

impl CollateralSource for StaticCollateral {
    fn fetch(&self, _request: &CollateralRequest) -> Result<Collateral, SourceError> {
        Ok(self.0.clone())
    }
}
