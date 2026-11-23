//! Collateral retrieval from a PCCS or directly from Intel PCS.
//!
//! Neither service is a trust anchor: every document fetched here is
//! verified by `sgx-ra-verifier` against the pinned Intel SGX Root CA. TLS
//! to the collateral service therefore protects availability and privacy
//! (the FMSPC identifies the platform model), not authenticity, which is why
//! plain HTTP to a local PCCS (the blueprint's `http://127.0.0.1:8080`) is
//! acceptable.
//!
//! Endpoints (Intel PCS / PCCS API v4, `/sgx/certification/v4/...`):
//!
//! | collateral | PCCS | Intel PCS |
//! |---|---|---|
//! | Root CA CRL | `rootcacrl` (hex DER) | `certificates.trustedservices.intel.com/IntelSGXRootCA.der` |
//! | PCK CRL | `pckcrl?ca=…&encoding=der` | same |
//! | TCB Info | `tcb?fmspc=…`, header `TCB-Info-Issuer-Chain` | same |
//! | QE Identity | `qe/identity`, header `SGX-Enclave-Identity-Issuer-Chain` | same |

use std::fmt;
use std::time::Duration;

use sgx_ra_verifier::collateral::{Collateral, CollateralRequest, CollateralSource, SourceError};
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};

/// The blueprint's PCCS address (a local PCCS / caching proxy). Not the
/// [`PccsConfig::default`]: a verifier without SGX usually has no PCCS.
pub const DEFAULT_PCCS_URL: &str = "http://127.0.0.1:8080";
/// Intel's Provisioning Certification Service.
pub const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";
/// Where Intel publishes the Root CA CRL (the PCS API does not serve it).
pub const INTEL_ROOT_CA_CRL_URL: &str =
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";

/// API path prefix of both PCS and PCCS.
const API_PREFIX: &str = "/sgx/certification/v4";
/// Upper bound on any response body. The largest real document (a PCK
/// CRL) is a few kilobytes.
const MAX_BODY: u64 = 4 << 20;
/// Upper bound on an issuer-chain header.
const MAX_HEADER: usize = 64 << 10;

/// Which kind of collateral service to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollateralService {
    /// An Intel PCCS (or compatible caching service).
    Pccs,
    /// Intel PCS directly.
    IntelPcs,
}

/// Configuration of a [`PccsClient`].
#[derive(Clone, PartialEq, Eq)]
pub struct PccsConfig {
    /// Base URL, e.g. `http://127.0.0.1:8080` or `https://pccs.example:8081`.
    /// The API path is appended.
    pub base_url: String,
    /// PCCS or Intel PCS.
    pub service: CollateralService,
    /// PEM certificates to trust for HTTPS instead of the Mozilla roots
    /// (e.g. a PCCS's self-issued CA).
    pub ca_certs_pem: Option<Vec<u8>>,
    /// Skip HTTPS certificate verification. Only defensible because the
    /// collateral is signature-verified; it still lets a network attacker
    /// see the FMSPC and withhold or replay collateral.
    pub insecure_skip_tls_verify: bool,
    /// Overall timeout of each request.
    pub timeout: Duration,
}

impl fmt::Debug for PccsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PccsConfig")
            .field("base_url", &self.base_url)
            .field("service", &self.service)
            .field("custom_ca", &self.ca_certs_pem.is_some())
            .field("insecure_skip_tls_verify", &self.insecure_skip_tls_verify)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Intel PCS: needs no API key, no SGX and no local service, so a
/// verifier works on any host with Internet access.
impl Default for PccsConfig {
    fn default() -> Self {
        Self::intel_pcs()
    }
}

impl PccsConfig {
    /// A PCCS at `base_url`.
    pub fn pccs(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            service: CollateralService::Pccs,
            ca_certs_pem: None,
            insecure_skip_tls_verify: false,
            timeout: Duration::from_secs(30),
        }
    }

    /// Intel PCS directly.
    pub fn intel_pcs() -> Self {
        Self {
            service: CollateralService::IntelPcs,
            ..Self::pccs(INTEL_PCS_URL)
        }
    }

    /// Trusts the CA certificates in `pem` for HTTPS.
    #[must_use]
    pub fn with_ca_pem(mut self, pem: Vec<u8>) -> Self {
        self.ca_certs_pem = Some(pem);
        self
    }
}

/// Errors of the collateral client.
#[derive(Debug)]
pub enum PccsError {
    /// The configuration is invalid.
    Config(String),
    /// A request failed (connection, TLS, HTTP status, size limit).
    Http {
        /// The requested URL.
        url: String,
        /// The underlying error.
        source: ureq::Error,
    },
    /// A required response header is missing or malformed.
    Header {
        /// The requested URL.
        url: String,
        /// The header.
        header: &'static str,
    },
}

impl fmt::Display for PccsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "invalid collateral service configuration: {e}"),
            Self::Http { url, source } => write!(f, "GET {url}: {source}"),
            Self::Header { url, header } => {
                write!(f, "GET {url}: missing or malformed header {header}")
            }
        }
    }
}

impl std::error::Error for PccsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Fetches DCAP collateral over HTTP(S). Implements
/// [`CollateralSource`] for [`sgx_ra_verifier::DcapVerifier`].
#[derive(Debug)]
pub struct PccsClient {
    config: PccsConfig,
    api_base: String,
    agent: ureq::Agent,
}

impl PccsClient {
    /// Validates `config` and builds the HTTP agent.
    pub fn new(config: PccsConfig) -> Result<Self, PccsError> {
        let base = config.base_url.trim_end_matches('/');
        let rest = base
            .strip_prefix("https://")
            .or_else(|| base.strip_prefix("http://"))
            .ok_or_else(|| PccsError::Config("URL must start with http:// or https://".into()))?;
        if rest.is_empty()
            || rest.contains(['?', '#', '@'])
            || rest.chars().any(char::is_whitespace)
        {
            return Err(PccsError::Config(format!(
                "URL {base:?} must be scheme://host[:port][/path] without query, fragment or credentials"
            )));
        }

        let mut tls = TlsConfig::builder().disable_verification(config.insecure_skip_tls_verify);
        if let Some(pem) = &config.ca_certs_pem {
            let certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(pem)
                .filter_map(|item| match item {
                    Ok(PemItem::Certificate(c)) => Some(Ok(c)),
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<_, _>>()
                .map_err(|e| PccsError::Config(format!("invalid CA PEM: {e}")))?;
            if certs.is_empty() {
                return Err(PccsError::Config("CA PEM contains no certificates".into()));
            }
            tls = tls.root_certs(RootCerts::new_with_certs(&certs));
        }
        let agent = ureq::Agent::config_builder()
            .tls_config(tls.build())
            .timeout_global(Some(config.timeout))
            .max_redirects(3)
            .build()
            .new_agent();
        Ok(Self {
            api_base: format!("{base}{API_PREFIX}"),
            config,
            agent,
        })
    }

    /// The configuration in use.
    pub fn config(&self) -> &PccsConfig {
        &self.config
    }

    fn get(
        &self,
        url: &str,
        header: Option<&'static str>,
    ) -> Result<(Vec<u8>, Vec<u8>), PccsError> {
        let http = |source| PccsError::Http {
            url: url.to_owned(),
            source,
        };
        let mut resp = self.agent.get(url).call().map_err(http)?;
        let chain = match header {
            None => Vec::new(),
            Some(name) => {
                // v3-era PCCS versions use the `SGX-` prefixed name for TCB Info.
                let alt = format!("SGX-{name}");
                let value = resp
                    .headers()
                    .get(name)
                    .or_else(|| resp.headers().get(alt.as_str()))
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| v.len() <= MAX_HEADER)
                    .ok_or(PccsError::Header {
                        url: url.to_owned(),
                        header: name,
                    })?;
                percent_decode(value).ok_or(PccsError::Header {
                    url: url.to_owned(),
                    header: name,
                })?
            }
        };
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(http)?;
        Ok((body, chain))
    }

    /// Fetches the collateral for `request`.
    pub fn fetch_collateral(&self, request: &CollateralRequest) -> Result<Collateral, PccsError> {
        let api = &self.api_base;
        let root_crl_url = match self.config.service {
            CollateralService::Pccs => format!("{api}/rootcacrl"),
            CollateralService::IntelPcs => INTEL_ROOT_CA_CRL_URL.to_owned(),
        };
        let (root_ca_crl, _) = self.get(&root_crl_url, None)?;
        let (pck_crl, _) = self.get(
            &format!("{api}/pckcrl?ca={}&encoding=der", request.pck_ca.as_query()),
            None,
        )?;
        let (tcb_info, tcb_info_issuer_chain) = self.get(
            &format!("{api}/tcb?fmspc={}", request.fmspc_hex()),
            Some("TCB-Info-Issuer-Chain"),
        )?;
        let (qe_identity, qe_identity_issuer_chain) = self.get(
            &format!("{api}/qe/identity"),
            Some("SGX-Enclave-Identity-Issuer-Chain"),
        )?;
        Ok(Collateral {
            root_ca_crl,
            pck_crl,
            tcb_info,
            tcb_info_issuer_chain,
            qe_identity,
            qe_identity_issuer_chain,
        })
    }
}

impl CollateralSource for PccsClient {
    fn fetch(&self, request: &CollateralRequest) -> Result<Collateral, SourceError> {
        Ok(self.fetch_collateral(request)?)
    }
}

/// Decodes `%XX` escapes (the issuer-chain headers are URL-encoded PEM).
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(
            percent_decode("-----BEGIN%20CERTIFICATE-----%0AMII%2B").unwrap(),
            b"-----BEGIN CERTIFICATE-----\nMII+"
        );
        assert!(percent_decode("%2").is_none());
        assert!(percent_decode("%zz").is_none());
    }

    #[test]
    fn config_validation() {
        assert_eq!(PccsConfig::default(), PccsConfig::intel_pcs());
        assert!(PccsClient::new(PccsConfig::default()).is_ok());
        assert!(PccsClient::new(PccsConfig::intel_pcs()).is_ok());
        for bad in [
            "127.0.0.1:8080",
            "ftp://x",
            "http://",
            "http://a/b?c",
            "http://user@host",
            "http://a b",
        ] {
            assert!(
                matches!(
                    PccsClient::new(PccsConfig::pccs(bad)),
                    Err(PccsError::Config(_))
                ),
                "{bad}"
            );
        }
        let c = PccsClient::new(PccsConfig::pccs("https://pccs.local:8081/")).unwrap();
        assert_eq!(c.api_base, "https://pccs.local:8081/sgx/certification/v4");

        let with_ca = PccsConfig::pccs("https://pccs.local:8081").with_ca_pem(
            include_bytes!("../../../fixtures/dcap/tcb_info_issuer_chain.pem").to_vec(),
        );
        assert!(PccsClient::new(with_ca).is_ok());
        let no_certs = PccsConfig::pccs("https://pccs.local").with_ca_pem(b"nothing".to_vec());
        assert!(matches!(
            PccsClient::new(no_certs),
            Err(PccsError::Config(_))
        ));
    }
}
