//! X.509 handling: the pinned Intel SGX Root CA, certificate and CRL
//! signature checks, validity periods and revocation.
//!
//! Only what Intel's SGX PKI uses is accepted: ECDSA P-256 keys and
//! `ecdsa-with-SHA256` signatures. Anything else is rejected rather than
//! interpreted.

use std::collections::HashSet;

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use sgx_ra_core::hex::Hex;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256,
    OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_KEY_USAGE,
};
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo, X509Name};

use crate::error::{VerifyError, cert_err, crl_err};

/// DER encoding of the Intel SGX Root CA certificate
/// (`CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US`,
/// valid 2018-05-21 to 2049-12-31), as published at
/// <https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem>.
///
/// This is the trust anchor of all DCAP verification. It is compiled in;
/// nothing received from the network can replace it.
pub const INTEL_SGX_ROOT_CA_DER: &[u8] = include_bytes!("intel_sgx_root_ca.der");

/// SHA-256 of [`INTEL_SGX_ROOT_CA_DER`], for out-of-band comparison.
pub const INTEL_SGX_ROOT_CA_SHA256: &str =
    "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3";

/// Tolerated clock difference (seconds) when checking that a certificate,
/// CRL or collateral document is *already* valid. Expiry is never relaxed
/// by this value.
pub const CLOCK_SKEW_SECS: i64 = 300;

/// Upper bound on the PEM / DER inputs accepted from the network.
const MAX_CHAIN_CERTS: usize = 8;

/// A parsed certificate together with its DER encoding.
pub(crate) struct Cert<'a> {
    pub(crate) x509: X509Certificate<'a>,
}

impl<'a> Cert<'a> {
    pub(crate) fn parse(der: &'a [u8], what: &'static str) -> Result<Self, VerifyError> {
        let (rest, x509) = X509Certificate::from_der(der)
            .map_err(|e| cert_err(what, format!("malformed certificate: {e}")))?;
        if !rest.is_empty() {
            return Err(cert_err(what, "trailing bytes after certificate"));
        }
        Ok(Self { x509 })
    }

    pub(crate) fn subject(&self) -> &X509Name<'a> {
        &self.x509.tbs_certificate.subject
    }

    pub(crate) fn issuer(&self) -> &X509Name<'a> {
        &self.x509.tbs_certificate.issuer
    }

    pub(crate) fn serial_hex(&self) -> String {
        Hex(self.x509.raw_serial()).to_string()
    }

    /// The first common name of the subject.
    pub(crate) fn common_name(&self) -> Option<&str> {
        self.subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
    }

    /// The certificate's P-256 public key.
    pub(crate) fn p256_key(&self, what: &'static str) -> Result<VerifyingKey, VerifyError> {
        p256_key_from_spki(self.x509.public_key(), what)
    }

    /// Checks the validity period at `now` (Unix seconds).
    pub(crate) fn check_validity(&self, now: i64, what: &'static str) -> Result<(), VerifyError> {
        let v = self.x509.validity();
        check_window(
            what,
            v.not_before.timestamp(),
            v.not_after.timestamp(),
            now,
            0,
        )
    }

    /// Checks that this certificate was issued and signed by `issuer`.
    pub(crate) fn check_issued_by(
        &self,
        issuer: &Cert<'_>,
        what: &'static str,
    ) -> Result<(), VerifyError> {
        if self.issuer().as_raw() != issuer.subject().as_raw() {
            return Err(cert_err(
                what,
                format!(
                    "issuer \"{}\" does not match \"{}\"",
                    self.issuer(),
                    issuer.subject()
                ),
            ));
        }
        let key = issuer.p256_key(what)?;
        verify_x509_signature(
            &key,
            self.x509.tbs_certificate.as_ref(),
            &self.x509.tbs_certificate.signature,
            &self.x509.signature_algorithm,
            &self.x509.signature_value.data,
            what,
        )
    }

    /// Rejects certificates with critical extensions we do not process, and
    /// checks basic constraints and key usage for the given role.
    pub(crate) fn check_role(&self, role: Role, what: &'static str) -> Result<(), VerifyError> {
        for ext in self.x509.extensions() {
            if ext.critical
                && ext.oid != OID_X509_EXT_BASIC_CONSTRAINTS
                && ext.oid != OID_X509_EXT_KEY_USAGE
            {
                return Err(cert_err(
                    what,
                    format!("unsupported critical extension {}", ext.oid),
                ));
            }
        }
        let is_ca = self
            .x509
            .basic_constraints()
            .map_err(|e| cert_err(what, format!("bad basic constraints: {e}")))?
            .is_some_and(|bc| bc.value.ca);
        let ku = self
            .x509
            .key_usage()
            .map_err(|e| cert_err(what, format!("bad key usage: {e}")))?
            .map(|ku| *ku.value);
        match role {
            Role::Ca { crl_signer } => {
                if !is_ca {
                    return Err(cert_err(what, "not a CA certificate"));
                }
                let Some(ku) = ku else {
                    return Err(cert_err(what, "CA certificate without key usage"));
                };
                if !ku.key_cert_sign() || (crl_signer && !ku.crl_sign()) {
                    return Err(cert_err(what, "key usage does not allow signing"));
                }
            }
            Role::EndEntity => {
                if is_ca {
                    return Err(cert_err(what, "end-entity certificate is a CA"));
                }
                if ku.is_some_and(|ku| !ku.digital_signature()) {
                    return Err(cert_err(what, "key usage does not allow signatures"));
                }
            }
        }
        Ok(())
    }
}

/// The role a certificate plays in a chain.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Role {
    /// A CA; `crl_signer` additionally requires the cRLSign key usage.
    Ca { crl_signer: bool },
    /// A signing (leaf) certificate.
    EndEntity,
}

/// The pinned root of trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustAnchor {
    der: Vec<u8>,
}

impl TrustAnchor {
    /// The Intel SGX Root CA.
    pub(crate) fn intel() -> Self {
        Self {
            der: INTEL_SGX_ROOT_CA_DER.to_vec(),
        }
    }

    /// A different root, for tests with a synthetic PKI only.
    #[cfg(test)]
    pub(crate) fn custom(der: Vec<u8>) -> Self {
        Self { der }
    }

    /// Parses the anchor and checks that it is a valid, self-signed CA at
    /// `now`.
    pub(crate) fn cert(&self, now: i64) -> Result<Cert<'_>, VerifyError> {
        const WHAT: &str = "Intel SGX Root CA";
        let root = Cert::parse(&self.der, WHAT)?;
        root.check_issued_by(&root, WHAT)?;
        root.check_validity(now, WHAT)?;
        root.check_role(Role::Ca { crl_signer: true }, WHAT)?;
        Ok(root)
    }

    /// Requires `der` (a root certificate shipped alongside a chain) to be
    /// exactly the pinned root.
    pub(crate) fn require_pinned(&self, der: &[u8], what: &'static str) -> Result<(), VerifyError> {
        if der == self.der.as_slice() {
            Ok(())
        } else {
            Err(VerifyError::UntrustedRoot { what })
        }
    }
}

/// `true` if the SHA-256 of `der` equals [`INTEL_SGX_ROOT_CA_SHA256`].
pub fn is_intel_root(der: &[u8]) -> bool {
    Hex(&Sha256::digest(der)).to_string() == INTEL_SGX_ROOT_CA_SHA256
}

/// Checks `not_before - skew <= now <= not_after + grace`.
pub(crate) fn check_window(
    what: &'static str,
    not_before: i64,
    not_after: i64,
    now: i64,
    grace_secs: i64,
) -> Result<(), VerifyError> {
    let not_after = not_after.saturating_add(grace_secs);
    if now.saturating_add(CLOCK_SKEW_SECS) < not_before || now > not_after {
        return Err(VerifyError::Expired {
            what,
            not_before,
            not_after,
            now,
        });
    }
    Ok(())
}

fn p256_key_from_spki(
    spki: &SubjectPublicKeyInfo<'_>,
    what: &'static str,
) -> Result<VerifyingKey, VerifyError> {
    let curve_ok = spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .is_some_and(|oid| oid == OID_EC_P256);
    if !curve_ok {
        return Err(cert_err(what, "public key is not an ECDSA P-256 key"));
    }
    VerifyingKey::from_sec1_bytes(&spki.subject_public_key.data)
        .map_err(|_| cert_err(what, "invalid P-256 public key"))
}

/// Verifies an X.509-style (certificate or CRL) signature.
fn verify_x509_signature(
    key: &VerifyingKey,
    tbs: &[u8],
    inner_alg: &AlgorithmIdentifier<'_>,
    outer_alg: &AlgorithmIdentifier<'_>,
    signature_der: &[u8],
    what: &'static str,
) -> Result<(), VerifyError> {
    // RFC 5280 §4.1.1.2: both algorithm fields must be identical.
    if outer_alg.algorithm != OID_SIG_ECDSA_WITH_SHA256 || inner_alg != outer_alg {
        return Err(cert_err(
            what,
            "signature algorithm is not ecdsa-with-SHA256",
        ));
    }
    let sig = Signature::from_der(signature_der).map_err(|_| VerifyError::BadSignature { what })?;
    key.verify(tbs, &sig)
        .map_err(|_| VerifyError::BadSignature { what })
}

/// Verifies a raw `r ‖ s` ECDSA P-256 / SHA-256 signature, the format used
/// by quotes and by the TCB Info / QE Identity JSON documents.
pub(crate) fn verify_raw_signature(
    key: &VerifyingKey,
    msg: &[u8],
    signature: &[u8],
    what: &'static str,
) -> Result<(), VerifyError> {
    let sig = Signature::from_slice(signature).map_err(|_| VerifyError::BadSignature { what })?;
    key.verify(msg, &sig)
        .map_err(|_| VerifyError::BadSignature { what })
}

/// The P-256 key encoded as the 64-byte `x ‖ y` used in quotes.
pub(crate) fn raw_p256_key(xy: &[u8; 64], what: &'static str) -> Result<VerifyingKey, VerifyError> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(xy);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| cert_err(what, "invalid P-256 public key"))
}

/// Splits a PEM bundle into DER certificates, in order.
///
/// Trailing NUL bytes (the quote's certification data is NUL-terminated)
/// and whitespace are ignored; anything else that is not a `CERTIFICATE`
/// block is an error.
pub(crate) fn pem_certificates(
    pem: &[u8],
    what: &'static str,
) -> Result<Vec<Vec<u8>>, VerifyError> {
    let end = pem
        .iter()
        .rposition(|b| !matches!(b, 0 | b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(0, |i| i + 1);
    let text = std::str::from_utf8(&pem[..end])
        .map_err(|_| cert_err(what, "certificate chain is not ASCII PEM"))?;

    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let body = rest
            .strip_prefix(BEGIN)
            .ok_or_else(|| cert_err(what, "expected a PEM CERTIFICATE block"))?;
        let (b64, after) = body
            .split_once(END)
            .ok_or_else(|| cert_err(what, "unterminated PEM block"))?;
        if certs.len() == MAX_CHAIN_CERTS {
            return Err(cert_err(what, "too many certificates"));
        }
        certs.push(base64_decode(b64).ok_or_else(|| cert_err(what, "invalid base64"))?);
        rest = after.trim_start();
    }
    if certs.is_empty() {
        return Err(cert_err(what, "no certificates"));
    }
    Ok(certs)
}

/// Strict standard-alphabet base64 decoding, ignoring ASCII whitespace.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let chars: Vec<u8> = input.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    if !chars.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    let n = chars.len() / 4;
    for (i, quad) in chars.chunks(4).enumerate() {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != n) {
            return None;
        }
        let mut acc = 0u32;
        for &c in &quad[..4 - pad] {
            acc = (acc << 6) | val(c)?;
        }
        acc <<= 6 * pad as u32;
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

/// Normalises a CRL as served by Intel PCS or a PCCS into DER.
///
/// Intel PCS serves DER (`encoding=der`); PCCS v4 serves the DER either
/// raw or hex-encoded depending on the endpoint and version; some
/// deployments serve PEM. The result is parsed and signature-checked
/// afterwards, so this only has to be unambiguous.
pub fn crl_to_der(bytes: &[u8]) -> Result<Vec<u8>, VerifyError> {
    const WHAT: &str = "CRL";
    let trimmed = bytes.trim_ascii();
    if trimmed.first() == Some(&0x30) {
        return Ok(bytes.to_vec());
    }
    if let Some(body) = trimmed.strip_prefix(b"-----BEGIN X509 CRL-----") {
        let text = std::str::from_utf8(body).map_err(|_| crl_err(WHAT, "not ASCII PEM"))?;
        let (b64, after) = text
            .split_once("-----END X509 CRL-----")
            .ok_or_else(|| crl_err(WHAT, "unterminated PEM block"))?;
        if !after.trim().is_empty() {
            return Err(crl_err(WHAT, "trailing data after PEM block"));
        }
        return base64_decode(b64).ok_or_else(|| crl_err(WHAT, "invalid base64"));
    }
    if !trimmed.is_empty()
        && trimmed.len().is_multiple_of(2)
        && trimmed.iter().all(u8::is_ascii_hexdigit)
    {
        let decoded: Vec<u8> = trimmed
            .chunks(2)
            .map(|p| {
                // Both bytes are ASCII hex digits, checked above.
                let s = std::str::from_utf8(p).unwrap_or("00");
                u8::from_str_radix(s, 16).unwrap_or(0)
            })
            .collect();
        if decoded.first() == Some(&0x30) {
            return Ok(decoded);
        }
    }
    Err(crl_err(WHAT, "not a DER, PEM or hex-encoded CRL"))
}

/// The serial numbers revoked by a verified CRL.
#[derive(Debug)]
pub(crate) struct RevokedSerials(HashSet<Vec<u8>>);

impl RevokedSerials {
    pub(crate) fn check(&self, cert: &Cert<'_>, what: &'static str) -> Result<(), VerifyError> {
        if self.0.contains(cert.x509.raw_serial()) {
            Err(VerifyError::Revoked {
                what,
                serial: cert.serial_hex(),
            })
        } else {
            Ok(())
        }
    }
}

/// Parses a DER CRL, checks that `issuer` issued and signed it and that it
/// is current at `now` (with `grace_secs` past `nextUpdate`), and returns
/// the revoked serials.
pub(crate) fn verify_crl(
    der: &[u8],
    issuer: &Cert<'_>,
    now: i64,
    grace_secs: i64,
    what: &'static str,
) -> Result<RevokedSerials, VerifyError> {
    let (rest, crl) = CertificateRevocationList::from_der(der)
        .map_err(|e| crl_err(what, format!("malformed CRL: {e}")))?;
    if !rest.is_empty() {
        return Err(crl_err(what, "trailing bytes after CRL"));
    }
    if crl.issuer().as_raw() != issuer.subject().as_raw() {
        return Err(crl_err(
            what,
            format!(
                "issued by \"{}\", expected \"{}\"",
                crl.issuer(),
                issuer.subject()
            ),
        ));
    }
    for ext in crl.extensions() {
        if ext.critical {
            return Err(crl_err(
                what,
                format!("unsupported critical extension {}", ext.oid),
            ));
        }
    }
    let key = issuer.p256_key(what)?;
    verify_x509_signature(
        &key,
        crl.tbs_cert_list.as_ref(),
        &crl.tbs_cert_list.signature,
        &crl.signature_algorithm,
        &crl.signature_value.data,
        what,
    )?;
    let next_update = crl
        .next_update()
        .ok_or_else(|| crl_err(what, "CRL has no nextUpdate"))?;
    check_window(
        what,
        crl.last_update().timestamp(),
        next_update.timestamp(),
        now,
        grace_secs,
    )?;
    Ok(RevokedSerials(
        crl.iter_revoked_certificates()
            .map(|r| r.raw_serial().to_vec())
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_root_is_intels() {
        assert!(is_intel_root(INTEL_SGX_ROOT_CA_DER));
        let anchor = TrustAnchor::intel();
        // 2026-11-23T00:00:00Z
        let root = anchor.cert(1_795_392_000).unwrap();
        assert_eq!(root.common_name(), Some("Intel SGX Root CA"));
        // The root is valid until 2049-12-31T23:59:59Z only.
        assert!(matches!(
            anchor.cert(2_524_608_000),
            Err(VerifyError::Expired { .. })
        ));
    }

    #[test]
    fn base64_roundtrip_and_rejects() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVs\nbG8h").unwrap(), b"hello!");
        assert_eq!(base64_decode("aGk=").unwrap(), b"hi");
        assert!(base64_decode("aGk").is_none());
        assert!(base64_decode("a===").is_none());
        assert!(base64_decode("aG=k").is_none());
        assert!(base64_decode("aGk=aGk=").is_none());
        assert!(base64_decode("aG*k").is_none());
    }

    #[test]
    fn crl_encodings() {
        let der = include_bytes!("../../../fixtures/dcap/root_ca_crl.der");
        assert_eq!(crl_to_der(der).unwrap(), der);
        let hex = Hex(der).to_string();
        assert_eq!(crl_to_der(hex.as_bytes()).unwrap(), der);
        assert_eq!(crl_to_der(hex.to_uppercase().as_bytes()).unwrap(), der);
        let pem = format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n",
            base64_encode(der)
        );
        assert_eq!(crl_to_der(pem.as_bytes()).unwrap(), der);
        assert!(crl_to_der(b"").is_err());
        assert!(crl_to_der(b"<html>error</html>").is_err());
        assert!(crl_to_der(b"abcd").is_err());
    }

    #[test]
    fn pem_bundle_parsing() {
        let pem = include_bytes!("../../../fixtures/dcap/tcb_info_issuer_chain.pem");
        let certs = pem_certificates(pem, "test").unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[1], INTEL_SGX_ROOT_CA_DER);

        let mut nul = pem.to_vec();
        nul.extend_from_slice(b"\n\0");
        assert_eq!(pem_certificates(&nul, "test").unwrap(), certs);

        let mut junk = pem.to_vec();
        junk.extend_from_slice(b"junk");
        assert!(pem_certificates(&junk, "test").is_err());
        assert!(pem_certificates(b"", "test").is_err());
        assert!(pem_certificates(b"-----BEGIN CERTIFICATE-----\nAAAA", "test").is_err());
    }

    pub(crate) fn base64_encode(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let mut b = [0u8; 3];
            b[..chunk.len()].copy_from_slice(chunk);
            let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
