//! DCAP verification tests.
//!
//! * `real_*`: the recorded quote `fixtures/quote_v3.dat` with collateral
//!   recorded from Intel PCS on 2026-11-22 (`fixtures/dcap/`), verified at
//!   a fixed time. Positive path plus tampering of every signed part.
//! * `synthetic_*`: a throw-away PKI shaped like Intel's (root → PCK CA →
//!   PCK leaf with SGX extension, TCB signing cert, CRLs, signed JSON). It
//!   covers what recorded data cannot: revocation, foreign roots, QE
//!   identity mismatches, revoked TCB levels, debug enclaves.

use std::time::Duration;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    CustomExtension, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams,
    SerialNumber,
};
use sgx_ra_core::attestation::{EnclavePolicy, PolicyViolation, TcbStatus, Verifier};
use sgx_ra_core::binding;
use sgx_ra_core::hex::Hex;
use sgx_ra_core::sgx::{Measurement, Quote};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::macros::datetime;

use crate::collateral::{Collateral, CollateralRequest, CollateralSource, SourceError};
use crate::pki::TrustAnchor;
use crate::verify::verify_quote_with_anchor;
use crate::*;

// ---------------------------------------------------------------------------
// Recorded quote and collateral
// ---------------------------------------------------------------------------

const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");

/// 2026-11-23T00:00:00Z: all recorded collateral is current.
const T0: i64 = 1_795_392_000;
/// 2026-12-22T21:33:19Z: `nextUpdate` of the recorded PCK CRL, the first
/// collateral to expire.
const PCK_CRL_NEXT_UPDATE: i64 = 1_797_975_199;

const FIXTURE_MRENCLAVE: &str = "e413a4ed616c7a79634d5ca05a2fda746a1f0c71349a80b25a02828846fab90e";
const FIXTURE_MRSIGNER: &str = "ac2c9fa87e4c91768b1d0c47169466c50d5a98c790639fbaefe7352a59919980";

fn recorded_collateral() -> Collateral {
    Collateral {
        root_ca_crl: include_bytes!("../../../fixtures/dcap/root_ca_crl.der").to_vec(),
        pck_crl: include_bytes!("../../../fixtures/dcap/pck_crl_platform.der").to_vec(),
        tcb_info: include_bytes!("../../../fixtures/dcap/tcb_info.json").to_vec(),
        tcb_info_issuer_chain: include_bytes!("../../../fixtures/dcap/tcb_info_issuer_chain.pem")
            .to_vec(),
        qe_identity: include_bytes!("../../../fixtures/dcap/qe_identity.json").to_vec(),
        qe_identity_issuer_chain: include_bytes!(
            "../../../fixtures/dcap/qe_identity_issuer_chain.pem"
        )
        .to_vec(),
    }
}

fn at(t: i64) -> VerifierOptions {
    VerifierOptions {
        fixed_time: Some(t),
        ..VerifierOptions::default()
    }
}

fn verify_real(quote: &[u8], collateral: &Collateral) -> Result<VerifiedQuote, VerifyError> {
    verify_quote(quote, collateral, &at(T0))
}

fn fixture_policy() -> EnclavePolicy {
    EnclavePolicy::new(Measurement::from_hex(FIXTURE_MRENCLAVE).unwrap())
}

fn real_verifier() -> DcapVerifier<StaticCollateral> {
    DcapVerifier::new(StaticCollateral(recorded_collateral())).with_options(at(T0))
}

/// Byte offsets inside the recorded quote.
mod off {
    pub const MR_ENCLAVE: usize = 48 + 64;
    pub const REPORT_DATA: usize = 48 + 320;
    pub const USER_DATA: usize = 28;
    pub const SIG: usize = 436;
    pub const ATT_KEY: usize = SIG + 64;
    pub const QE_REPORT: usize = ATT_KEY + 64;
    pub const QE_REPORT_SIG: usize = QE_REPORT + 384;
    pub const QE_AUTH: usize = QE_REPORT_SIG + 64 + 2;
}

fn flip(data: &[u8], at: usize) -> Vec<u8> {
    let mut v = data.to_vec();
    v[at] ^= 0x01;
    v
}

#[test]
fn real_quote_verifies_with_recorded_collateral() {
    let v = verify_real(QUOTE_V3, &recorded_collateral()).unwrap();
    let id = v.claims.identity();
    assert_eq!(id.mr_enclave.to_string(), FIXTURE_MRENCLAVE);
    assert_eq!(id.mr_signer.to_string(), FIXTURE_MRSIGNER);
    assert_eq!((id.isv_prod_id, id.isv_svn), (1, 10));
    assert_eq!(v.pck_ca, PckCa::Platform);
    assert_eq!(Hex(&v.pck.fmspc).to_string(), "30606a000000");
    // PCK TCB 07 09 03 03 ff ff 01 …, PCE SVN 13 matches the
    // [7, 9, 3, 3, 255, 255, 1] level, which Intel rates OutOfDate.
    assert_eq!(v.platform_tcb_status, TcbStatus::OutOfDate);
    assert_eq!(v.platform_tcb_date, "2022-08-10T00:00:00Z");
    assert_eq!(v.qe_tcb_status, TcbStatus::UpToDate);
    assert_eq!(v.claims.tcb_status(), TcbStatus::OutOfDate);
    assert!(
        v.claims
            .advisory_ids()
            .iter()
            .any(|a| a == "INTEL-SA-00657")
    );
    assert_eq!(v.tcb_evaluation_data_number, 20);
    assert_eq!(v.collateral_expiry, 1_797_975_260); // TCB Info nextUpdate
    // The best level for this FMSPC is [15, 16, 3, 3, 255, 255, 1],
    // SWHardeningNeeded: only the two microcode SVNs are behind.
    let gap = v
        .platform_tcb_gap
        .expect("platform is below the best level");
    assert_eq!(gap.best.status, TcbStatus::SwHardeningNeeded);
    assert_eq!(gap.best.tcb_date, "2025-08-13T00:00:00Z");
    let shortfalls: Vec<String> = gap.shortfalls.iter().map(ToString::to_string).collect();
    assert_eq!(
        shortfalls,
        [
            "component 0 (BIOS, Early Microcode Update) is 7 < 15",
            "component 1 (OS/VMM, SGX Late Microcode Update) is 9 < 16",
        ]
    );
    assert_eq!(
        gap.shortfalls[0].remedy(),
        "update the BIOS / microcode of the physical host"
    );
}

#[test]
fn tcb_gap_reports_configuration_components() {
    // The live executor's PCK TCB (2026-11-24, Alibaba Cloud ecs.c7t,
    // Xeon 8369B): microcode behind and component 6 (the configuration bit
    // behind "ConfigurationNeeded") clear.
    let chain = pki::pem_certificates(
        include_bytes!("../../../fixtures/dcap/tcb_info_issuer_chain.pem"),
        "chain",
    )
    .unwrap();
    let signer = pki::Cert::parse(&chain[0], "signer")
        .unwrap()
        .p256_key("signer")
        .unwrap();
    let info = crate::tcb::TcbInfo::verify_and_parse(
        include_bytes!("../../../fixtures/dcap/tcb_info.json"),
        &signer,
    )
    .unwrap();
    let have = [14, 14, 3, 3, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let level = info.level_for(&have, 13).unwrap();
    assert_eq!(level.status, TcbStatus::OutOfDateConfigurationNeeded);
    let gap = info.gap_to_best(&have, 13).unwrap();
    let parts: Vec<(Option<usize>, u16, u16)> = gap
        .shortfalls
        .iter()
        .map(|s| (s.component, s.have, s.need))
        .collect();
    assert_eq!(
        parts,
        [(Some(0), 14, 15), (Some(1), 14, 16), (Some(6), 0, 1)]
    );
    assert_eq!(gap.shortfalls[2].label, "");
    assert_eq!(
        gap.shortfalls[2].remedy(),
        "update or reconfigure the BIOS of the physical host"
    );
    assert_eq!(info.gap_to_best(&info.levels[0].comp_svn, 13), None);
    assert!(
        info.gap_to_best(&info.levels[0].comp_svn, 12)
            .unwrap()
            .shortfalls[0]
            .component
            .is_none()
    );
}

#[test]
fn real_collateral_request() {
    let req = collateral_request(QUOTE_V3).unwrap();
    assert_eq!(req.fmspc_hex(), "30606a000000");
    assert_eq!(req.pck_ca, PckCa::Platform);
}

#[test]
fn real_policy_evaluation() {
    let verifier = real_verifier();
    // Default policy: UpToDate only.
    assert_eq!(
        verifier.verify(QUOTE_V3, &fixture_policy()),
        Err(VerifyError::Policy(PolicyViolation::TcbStatusNotAllowed(
            TcbStatus::OutOfDate
        )))
    );
    let lenient = fixture_policy().allow_tcb_status(TcbStatus::OutOfDate);
    let claims = verifier.verify(QUOTE_V3, &lenient).unwrap();
    assert_eq!(claims.tcb_status(), TcbStatus::OutOfDate);

    // MRENCLAVE from a different build.
    let other = Measurement([0x42; 32]);
    assert!(matches!(
        verifier.verify(
            QUOTE_V3,
            &EnclavePolicy::new(other).allow_tcb_status(TcbStatus::OutOfDate)
        ),
        Err(VerifyError::Policy(
            PolicyViolation::MrEnclaveMismatch { .. }
        ))
    ));
    // Optional MRSIGNER / ISVPRODID / minimum ISVSVN.
    let signer = Measurement::from_hex(FIXTURE_MRSIGNER).unwrap();
    assert!(
        verifier
            .verify(
                QUOTE_V3,
                &lenient
                    .clone()
                    .with_mr_signer(signer)
                    .with_isv_prod_id(1)
                    .with_min_isv_svn(10)
            )
            .is_ok()
    );
    assert!(matches!(
        verifier.verify(QUOTE_V3, &lenient.clone().with_mr_signer(other)),
        Err(VerifyError::Policy(
            PolicyViolation::MrSignerMismatch { .. }
        ))
    ));
    assert!(matches!(
        verifier.verify(QUOTE_V3, &lenient.clone().with_isv_prod_id(2)),
        Err(VerifyError::Policy(
            PolicyViolation::IsvProdIdMismatch { .. }
        ))
    ));
    assert!(matches!(
        verifier.verify(QUOTE_V3, &lenient.clone().with_min_isv_svn(11)),
        Err(VerifyError::Policy(PolicyViolation::IsvSvnTooLow { .. }))
    ));
}

#[test]
fn real_report_data_is_not_a_channel_binding() {
    // The recorded quote has all-zero report_data: it commits to no key, so
    // the channel binding check rejects every key.
    let claims = real_verifier()
        .verify(
            QUOTE_V3,
            &fixture_policy().allow_tcb_status(TcbStatus::OutOfDate),
        )
        .unwrap();
    assert!(binding::check_report_data(&claims.report_data(), &[0u8; 32]).is_err());
}

#[test]
fn real_tampered_quote_is_rejected() {
    let c = recorded_collateral();
    // Enclave identity and report data are covered by the quote signature.
    for at in [
        off::MR_ENCLAVE,
        off::REPORT_DATA,
        off::USER_DATA,
        off::SIG + 5,
    ] {
        assert_eq!(
            verify_real(&flip(QUOTE_V3, at), &c),
            Err(VerifyError::BadSignature { what: "quote" }),
            "offset {at}"
        );
    }
    // A different attestation key no longer matches the QE report.
    assert_eq!(
        verify_real(&flip(QUOTE_V3, off::ATT_KEY + 63), &c),
        Err(VerifyError::QeReportDataMismatch)
    );
    assert_eq!(
        verify_real(&flip(QUOTE_V3, off::QE_AUTH), &c),
        Err(VerifyError::QeReportDataMismatch)
    );
    // QE report and its signature are covered by the PCK key.
    for at in [
        off::QE_REPORT + 64,
        off::QE_REPORT + 320,
        off::QE_REPORT_SIG + 1,
    ] {
        assert_eq!(
            verify_real(&flip(QUOTE_V3, at), &c),
            Err(VerifyError::BadSignature { what: "QE report" }),
            "offset {at}"
        );
    }
}

#[test]
fn real_tampered_pck_chain_is_rejected() {
    let c = recorded_collateral();
    let quote = Quote::parse(QUOTE_V3).unwrap();
    let cert_data = quote.signature().certification.data;
    let start = QUOTE_V3.len() - cert_data.len();
    let pem = std::str::from_utf8(cert_data).unwrap();

    // Swap the order of leaf and intermediate.
    let blocks: Vec<&str> = pem.split_inclusive("-----END CERTIFICATE-----\n").collect();
    assert_eq!(blocks.len(), 4); // 3 certificates and the trailing NUL
    let swapped = [blocks[1], blocks[0], blocks[2], blocks[3]].concat();
    let mut q = QUOTE_V3.to_vec();
    q[start..].copy_from_slice(swapped.as_bytes());
    assert!(matches!(
        verify_real(&q, &c),
        Err(VerifyError::Certificate { .. })
    ));

    // Drop the root: only 2 certificates.
    let short = [blocks[0], blocks[1]].concat();
    let mut q = QUOTE_V3[..start].to_vec();
    q.extend_from_slice(short.as_bytes());
    let len_at = start - 4;
    q[len_at..start].copy_from_slice(&(short.len() as u32).to_le_bytes());
    let sig_len = (q.len() - 436) as u32;
    q[432..436].copy_from_slice(&sig_len.to_le_bytes());
    assert!(matches!(
        verify_real(&q, &c),
        Err(VerifyError::Certificate {
            what: "PCK certificate chain",
            ..
        })
    ));

    // A flipped bit inside the leaf's base64 (its signature or TBS).
    let leaf_body = pem.find("MII").unwrap() + 200;
    let mut q = QUOTE_V3.to_vec();
    q[start + leaf_body] = if q[start + leaf_body] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert!(verify_real(&q, &c).is_err());
}

#[test]
fn real_tampered_collateral_is_rejected() {
    let base = recorded_collateral();

    // A TCB level status rewritten from OutOfDate to UpToDate.
    let mut c = base.clone();
    let s = String::from_utf8(c.tcb_info.clone()).unwrap();
    c.tcb_info = s.replacen("\"OutOfDate\"", "\"UpToDate\"", 1).into_bytes();
    assert_eq!(
        verify_real(QUOTE_V3, &c),
        Err(VerifyError::BadSignature { what: "TCB Info" })
    );

    // Re-serialised body (whitespace) is no longer the signed byte string.
    let mut c = base.clone();
    c.tcb_info = s.replacen("{\"id\"", "{ \"id\"", 1).into_bytes();
    assert_eq!(
        verify_real(QUOTE_V3, &c),
        Err(VerifyError::BadSignature { what: "TCB Info" })
    );

    // QE Identity with a different QE MRSIGNER.
    let mut c = base.clone();
    let s = String::from_utf8(c.qe_identity.clone()).unwrap();
    c.qe_identity = s.replacen("8C4F", "8C4E", 1).into_bytes();
    assert_eq!(
        verify_real(QUOTE_V3, &c),
        Err(VerifyError::BadSignature {
            what: "QE Identity"
        })
    );

    // Swapped documents.
    let mut c = base.clone();
    std::mem::swap(&mut c.tcb_info, &mut c.qe_identity);
    assert!(matches!(
        verify_real(QUOTE_V3, &c),
        Err(VerifyError::Collateral {
            what: "TCB Info",
            ..
        })
    ));
    let mut c = base.clone();
    std::mem::swap(&mut c.root_ca_crl, &mut c.pck_crl);
    assert!(matches!(
        verify_real(QUOTE_V3, &c),
        Err(VerifyError::Crl {
            what: "Root CA CRL",
            ..
        })
    ));

    // Issuer chain without the pinned root, or with the PCK chain instead.
    let mut c = base.clone();
    let pem = String::from_utf8(c.tcb_info_issuer_chain.clone()).unwrap();
    let first = pem
        .split_inclusive("-----END CERTIFICATE-----")
        .next()
        .unwrap();
    c.tcb_info_issuer_chain = first.as_bytes().to_vec();
    assert!(matches!(
        verify_real(QUOTE_V3, &c),
        Err(VerifyError::Certificate {
            what: "TCB Info issuer chain",
            ..
        })
    ));
    let mut c = base.clone();
    let quote = Quote::parse(QUOTE_V3).unwrap();
    c.qe_identity_issuer_chain = quote.signature().certification.data.to_vec();
    assert!(matches!(
        verify_real(QUOTE_V3, &c),
        Err(VerifyError::Certificate {
            what: "QE Identity issuer chain",
            ..
        })
    ));

    // Truncated CRL.
    let mut c = base.clone();
    c.pck_crl.truncate(c.pck_crl.len() - 1);
    assert!(matches!(
        verify_real(QUOTE_V3, &c),
        Err(VerifyError::Crl { .. })
    ));

    // Hex-encoded CRLs as served by PCCS are accepted.
    let mut c = base.clone();
    c.root_ca_crl = Hex(&c.root_ca_crl).to_string().into_bytes();
    c.pck_crl = Hex(&c.pck_crl).to_string().into_bytes();
    assert!(verify_real(QUOTE_V3, &c).is_ok());
}

#[test]
fn real_collateral_freshness() {
    let c = recorded_collateral();
    assert!(verify_quote(QUOTE_V3, &c, &at(PCK_CRL_NEXT_UPDATE)).is_ok());
    let late = PCK_CRL_NEXT_UPDATE + 1;
    assert!(matches!(
        verify_quote(QUOTE_V3, &c, &at(late)),
        Err(VerifyError::Expired {
            what: "PCK CRL",
            ..
        })
    ));
    // Explicit grace accepts stale collateral…
    let grace = VerifierOptions {
        collateral_grace: Duration::from_secs(7 * 86_400),
        fixed_time: Some(late + 3 * 86_400),
    };
    assert!(verify_quote(QUOTE_V3, &c, &grace).is_ok());
    // …but never expired or not-yet-valid certificates. The PCK leaf is
    // valid from 2023-03-09.
    let early = VerifierOptions {
        collateral_grace: Duration::from_secs(u64::MAX / 2),
        fixed_time: Some(1_672_531_200), // 2023-01-01
    };
    assert!(matches!(
        verify_quote(QUOTE_V3, &c, &early),
        Err(VerifyError::Expired {
            what: "PCK certificate",
            ..
        })
    ));
    // Collateral issued after the verification time (2026-11-22T21:34:20Z
    // is the TCB Info issue date; the PCK CRL is from 21:33:19).
    assert!(matches!(
        verify_quote(QUOTE_V3, &c, &at(1_795_383_199 - 400)),
        Err(VerifyError::Expired { .. })
    ));
}

#[test]
fn real_structural_rejections() {
    let c = recorded_collateral();
    assert!(matches!(
        verify_real(&QUOTE_V3[..QUOTE_V3.len() - 1], &c),
        Err(VerifyError::Parse(_))
    ));
    assert!(matches!(
        verify_real(&flip(QUOTE_V3, 12), &c),
        Err(VerifyError::UntrustedQeVendor(_))
    ));
}

struct FailingSource;

impl CollateralSource for FailingSource {
    fn fetch(&self, _: &CollateralRequest) -> Result<Collateral, SourceError> {
        Err("PCCS unreachable".into())
    }
}

#[test]
fn collateral_source_failure_is_reported() {
    let v = DcapVerifier::new(FailingSource).with_options(at(T0));
    assert_eq!(
        v.verify(QUOTE_V3, &fixture_policy()),
        Err(VerifyError::CollateralUnavailable(
            "PCCS unreachable".into()
        ))
    );
}

#[test]
fn real_quote_rejected_under_foreign_anchor() {
    let world = Spec::default().build();
    let r = verify_quote_with_anchor(QUOTE_V3, &recorded_collateral(), &at(T0), &world.anchor);
    assert_eq!(
        r,
        Err(VerifyError::UntrustedRoot {
            what: "PCK certificate chain"
        })
    );
}

// ---------------------------------------------------------------------------
// Synthetic PKI
// ---------------------------------------------------------------------------

const QE_MRSIGNER: [u8; 32] = [0x8c; 32];
const UP: &str = "UpToDate";

#[derive(Clone)]
struct Spec {
    pck_ca_cn: &'static str,
    revoke_leaf: bool,
    revoke_ca: bool,
    revoke_tcb_signer: bool,
    pck_comps: [u8; 16],
    pck_pcesvn: u16,
    fmspc: [u8; 6],
    tcb_info_fmspc: [u8; 6],
    tcb_levels: Vec<([u8; 16], u16, &'static str)>,
    qe_isv_svn: u16,
    qe_flags: u64,
    qe_mr_signer: [u8; 32],
    qe_identity_levels: Vec<(u16, &'static str)>,
    enclave_flags: u64,
    mr_enclave: [u8; 32],
    report_data: [u8; 64],
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            pck_ca_cn: "Intel SGX PCK Processor CA",
            revoke_leaf: false,
            revoke_ca: false,
            revoke_tcb_signer: false,
            pck_comps: [5; 16],
            pck_pcesvn: 13,
            fmspc: [0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00],
            tcb_info_fmspc: [0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00],
            tcb_levels: vec![([5; 16], 13, UP), ([4; 16], 13, "SWHardeningNeeded")],
            qe_isv_svn: 8,
            qe_flags: 0x11,
            qe_mr_signer: QE_MRSIGNER,
            qe_identity_levels: vec![(8, UP), (6, "OutOfDate")],
            enclave_flags: 0x05,
            mr_enclave: [0xe1; 32],
            report_data: [0; 64],
        }
    }
}

struct World {
    quote: Vec<u8>,
    collateral: Collateral,
    anchor: TrustAnchor,
}

fn key(seed: u8) -> (SigningKey, KeyPair) {
    let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
    let kp = KeyPair::try_from(sk.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    (sk, kp)
}

fn params(cn: &str, serial: u8, ca: bool) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.distinguished_name
        .push(DnType::OrganizationName, "Intel Corporation");
    p.serial_number = Some(SerialNumber::from(vec![serial; 20]));
    p.not_before = datetime!(2020-01-01 0:00 UTC);
    p.not_after = datetime!(2040-01-01 0:00 UTC);
    p.key_identifier_method = KeyIdMethod::Sha256;
    if ca {
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    } else {
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    }
    p
}

fn crl(revoked: &[u8], issuer: &rcgen::Issuer<'_, KeyPair>) -> Vec<u8> {
    CertificateRevocationListParams {
        this_update: datetime!(2026-11-01 0:00 UTC),
        next_update: datetime!(2026-12-31 0:00 UTC),
        crl_number: SerialNumber::from(vec![1]),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|&s| RevokedCertParams {
                serial_number: SerialNumber::from(vec![s; 20]),
                revocation_time: datetime!(2026-10-01 0:00 UTC),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .unwrap()
    .der()
    .to_vec()
}

// Minimal DER encoder for the SGX extension.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match value.len() {
        n @ 0..=0x7f => out.push(n as u8),
        n @ 0x80..=0xff => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
    out
}

fn der_uint(v: u32) -> Vec<u8> {
    let mut b: Vec<u8> = v
        .to_be_bytes()
        .into_iter()
        .skip_while(|&b| b == 0)
        .collect();
    if b.first().is_none_or(|&f| f & 0x80 != 0) {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

fn sgx_oid(sub: &[u8]) -> Vec<u8> {
    let mut oid = vec![0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01];
    oid.extend_from_slice(sub);
    tlv(0x06, &oid)
}

fn entry(sub: &[u8], value: Vec<u8>) -> Vec<u8> {
    tlv(0x30, &[sgx_oid(sub), value].concat())
}

fn sgx_extension(spec: &Spec) -> Vec<u8> {
    let mut tcb = Vec::new();
    for (i, svn) in spec.pck_comps.iter().enumerate() {
        tcb.extend(entry(&[2, i as u8 + 1], der_uint(u32::from(*svn))));
    }
    tcb.extend(entry(&[2, 17], der_uint(u32::from(spec.pck_pcesvn))));
    tcb.extend(entry(&[2, 18], tlv(0x04, &spec.pck_comps)));
    let body = [
        entry(&[1], tlv(0x04, &[0xaa; 16])),
        entry(&[2], tlv(0x30, &tcb)),
        entry(&[3], tlv(0x04, &[0, 0])),
        entry(&[4], tlv(0x04, &spec.fmspc)),
        entry(&[5], tlv(0x0a, &[0])),
    ]
    .concat();
    tlv(0x30, &body)
}

fn report_body(
    flags: u64,
    mr_enclave: [u8; 32],
    mr_signer: [u8; 32],
    prod_id: u16,
    svn: u16,
    rd: [u8; 64],
) -> [u8; 384] {
    let mut b = [0u8; 384];
    b[48..56].copy_from_slice(&flags.to_le_bytes());
    b[56..64].copy_from_slice(&0xe7u64.to_le_bytes());
    b[64..96].copy_from_slice(&mr_enclave);
    b[128..160].copy_from_slice(&mr_signer);
    b[256..258].copy_from_slice(&prod_id.to_le_bytes());
    b[258..260].copy_from_slice(&svn.to_le_bytes());
    b[320..384].copy_from_slice(&rd);
    b
}

fn sign_json(body: &str, key: &SigningKey) -> String {
    let sig: Signature = key.sign(body.as_bytes());
    Hex(&sig.to_bytes()).to_string()
}

impl Spec {
    fn build(&self) -> World {
        let (_, root_kp) = key(1);
        let root =
            CertifiedIssuer::self_signed(params("Intel SGX Root CA", 1, true), root_kp).unwrap();
        let (_, ca_kp) = key(2);
        let ca = CertifiedIssuer::signed_by(params(self.pck_ca_cn, 2, true), ca_kp, &root).unwrap();
        let (pck_sk, pck_kp) = key(3);
        let mut leaf_params = params("Intel SGX PCK Certificate", 3, false);
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 2, 840, 113741, 1, 13, 1],
                sgx_extension(self),
            ));
        let leaf = leaf_params.signed_by(&pck_kp, &ca).unwrap();
        let (tcb_sk, tcb_kp) = key(4);
        let tcb_signer = params("Intel SGX TCB Signing", 4, false)
            .signed_by(&tcb_kp, &root)
            .unwrap();

        let mut root_revoked = Vec::new();
        if self.revoke_ca {
            root_revoked.push(2);
        }
        if self.revoke_tcb_signer {
            root_revoked.push(4);
        }
        let pck_revoked: &[u8] = if self.revoke_leaf { &[3, 9] } else { &[9] };

        // Quote.
        let att_sk = SigningKey::from_slice(&[5; 32]).unwrap();
        let att_pub: [u8; 64] = att_sk.verifying_key().to_encoded_point(false).as_bytes()[1..]
            .try_into()
            .unwrap();
        let auth_data = [0x5a; 32];
        let mut qe_rd = [0u8; 64];
        qe_rd[..32].copy_from_slice(
            &Sha256::new()
                .chain_update(att_pub)
                .chain_update(auth_data)
                .finalize(),
        );
        let qe_report = report_body(
            self.qe_flags,
            [0x9e; 32],
            QE_MRSIGNER,
            1,
            self.qe_isv_svn,
            qe_rd,
        );
        let qe_sig: Signature = pck_sk.sign(&qe_report);

        let mut header = [0u8; 48];
        header[0..2].copy_from_slice(&3u16.to_le_bytes());
        header[2..4].copy_from_slice(&2u16.to_le_bytes());
        header[8..10].copy_from_slice(&self.qe_isv_svn.to_le_bytes());
        header[10..12].copy_from_slice(&self.pck_pcesvn.to_le_bytes());
        header[12..28].copy_from_slice(&sgx_ra_core::sgx::quote::INTEL_QE_VENDOR_ID);
        let body = report_body(
            self.enclave_flags,
            self.mr_enclave,
            [0x5e; 32],
            1,
            3,
            self.report_data,
        );
        let signed = [&header[..], &body[..]].concat();
        let quote_sig: Signature = att_sk.sign(&signed);

        let chain_pem = format!("{}{}{}", leaf.pem(), ca.pem(), root.pem());
        let mut sig_data = Vec::new();
        sig_data.extend_from_slice(&quote_sig.to_bytes());
        sig_data.extend_from_slice(&att_pub);
        sig_data.extend_from_slice(&qe_report);
        sig_data.extend_from_slice(&qe_sig.to_bytes());
        sig_data.extend_from_slice(&(auth_data.len() as u16).to_le_bytes());
        sig_data.extend_from_slice(&auth_data);
        sig_data.extend_from_slice(&5u16.to_le_bytes());
        sig_data.extend_from_slice(&(chain_pem.len() as u32).to_le_bytes());
        sig_data.extend_from_slice(chain_pem.as_bytes());
        let mut quote = signed;
        quote.extend_from_slice(&(sig_data.len() as u32).to_le_bytes());
        quote.extend_from_slice(&sig_data);

        // Collateral.
        let levels: Vec<String> = self
            .tcb_levels
            .iter()
            .map(|(comps, pcesvn, status)| {
                let comps: Vec<String> = comps.iter().map(|s| format!("{{\"svn\":{s}}}")).collect();
                format!(
                    "{{\"tcb\":{{\"sgxtcbcomponents\":[{}],\"pcesvn\":{pcesvn}}},\"tcbDate\":\"2025-08-13T00:00:00Z\",\"tcbStatus\":\"{status}\",\"advisoryIDs\":[\"INTEL-SA-00001\"]}}",
                    comps.join(",")
                )
            })
            .collect();
        let tcb_body = format!(
            "{{\"id\":\"SGX\",\"version\":3,\"issueDate\":\"2026-11-20T00:00:00Z\",\"nextUpdate\":\"2026-12-20T00:00:00Z\",\"fmspc\":\"{}\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":20,\"tcbLevels\":[{}]}}",
            Hex(&self.tcb_info_fmspc),
            levels.join(",")
        );
        let tcb_info = format!(
            "{{\"tcbInfo\":{tcb_body},\"signature\":\"{}\"}}",
            sign_json(&tcb_body, &tcb_sk)
        );
        let qe_levels: Vec<String> = self
            .qe_identity_levels
            .iter()
            .map(|(svn, status)| {
                format!(
                    "{{\"tcb\":{{\"isvsvn\":{svn}}},\"tcbDate\":\"2025-08-13T00:00:00Z\",\"tcbStatus\":\"{status}\",\"advisoryIDs\":[\"INTEL-SA-00002\"]}}"
                )
            })
            .collect();
        let qe_body = format!(
            "{{\"id\":\"QE\",\"version\":2,\"issueDate\":\"2026-11-20T00:00:00Z\",\"nextUpdate\":\"2026-12-20T00:00:00Z\",\"tcbEvaluationDataNumber\":20,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"{}\",\"isvprodid\":1,\"tcbLevels\":[{}]}}",
            Hex(&self.qe_mr_signer),
            qe_levels.join(",")
        );
        let qe_identity = format!(
            "{{\"enclaveIdentity\":{qe_body},\"signature\":\"{}\"}}",
            sign_json(&qe_body, &tcb_sk)
        );
        let signer_chain = format!("{}{}", tcb_signer.pem(), root.pem());

        World {
            quote,
            collateral: Collateral {
                root_ca_crl: crl(&root_revoked, &root),
                pck_crl: crl(pck_revoked, &ca),
                tcb_info: tcb_info.into_bytes(),
                tcb_info_issuer_chain: signer_chain.clone().into_bytes(),
                qe_identity: qe_identity.into_bytes(),
                qe_identity_issuer_chain: signer_chain.into_bytes(),
            },
            anchor: TrustAnchor::custom(root.der().to_vec()),
        }
    }
}

impl World {
    fn verify(&self) -> Result<VerifiedQuote, VerifyError> {
        verify_quote_with_anchor(&self.quote, &self.collateral, &at(T0), &self.anchor)
    }

    fn verifier(&self) -> DcapVerifier<StaticCollateral> {
        DcapVerifier::new(StaticCollateral(self.collateral.clone()))
            .with_options(at(T0))
            .with_anchor(self.anchor.clone())
    }
}

fn spec(f: impl FnOnce(&mut Spec)) -> World {
    let mut s = Spec::default();
    f(&mut s);
    s.build()
}

#[test]
fn synthetic_up_to_date_platform_is_accepted() {
    let w = Spec::default().build();
    let v = w.verify().unwrap();
    assert_eq!(v.claims.tcb_status(), TcbStatus::UpToDate);
    assert_eq!(v.pck_ca, PckCa::Processor);
    assert_eq!(
        v.claims.advisory_ids(),
        ["INTEL-SA-00001", "INTEL-SA-00002"]
    );
    let policy = EnclavePolicy::new(Measurement([0xe1; 32]));
    assert!(w.verifier().verify(&w.quote, &policy).is_ok());
    // The same synthetic evidence is worthless under the real Intel root.
    assert_eq!(
        verify_quote(&w.quote, &w.collateral, &at(T0)),
        Err(VerifyError::UntrustedRoot {
            what: "PCK certificate chain"
        })
    );
}

#[test]
fn synthetic_report_data_binds_channel_key() {
    let channel_key = [0x77u8; 32];
    let w = spec(|s| s.report_data = binding::report_data_for(&channel_key).0);
    let claims = w
        .verifier()
        .verify(&w.quote, &EnclavePolicy::new(Measurement([0xe1; 32])))
        .unwrap();
    assert!(binding::check_report_data(&claims.report_data(), &channel_key).is_ok());
    assert!(binding::check_report_data(&claims.report_data(), &[0x78; 32]).is_err());
}

#[test]
fn synthetic_revocation() {
    assert!(matches!(
        spec(|s| s.revoke_leaf = true).verify(),
        Err(VerifyError::Revoked {
            what: "PCK certificate",
            ..
        })
    ));
    assert!(matches!(
        spec(|s| s.revoke_ca = true).verify(),
        Err(VerifyError::Revoked {
            what: "PCK CA certificate",
            ..
        })
    ));
    assert!(matches!(
        spec(|s| s.revoke_tcb_signer = true).verify(),
        Err(VerifyError::Revoked {
            what: "TCB Info issuer chain",
            ..
        })
    ));
}

#[test]
fn synthetic_pck_crl_must_come_from_the_issuing_ca() {
    // Use the Root CA CRL in place of the PCK CRL: wrong issuer.
    let mut w = Spec::default().build();
    w.collateral.pck_crl = w.collateral.root_ca_crl.clone();
    assert!(matches!(
        w.verify(),
        Err(VerifyError::Crl {
            what: "PCK CRL",
            ..
        })
    ));
}

#[test]
fn synthetic_unknown_pck_ca_is_rejected() {
    assert!(matches!(
        spec(|s| s.pck_ca_cn = "Evil PCK CA").verify(),
        Err(VerifyError::Certificate {
            what: "PCK CA certificate",
            ..
        })
    ));
}

#[test]
fn synthetic_tcb_info_must_match_platform() {
    assert!(matches!(
        spec(|s| s.tcb_info_fmspc = [1; 6]).verify(),
        Err(VerifyError::Collateral {
            what: "TCB Info",
            ..
        })
    ));
    // Platform below every TCB level.
    assert_eq!(
        spec(|s| s.pck_comps = [3; 16]).verify(),
        Err(VerifyError::TcbLevelNotFound { what: "platform" })
    );
    // PCE SVN below the level.
    assert_eq!(
        spec(|s| s.pck_pcesvn = 12).verify(),
        Err(VerifyError::TcbLevelNotFound { what: "platform" })
    );
    // One component below the top level selects the next level.
    let v = spec(|s| s.pck_comps[15] = 4).verify().unwrap();
    assert_eq!(v.claims.tcb_status(), TcbStatus::SwHardeningNeeded);
}

#[test]
fn synthetic_revoked_tcb_is_never_accepted() {
    assert_eq!(
        spec(|s| s.tcb_levels = vec![([5; 16], 13, "Revoked")]).verify(),
        Err(VerifyError::TcbRevoked)
    );
    assert_eq!(
        spec(|s| s.qe_identity_levels = vec![(8, "Revoked")]).verify(),
        Err(VerifyError::TcbRevoked)
    );
}

#[test]
fn synthetic_qe_identity_checks() {
    assert_eq!(
        spec(|s| s.qe_mr_signer = [0; 32]).verify(),
        Err(VerifyError::QeIdentityMismatch { field: "MRSIGNER" })
    );
    // DEBUG bit set on the QE (masked attributes compare).
    assert_eq!(
        spec(|s| s.qe_flags = 0x13).verify(),
        Err(VerifyError::QeIdentityMismatch {
            field: "attributes"
        })
    );
    // QE below every level.
    assert_eq!(
        spec(|s| s.qe_isv_svn = 5).verify(),
        Err(VerifyError::TcbLevelNotFound {
            what: "quoting enclave"
        })
    );
    // Out-of-date QE makes the whole TCB out of date.
    let v = spec(|s| s.qe_isv_svn = 7).verify().unwrap();
    assert_eq!(v.qe_tcb_status, TcbStatus::OutOfDate);
    assert_eq!(v.platform_tcb_status, TcbStatus::UpToDate);
    assert_eq!(v.claims.tcb_status(), TcbStatus::OutOfDate);
}

#[test]
fn synthetic_debug_enclave_is_rejected_by_policy() {
    let w = spec(|s| s.enclave_flags = 0x07);
    // Cryptographically fine…
    assert!(w.verify().is_ok());
    // …but no policy accepts it.
    let mut policy = EnclavePolicy::new(Measurement([0xe1; 32]));
    for s in TcbStatus::ALL {
        policy = policy.allow_tcb_status(s);
    }
    assert_eq!(
        w.verifier().verify(&w.quote, &policy),
        Err(VerifyError::Policy(PolicyViolation::DebugEnclave))
    );
}

#[test]
fn debug_enclave_is_rejected_even_by_a_permissive_policy() {
    /// A careless custom policy that accepts everything.
    struct AcceptAll;
    impl sgx_ra_core::attestation::Policy for AcceptAll {
        fn check(&self, _: &sgx_ra_core::VerifiedClaims) -> Result<(), PolicyViolation> {
            Ok(())
        }
    }
    let w = spec(|s| s.enclave_flags = 0x07);
    assert_eq!(
        w.verifier().verify(&w.quote, &AcceptAll),
        Err(VerifyError::Policy(PolicyViolation::DebugEnclave))
    );
    // MODE64BIT clear (32-bit enclave): also rejected before the policy.
    let w = spec(|s| s.enclave_flags = 0x01);
    assert_eq!(
        w.verifier().verify(&w.quote, &AcceptAll),
        Err(VerifyError::Policy(PolicyViolation::NotMode64Bit))
    );
    // The same policy accepts a production enclave.
    let w = spec(|_| {});
    assert!(w.verifier().verify(&w.quote, &AcceptAll).is_ok());
}

#[test]
fn synthetic_unsupported_collateral_versions() {
    let mut w = Spec::default().build();
    let tcb = String::from_utf8(w.collateral.tcb_info.clone()).unwrap();
    // Valid JSON but missing the signature.
    let body_end = tcb.find(",\"signature\"").unwrap();
    w.collateral.tcb_info = format!("{}}}", &tcb[..body_end]).into_bytes();
    assert!(matches!(
        w.verify(),
        Err(VerifyError::Collateral {
            what: "TCB Info",
            ..
        })
    ));
}

#[test]
fn synthetic_freshness_of_crls() {
    let w = Spec::default().build();
    // Synthetic CRLs are valid until 2026-12-31, documents until 2026-12-20.
    let after_docs = OffsetDateTime::parse(
        "2026-12-21T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp();
    assert!(matches!(
        verify_quote_with_anchor(&w.quote, &w.collateral, &at(after_docs), &w.anchor),
        Err(VerifyError::Expired {
            what: "TCB Info",
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// Recorded quote of the public executor (OutOfDateConfigurationNeeded)
// ---------------------------------------------------------------------------

const LIVE_QUOTE: &[u8] = include_bytes!("../../../fixtures/live/quote.dat");

/// 2026-11-24T00:00:00Z: all recorded live collateral is current.
const T_LIVE: i64 = 1_795_478_400;

fn live_collateral() -> Collateral {
    Collateral {
        root_ca_crl: include_bytes!("../../../fixtures/live/root_ca_crl.der").to_vec(),
        pck_crl: include_bytes!("../../../fixtures/live/pck_crl_platform.der").to_vec(),
        tcb_info: include_bytes!("../../../fixtures/live/tcb_info.json").to_vec(),
        tcb_info_issuer_chain: include_bytes!("../../../fixtures/live/tcb_info_issuer_chain.pem")
            .to_vec(),
        qe_identity: include_bytes!("../../../fixtures/live/qe_identity.json").to_vec(),
        qe_identity_issuer_chain: include_bytes!(
            "../../../fixtures/live/qe_identity_issuer_chain.pem"
        )
        .to_vec(),
    }
}

fn live_policy() -> EnclavePolicy {
    let quote = Quote::parse(LIVE_QUOTE).unwrap();
    EnclavePolicy::new(quote.report_body().mr_enclave())
}

fn live_verifier() -> DcapVerifier<StaticCollateral> {
    DcapVerifier::new(StaticCollateral(live_collateral())).with_options(at(T_LIVE))
}

fn ice_lake_policy() -> EnclavePolicy {
    tcb::ICE_LAKE_SP_TCB_STATUSES
        .into_iter()
        .fold(live_policy(), EnclavePolicy::allow_tcb_status)
        .allow_advisories(tcb::ICE_LAKE_SP_ADVISORIES)
}

#[test]
fn live_quote_is_out_of_date_configuration_needed() {
    let v = verify_quote(LIVE_QUOTE, &live_collateral(), &at(T_LIVE)).unwrap();
    assert_eq!(v.pck.fmspc, [0x00, 0x60, 0x6a, 0, 0, 0]);
    assert_eq!(
        v.platform_tcb_status,
        TcbStatus::OutOfDateConfigurationNeeded
    );
    assert_eq!(v.platform_tcb_date, "2024-03-13T00:00:00Z");
    assert_eq!(v.qe_tcb_status, TcbStatus::UpToDate);
    assert_eq!(
        v.claims.tcb_status(),
        TcbStatus::OutOfDateConfigurationNeeded
    );
    let mut ids = v.claims.advisory_ids().to_vec();
    ids.sort();
    assert_eq!(
        ids,
        [
            "INTEL-SA-00615",
            "INTEL-SA-00657",
            "INTEL-SA-00767",
            "INTEL-SA-01079",
            "INTEL-SA-01103",
            "INTEL-SA-01153"
        ]
    );
    let gap = v.platform_tcb_gap.unwrap();
    assert_eq!(gap.best.status, TcbStatus::SwHardeningNeeded);
}

#[test]
fn live_quote_policy() {
    let verifier = live_verifier();
    // UpToDate only (--strict-tcb): rejected.
    assert_eq!(
        verifier.verify(LIVE_QUOTE, &live_policy()),
        Err(VerifyError::Policy(PolicyViolation::TcbStatusNotAllowed(
            TcbStatus::OutOfDateConfigurationNeeded
        )))
    );
    // Statuses and advisories allowlisted: accepted.
    let claims = verifier.verify(LIVE_QUOTE, &ice_lake_policy()).unwrap();
    assert_eq!(claims.tcb_status(), TcbStatus::OutOfDateConfigurationNeeded);
    // The best level reachable on Ice Lake SP only: rejected.
    assert_eq!(
        verifier.verify(
            LIVE_QUOTE,
            &live_policy()
                .allow_tcb_status(TcbStatus::SwHardeningNeeded)
                .allow_advisories(tcb::ICE_LAKE_SP_ADVISORIES)
        ),
        Err(VerifyError::Policy(PolicyViolation::TcbStatusNotAllowed(
            TcbStatus::OutOfDateConfigurationNeeded
        )))
    );
    // Status allowed, but one advisory missing from the allowlist: rejected.
    for missing in tcb::ICE_LAKE_SP_ADVISORIES {
        let policy = live_policy()
            .allow_tcb_status(TcbStatus::OutOfDateConfigurationNeeded)
            .allow_advisories(
                tcb::ICE_LAKE_SP_ADVISORIES
                    .into_iter()
                    .filter(|id| *id != missing),
            );
        assert_eq!(
            verifier.verify(LIVE_QUOTE, &policy),
            Err(VerifyError::Policy(PolicyViolation::AdvisoryNotAllowed {
                status: TcbStatus::OutOfDateConfigurationNeeded,
                advisory_id: missing.into(),
            }))
        );
    }
}

#[test]
fn ice_lake_allowlist_matches_recorded_tcb_info() {
    // Every level from 2024-03-13 up has an allowlisted status and only
    // allowlisted advisories; every older level carries another advisory.
    let chain = pki::pem_certificates(&live_collateral().tcb_info_issuer_chain, "chain").unwrap();
    let signer = pki::Cert::parse(&chain[0], "signer")
        .unwrap()
        .p256_key("signer")
        .unwrap();
    let levels = tcb::TcbInfo::verify_and_parse(&live_collateral().tcb_info, &signer)
        .unwrap()
        .levels;
    let covered = |l: &tcb::TcbLevel| {
        tcb::ICE_LAKE_SP_TCB_STATUSES.contains(&l.status)
            && l.advisory_ids
                .iter()
                .all(|id| tcb::ICE_LAKE_SP_ADVISORIES.contains(&id.as_str()))
    };
    for l in &levels {
        assert_eq!(covered(l), l.tcb_date.as_str() >= "2024-03-13", "{l:?}");
    }
    assert!(levels.iter().any(|l| !covered(l)));
}
