//! Collateral retrieval + DCAP verification of the recorded quote.
//!
//! * A mock PCCS on 127.0.0.1 serves the recorded Intel collateral the way
//!   PCCS v4 does (hex-encoded Root CA CRL, URL-encoded issuer-chain
//!   headers). Verification runs at a fixed time.
//! * `live_intel_pcs` (ignored by default, needs Internet) fetches fresh
//!   collateral from Intel PCS and verifies at the current time:
//!   `cargo test -p sgx-ra-client --test pccs_collateral -- --ignored`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use sgx_ra_client::sgx_ra_core::attestation::{
    EnclavePolicy, PolicyViolation, TcbStatus, Verifier,
};
use sgx_ra_client::sgx_ra_core::sgx::Measurement;
use sgx_ra_client::{PccsConfig, VerifierOptions, VerifyError, dcap_verifier};

const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");
const ROOT_CA_CRL: &[u8] = include_bytes!("../../../fixtures/dcap/root_ca_crl.der");
const PCK_CRL: &[u8] = include_bytes!("../../../fixtures/dcap/pck_crl_platform.der");
const TCB_INFO: &[u8] = include_bytes!("../../../fixtures/dcap/tcb_info.json");
const TCB_CHAIN: &[u8] = include_bytes!("../../../fixtures/dcap/tcb_info_issuer_chain.pem");
const QE_IDENTITY: &[u8] = include_bytes!("../../../fixtures/dcap/qe_identity.json");
const QE_CHAIN: &[u8] = include_bytes!("../../../fixtures/dcap/qe_identity_issuer_chain.pem");

/// 2026-11-23T00:00:00Z
const T0: i64 = 1_795_392_000;
const MRENCLAVE: &str = "e413a4ed616c7a79634d5ca05a2fda746a1f0c71349a80b25a02828846fab90e";

fn policy() -> EnclavePolicy {
    EnclavePolicy::new(Measurement::from_hex(MRENCLAVE).unwrap())
}

fn url_encode(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Status, optional issuer-chain header, body.
type Response = (u16, Option<(&'static str, &'static [u8])>, Vec<u8>);

#[derive(Clone, Default)]
struct Mock {
    tcb_info: Option<Vec<u8>>,
    omit_tcb_header: bool,
    qe_identity_status: Option<u16>,
}

/// Serves one PCCS per test; returns its base URL and the request log.
fn serve(mock: Mock) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                    break;
                }
            }
            let target = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_owned();
            log2.lock().unwrap().push(target.clone());

            let tcb_info = mock.tcb_info.clone().unwrap_or_else(|| TCB_INFO.to_vec());
            let (status, header, body): Response = match target.as_str() {
                "/sgx/certification/v4/rootcacrl" => (200, None, hex(ROOT_CA_CRL).into_bytes()),
                "/sgx/certification/v4/pckcrl?ca=platform&encoding=der" => {
                    (200, None, PCK_CRL.to_vec())
                }
                "/sgx/certification/v4/tcb?fmspc=30606a000000" => (
                    200,
                    (!mock.omit_tcb_header).then_some(("TCB-Info-Issuer-Chain", TCB_CHAIN)),
                    tcb_info,
                ),
                "/sgx/certification/v4/qe/identity" => (
                    mock.qe_identity_status.unwrap_or(200),
                    Some(("SGX-Enclave-Identity-Issuer-Chain", QE_CHAIN)),
                    QE_IDENTITY.to_vec(),
                ),
                _ => (404, None, b"not found".to_vec()),
            };
            let mut resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            if let Some((name, value)) = header {
                resp.push_str(&format!("{name}: {}\r\n", url_encode(value)));
            }
            resp.push_str("\r\n");
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    (url, log)
}

fn options() -> VerifierOptions {
    VerifierOptions {
        fixed_time: Some(T0),
        ..VerifierOptions::default()
    }
}

#[test]
fn verifies_recorded_quote_with_mock_pccs() {
    let (url, log) = serve(Mock::default());
    let verifier = dcap_verifier(PccsConfig::pccs(&url), options()).unwrap();

    // Default policy: the platform is OutOfDate.
    assert_eq!(
        verifier.verify(QUOTE_V3, &policy()),
        Err(VerifyError::Policy(PolicyViolation::TcbStatusNotAllowed(
            TcbStatus::OutOfDate
        )))
    );
    let claims = verifier
        .verify(QUOTE_V3, &policy().allow_tcb_status(TcbStatus::OutOfDate))
        .unwrap();
    assert_eq!(claims.identity().mr_enclave.to_string(), MRENCLAVE);

    let log = log.lock().unwrap();
    assert_eq!(
        log[..4],
        [
            "/sgx/certification/v4/rootcacrl",
            "/sgx/certification/v4/pckcrl?ca=platform&encoding=der",
            "/sgx/certification/v4/tcb?fmspc=30606a000000",
            "/sgx/certification/v4/qe/identity",
        ]
    );
}

#[test]
fn rejects_tampered_collateral_from_pccs() {
    let forged = String::from_utf8(TCB_INFO.to_vec())
        .unwrap()
        .replace("\"OutOfDate\"", "\"UpToDate\"");
    let (url, _) = serve(Mock {
        tcb_info: Some(forged.into_bytes()),
        ..Mock::default()
    });
    let verifier = dcap_verifier(PccsConfig::pccs(url), options()).unwrap();
    assert_eq!(
        verifier.verify(QUOTE_V3, &policy().allow_tcb_status(TcbStatus::OutOfDate)),
        Err(VerifyError::BadSignature { what: "TCB Info" })
    );
}

#[test]
fn reports_unavailable_collateral() {
    let (url, _) = serve(Mock {
        qe_identity_status: Some(404),
        ..Mock::default()
    });
    let verifier = dcap_verifier(PccsConfig::pccs(url), options()).unwrap();
    let err = verifier.verify(QUOTE_V3, &policy()).unwrap_err();
    assert!(
        matches!(&err, VerifyError::CollateralUnavailable(m) if m.contains("qe/identity")),
        "{err}"
    );

    let (url, _) = serve(Mock {
        omit_tcb_header: true,
        ..Mock::default()
    });
    let verifier = dcap_verifier(PccsConfig::pccs(url), options()).unwrap();
    let err = verifier.verify(QUOTE_V3, &policy()).unwrap_err();
    assert!(
        matches!(&err, VerifyError::CollateralUnavailable(m) if m.contains("TCB-Info-Issuer-Chain")),
        "{err}"
    );

    // Nothing listening.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let verifier = dcap_verifier(
        PccsConfig::pccs(format!("http://127.0.0.1:{port}")),
        options(),
    )
    .unwrap();
    assert!(matches!(
        verifier.verify(QUOTE_V3, &policy()),
        Err(VerifyError::CollateralUnavailable(_))
    ));
}

#[test]
#[ignore = "needs Internet access to Intel PCS"]
fn live_intel_pcs() {
    let verifier = dcap_verifier(PccsConfig::intel_pcs(), VerifierOptions::default()).unwrap();
    let mut lenient = policy();
    for s in TcbStatus::ALL {
        lenient = lenient.allow_tcb_status(s);
    }
    let verified = verifier.verify_detailed(QUOTE_V3, &lenient).unwrap();
    eprintln!(
        "Intel PCS: platform {} / QE {} → {} (TCB evaluation data number {}, {} advisories)",
        verified.platform_tcb_status,
        verified.qe_tcb_status,
        verified.claims.tcb_status(),
        verified.tcb_evaluation_data_number,
        verified.claims.advisory_ids().len()
    );
}
