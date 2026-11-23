//! Runs the `echo-client` binary against in-process stand-ins: an executor
//! host on 127.0.0.1 (plain TCP, `--plaintext`) and, where needed, a mock
//! PCCS serving the recorded Intel collateral.
//!
//! A complete success needs a real SGX quote binding a key we can talk to,
//! so it cannot run here; the success path of the flow is covered by
//! `crates/sgx-ra-client/tests/attested_channel.rs`. These tests check the
//! CLI's reporting and that every failure exits non-zero.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use sgx_ra_client::OsRng;
use sgx_ra_client::sgx_ra_core::handshake::IdentityKey;
use sgx_ra_client::sgx_ra_core::session::EnclaveEndpoint;
use sgx_ra_client::sgx_ra_core::sgx::{Quote, ReportBody};
use sgx_ra_client::sgx_ra_core::wire::{self, Decoded, Response, Status};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures");
const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");
const QUOTE_MRENCLAVE: &str = "e413a4ed616c7a79634d5ca05a2fda746a1f0c71349a80b25a02828846fab90e";
/// nextUpdate of the recorded PCK CRL (2026-12-22T21:33:19Z), the first
/// recorded collateral to expire. After it, live-time verification of the
/// recorded quote must fail, so the tests that need it are skipped.
const COLLATERAL_EXPIRY: u64 = 1_797_975_199;

fn echo_client(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_echo-client"))
        .args(args)
        .output()
        .expect("run echo-client")
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// A one-connection executor: announces `quote`, then answers requests
/// with an `EnclaveEndpoint` whose report commits to its own fresh key
/// (which the announced quote does not).
fn executor(quote: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut frame = Vec::new();
        wire::encode_quote(quote, &mut frame).unwrap();
        if stream.write_all(&frame).is_err() {
            return;
        }
        let identity = IdentityKey::generate(&mut OsRng).unwrap();
        let mut raw = *Quote::parse(QUOTE_V3).unwrap().report_body().as_bytes();
        raw[320..].copy_from_slice(identity.report_data().as_bytes());
        let mut endpoint = EnclaveEndpoint::new(identity);
        endpoint.set_report_body(ReportBody::from_array(raw));
        while let Some(request) = read_request(&mut stream) {
            let response =
                match endpoint.handle(&request, &mut OsRng, |req: &[u8], resp: &mut Vec<u8>| {
                    resp.extend_from_slice(req);
                    Ok::<(), ()>(())
                }) {
                    Ok(payload) => Response::Ok(payload),
                    Err(_) => Response::Failure(Status::EnclaveCommunicationFailure),
                };
            let mut out = Vec::new();
            wire::encode_response(&response, &mut out).unwrap();
            if stream.write_all(&out).is_err() {
                return;
            }
        }
    });
    port
}

fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        match wire::decode_request(&buf).ok()? {
            Decoded::Complete { value, .. } => return Some(value),
            Decoded::Incomplete { needed } => {
                let start = buf.len();
                buf.resize(start + needed, 0);
                stream.read_exact(&mut buf[start..]).ok()?;
            }
        }
    }
}

/// A host that sends raw bytes and closes.
fn raw_host(bytes: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(bytes);
        }
    });
    port
}

/// A mock PCCS (v4 API) serving the recorded collateral for `quote_v3.dat`.
fn pccs() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let read = |name: &str| std::fs::read(format!("{FIXTURES}/dcap/{name}")).unwrap();
    let root_crl_hex: String = read("root_ca_crl.der")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let pck_crl = read("pck_crl_platform.der");
    let tcb_info = read("tcb_info.json");
    let tcb_chain = read("tcb_info_issuer_chain.pem");
    let qe_identity = read("qe_identity.json");
    let qe_chain = read("qe_identity_issuer_chain.pem");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            let _ = reader.read_line(&mut request_line);
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                    break;
                }
            }
            let target = request_line.split_whitespace().nth(1).unwrap_or("");
            let (body, header): (Vec<u8>, Option<(&str, &[u8])>) = match target {
                "/sgx/certification/v4/rootcacrl" => (root_crl_hex.clone().into_bytes(), None),
                "/sgx/certification/v4/pckcrl?ca=platform&encoding=der" => (pck_crl.clone(), None),
                "/sgx/certification/v4/tcb?fmspc=30606a000000" => (
                    tcb_info.clone(),
                    Some(("TCB-Info-Issuer-Chain", &tcb_chain)),
                ),
                "/sgx/certification/v4/qe/identity" => (
                    qe_identity.clone(),
                    Some(("SGX-Enclave-Identity-Issuer-Chain", &qe_chain)),
                ),
                _ => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                }
            };
            let mut resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            if let Some((name, value)) = header {
                let encoded: String = value
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                            (b as char).to_string()
                        } else {
                            format!("%{b:02X}")
                        }
                    })
                    .collect();
                resp.push_str(&format!("{name}: {encoded}\r\n"));
            }
            resp.push_str("\r\n");
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    url
}

fn collateral_still_valid() -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now >= COLLATERAL_EXPIRY {
        eprintln!("skipped: the recorded collateral expired (re-record fixtures/dcap)");
        return false;
    }
    true
}

#[test]
fn remote_diagnostic_exits_with_unavailable() {
    let port = raw_host(include_bytes!(
        "../../../fixtures/remote_pccs_error_session.bin"
    ));
    let out = echo_client(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--plaintext",
        "--expected-mrenclave",
        QUOTE_MRENCLAVE,
    ]);
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(3), "{stdout}\n{stderr}");
    assert!(stdout.contains("[OK] Expected MRENCLAVE (pinned on the command line)"));
    assert!(stdout.contains("[OK] Connected to 127.0.0.1"));
    assert!(
        stderr.contains("[FAIL] No quote received: remote attestation infrastructure unavailable")
    );
    assert!(stderr.contains("Error in sgx_qe_get_target_info"));
}

#[test]
fn mrenclave_mismatch_with_gendata_fails_before_collateral() {
    // The blueprint enclave's gendata vs the recorded quote of another
    // enclave. The collateral service URL is unreachable on purpose: the
    // mismatch must be reported without contacting it.
    let port = executor(QUOTE_V3);
    let out = echo_client(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--plaintext",
        "--gendata-path",
        &format!("{FIXTURES}/blueprint_enclave.so.gendata"),
        "--pccs-url",
        "http://127.0.0.1:9",
    ]);
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stdout.contains(
        "blueprint_enclave.so.gendata: ed92b9ba8521bec3c3b2eacdf67846d275dd655965280028e05bf1a5f318434c"
    ));
    assert!(stdout.contains("[OK] Received quote (4734 bytes)"));
    assert!(stdout.contains("[OK] Quote structure valid: DCAP v3"));
    assert!(stderr.contains("[FAIL] MRENCLAVE mismatch"));
    assert!(stderr.contains("expected (local build) ed92b9ba"));
    assert!(stderr.contains(&format!("remote quote          {QUOTE_MRENCLAVE}")));
}

#[test]
fn unreachable_collateral_service_fails() {
    let port = executor(QUOTE_V3);
    let out = echo_client(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--plaintext",
        "--expected-mrenclave",
        QUOTE_MRENCLAVE,
        "--pccs-url",
        "http://127.0.0.1:9",
    ]);
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(
        stderr.contains("[FAIL] Quote verification failed"),
        "{stderr}"
    );
    assert!(!stdout.contains("PCK certificate chain verified"));
}

#[test]
fn verified_quote_out_of_date_platform_is_rejected_by_default() {
    if !collateral_still_valid() {
        return;
    }
    let url = pccs();
    let port = executor(QUOTE_V3);
    let out = echo_client(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--plaintext",
        "--expected-mrenclave",
        QUOTE_MRENCLAVE,
        "--pccs-url",
        &url,
    ]);
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(
        stderr.contains(
            "[FAIL] Policy rejected the enclave: platform TCB status OutOfDate is not allowed"
        ),
        "{stderr}"
    );
}

#[test]
fn verified_quote_without_key_binding_is_rejected() {
    if !collateral_still_valid() {
        return;
    }
    // Genuine quote, accepted by an explicitly relaxed policy, but its
    // report_data binds no key: the handshake must fail.
    let url = pccs();
    let port = executor(QUOTE_V3);
    let out = echo_client(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--plaintext",
        "--expected-mrenclave",
        QUOTE_MRENCLAVE,
        "--pccs-url",
        &url,
        "--allow-tcb-status",
        "OutOfDate",
        "--isv-prod-id",
        "1",
        "--min-isv-svn",
        "10",
        "--mrsigner",
        "ac2c9fa87e4c91768b1d0c47169466c50d5a98c790639fbaefe7352a59919980",
    ]);
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    for line in [
        "[OK] PCK certificate chain verified up to the pinned Intel SGX Root CA",
        "[OK] TCB Info (FMSPC 30606a000000) and QE Identity signed by Intel SGX TCB Signing",
        "[OK] Quoting enclave report signed by the PCK key",
        "[OK] Quote signature over header and enclave report verified",
        "[OK] Platform TCB status OutOfDate",
        "[OK] Enclave is not in debug mode",
        &format!("[OK] Remote MRENCLAVE {QUOTE_MRENCLAVE} is identical to the local build"),
        "[OK] MRSIGNER ac2c9fa8",
        "[OK] ISVPRODID 1 = 1",
        "[OK] ISVSVN 10 >= 10",
    ] {
        assert!(stdout.contains(line), "missing {line:?} in\n{stdout}");
    }
    assert!(!stdout.contains("Handshake complete"));
    assert!(
        stderr.contains(
            "[FAIL] The enclave's channel key is NOT the key bound in the attested report_data"
        ),
        "{stderr}"
    );
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &["--expected-mrenclave", "xyz"][..],
        &["--allow-tcb-status", "Revoked"],
        &["--insecure-tls", "--plaintext"],
    ] {
        assert_eq!(echo_client(args).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn missing_dockerfile_is_reported() {
    let out = echo_client(&[
        "--dockerfile",
        "/nonexistent/Dockerfile",
        "--container-engine",
        "docker",
    ]);
    let (_, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr.contains("[FAIL] Dockerfile /nonexistent/Dockerfile not found"),
        "{stderr}"
    );
}

#[test]
fn inspect_subcommands() {
    let out = echo_client(&[
        "inspect-quote",
        &format!("{FIXTURES}/quote_v3.dat"),
        "--expect-mrenclave",
        QUOTE_MRENCLAVE,
    ]);
    let (stdout, _) = text(&out);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("mr_enclave check  matches"));
    let out = echo_client(&[
        "inspect-gendata",
        &format!("{FIXTURES}/blueprint_enclave.so.gendata"),
    ]);
    assert!(out.status.success());
    assert!(
        text(&out)
            .0
            .contains("ed92b9ba8521bec3c3b2eacdf67846d275dd655965280028e05bf1a5f318434c")
    );
}
