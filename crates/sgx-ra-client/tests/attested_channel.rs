//! The client flow (`attest_and_connect` / `EnclaveChannel`) against an
//! in-process host on 127.0.0.1 that speaks the executor protocol and runs
//! the real enclave-side state machine (`EnclaveEndpoint`).
//!
//! No SGX hardware is involved, so evidence is either a bare report body
//! accepted by a stand-in verifier (exercising everything after quote
//! verification), or the recorded DCAP quote verified for real by
//! `DcapVerifier` against recorded collateral at a fixed time.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

use sgx_ra_client::sgx_ra_core::attestation::{
    EnclavePolicy, Policy, PolicyViolation, TcbStatus, VerifiedClaims, Verifier,
};
use sgx_ra_client::sgx_ra_core::binding::BindingError;
use sgx_ra_client::sgx_ra_core::channel::{AttestedChannel, SecureChannel};
use sgx_ra_client::sgx_ra_core::handshake::{HandshakeError, IdentityKey, MAX_RECORD_PLAINTEXT};
use sgx_ra_client::sgx_ra_core::session::{ChannelError, EnclaveEndpoint};
use sgx_ra_client::sgx_ra_core::sgx::{Measurement, Quote, ReportBody};
use sgx_ra_client::sgx_ra_core::wire::{self, Decoded, Response, Status};
use sgx_ra_client::sgx_ra_verifier::collateral::{Collateral, StaticCollateral};
use sgx_ra_client::{
    ConnectError, DcapVerifier, ExecutorError, OsRng, VerifierOptions, VerifyError,
    attest_and_connect,
};

const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");
/// 2026-11-23T00:00:00Z, inside the validity of the recorded collateral.
const T0: i64 = 1_795_392_000;
const REPORT_DATA_OFFSET: usize = 320;

/// The fixture's report body with report_data committing to `identity`.
fn body_for(identity: &IdentityKey) -> ReportBody {
    let mut raw = *Quote::parse(QUOTE_V3).unwrap().report_body().as_bytes();
    raw[REPORT_DATA_OFFSET..].copy_from_slice(identity.report_data().as_bytes());
    ReportBody::from_array(raw)
}

/// Stand-in verifier: the evidence *is* a report body (as in SGX
/// simulation mode). Applies the policy like the real verifier.
struct TrustReportBody;

impl Verifier for TrustReportBody {
    type Error = PolicyViolation;

    fn verify(&self, evidence: &[u8], policy: &dyn Policy) -> Result<VerifiedClaims, Self::Error> {
        let body = ReportBody::from_bytes(evidence).expect("report body evidence");
        let claims = VerifiedClaims::new(body, TcbStatus::UpToDate, Vec::new());
        policy.check(&claims)?;
        Ok(claims)
    }
}

/// Host behaviour: what to announce and which body the enclave holds.
struct HostSpec {
    announce: Vec<u8>,
    identity: IdentityKey,
    enclave_body: ReportBody,
}

/// Serves exactly one connection like the executor would: quote frame,
/// then request/response lockstep through `EnclaveEndpoint` (echo app).
fn serve(spec: HostSpec) -> (u16, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut frame = Vec::new();
        wire::encode_quote(&spec.announce, &mut frame).unwrap();
        stream.write_all(&frame).unwrap();

        let mut endpoint = EnclaveEndpoint::new(spec.identity);
        endpoint.set_report_body(spec.enclave_body);
        let mut statuses = Vec::new();
        while let Some(request) = read_request(&mut stream) {
            let reply = endpoint.handle(&request, &mut OsRng, |req: &[u8], resp: &mut Vec<u8>| {
                resp.extend_from_slice(req);
                Ok::<(), &str>(())
            });
            let response = match reply {
                Ok(payload) => Response::Ok(payload),
                Err(_) => Response::Failure(Status::EnclaveCommunicationFailure),
            };
            statuses.push(matches!(response, Response::Ok(_)) as u8);
            let mut out = Vec::new();
            wire::encode_response(&response, &mut out).unwrap();
            if stream.write_all(&out).is_err() {
                break;
            }
        }
        statuses
    });
    (port, handle)
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

fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).unwrap()
}

#[test]
fn echo_over_attested_channel() {
    let identity = IdentityKey::generate(&mut OsRng).unwrap();
    let public = *identity.public_key();
    let body = body_for(&identity);
    let (port, host) = serve(HostSpec {
        announce: body.as_bytes().to_vec(),
        identity,
        enclave_body: body,
    });

    let policy = EnclavePolicy::new(body.mr_enclave());
    let mut channel =
        attest_and_connect(connect(port), &TrustReportBody, &policy, &mut OsRng).unwrap();
    assert_eq!(channel.enclave_public_key(), &public);
    assert_eq!(
        channel.peer_claims().identity().mr_enclave,
        body.mr_enclave()
    );

    assert_eq!(
        channel.request(b"Hello, SGX server!").unwrap(),
        b"Hello, SGX server!"
    );
    let largest = vec![0xa5; MAX_RECORD_PLAINTEXT];
    assert_eq!(channel.request(&largest).unwrap(), largest);
    assert_eq!(channel.request(b"").unwrap(), b"");
    // Too large for one record: refused locally, channel still usable.
    assert!(channel.send(&vec![0; MAX_RECORD_PLAINTEXT + 1]).is_err());
    drop(channel);
    assert!(host.join().unwrap().iter().all(|&ok| ok == 1));
}

#[test]
fn policy_mismatch_stops_before_the_handshake() {
    let identity = IdentityKey::generate(&mut OsRng).unwrap();
    let body = body_for(&identity);
    let (port, host) = serve(HostSpec {
        announce: body.as_bytes().to_vec(),
        identity,
        enclave_body: body,
    });
    let policy = EnclavePolicy::new(Measurement([0x11; 32]));
    let err = attest_and_connect(connect(port), &TrustReportBody, &policy, &mut OsRng).unwrap_err();
    assert!(matches!(
        err,
        ConnectError::Verification(PolicyViolation::MrEnclaveMismatch { .. })
    ));
    // The client sent nothing after the quote.
    assert!(host.join().unwrap().is_empty());
}

#[test]
fn key_not_bound_to_the_attested_report_is_rejected() {
    // The host announces a report for one key but the enclave answering
    // the handshake holds another (a relay / key substitution attack).
    let attested = IdentityKey::generate(&mut OsRng).unwrap();
    let impostor = IdentityKey::generate(&mut OsRng).unwrap();
    let attested_body = body_for(&attested);
    let (port, _host) = serve(HostSpec {
        announce: attested_body.as_bytes().to_vec(),
        enclave_body: body_for(&impostor),
        identity: impostor,
    });
    let policy = EnclavePolicy::new(attested_body.mr_enclave());
    let err = attest_and_connect(connect(port), &TrustReportBody, &policy, &mut OsRng).unwrap_err();
    assert!(
        matches!(
            err,
            ConnectError::Channel(ChannelError::Handshake(HandshakeError::Binding(
                BindingError
            )))
        ),
        "{err}"
    );
}

#[test]
fn enclave_failure_status_is_fatal() {
    // The enclave's report does not commit to its key, so it refuses the
    // HELLO (status 0x02); the client must not fall back to anything.
    let identity = IdentityKey::generate(&mut OsRng).unwrap();
    let other = IdentityKey::generate(&mut OsRng).unwrap();
    let body = body_for(&identity);
    let (port, _host) = serve(HostSpec {
        announce: body.as_bytes().to_vec(),
        identity,
        enclave_body: body_for(&other),
    });
    let policy = EnclavePolicy::new(body.mr_enclave());
    let err = attest_and_connect(connect(port), &TrustReportBody, &policy, &mut OsRng).unwrap_err();
    assert!(
        matches!(
            err,
            ConnectError::Channel(ChannelError::Transport(ExecutorError::Status(
                Status::EnclaveCommunicationFailure
            )))
        ),
        "{err}"
    );
}

fn recorded_collateral() -> Collateral {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/dcap/");
    let read = |name: &str| std::fs::read(format!("{dir}{name}")).unwrap();
    Collateral {
        root_ca_crl: read("root_ca_crl.der"),
        pck_crl: read("pck_crl_platform.der"),
        tcb_info: read("tcb_info.json"),
        tcb_info_issuer_chain: read("tcb_info_issuer_chain.pem"),
        qe_identity: read("qe_identity.json"),
        qe_identity_issuer_chain: read("qe_identity_issuer_chain.pem"),
    }
}

#[test]
fn real_dcap_quote_without_key_binding_is_rejected() {
    // The recorded quote is genuine, but its report_data is all zero (the
    // blueprint enclave binds no key). DCAP verification and policy pass;
    // the handshake must still refuse whatever key the host presents.
    let quote = Quote::parse(QUOTE_V3).unwrap();
    let mr_enclave = quote.report_body().mr_enclave();
    let identity = IdentityKey::generate(&mut OsRng).unwrap();
    let (port, _host) = serve(HostSpec {
        announce: QUOTE_V3.to_vec(),
        enclave_body: body_for(&identity),
        identity,
    });
    let verifier =
        DcapVerifier::new(StaticCollateral(recorded_collateral())).with_options(VerifierOptions {
            fixed_time: Some(T0),
            ..VerifierOptions::default()
        });
    // The recorded platform is OutOfDate; the default policy refuses it.
    let strict = EnclavePolicy::new(mr_enclave);
    assert!(matches!(
        verifier.verify(QUOTE_V3, &strict),
        Err(VerifyError::Policy(PolicyViolation::TcbStatusNotAllowed(
            TcbStatus::OutOfDate
        )))
    ));
    let policy = strict.allow_tcb_status(TcbStatus::OutOfDate);
    let err = attest_and_connect(connect(port), &verifier, &policy, &mut OsRng).unwrap_err();
    assert!(
        matches!(
            err,
            ConnectError::Channel(ChannelError::Handshake(HandshakeError::Binding(
                BindingError
            )))
        ),
        "{err}"
    );
}

#[test]
fn remote_diagnostic_is_reported_as_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(include_bytes!(
            "../../../fixtures/remote_pccs_error_session.bin"
        ))
        .unwrap();
    });
    let policy = EnclavePolicy::new(Measurement([0; 32]));
    match attest_and_connect(connect(port), &TrustReportBody, &policy, &mut OsRng) {
        Err(ConnectError::Executor(e)) => assert!(e.is_infrastructure_unavailable(), "{e}"),
        other => panic!("{other:?}"),
    }
}
