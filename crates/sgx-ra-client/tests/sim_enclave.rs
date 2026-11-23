//! End-to-end test against a real, linked enclave image running in SGX
//! simulation mode behind `enclave-sys/sim/sim_host` (see
//! `enclave-sys/README.md`).
//!
//! Ignored by default because it needs the simulation build. Run with:
//!
//! ```sh
//! SGX_RA_SIM_HOST='docker run --rm -i -v $PWD/target/enclave/echo-enclave-sim:/e \
//!     sgx-playground-server:latest /e/sim_host /e/enclave.signed.so' \
//! SGX_RA_SIM_MRENCLAVE=$(cat target/enclave/echo-enclave-sim/mrenclave.hex) \
//! cargo test -p sgx-ra-client --test sim_enclave -- --ignored
//! ```
//!
//! The simulation host announces the raw report instead of a DCAP quote, so
//! quote verification is replaced by trusting the report body; everything
//! after that (key binding, handshake, records, failure handling) is the
//! production code path on both sides.

use std::fs::File;
use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use sgx_ra_core::attestation::{TcbStatus, VerifiedClaims};
use sgx_ra_core::channel::SecureChannel;
use sgx_ra_core::handshake::{
    self, ClientHandshake, HandshakeError, HelloReply, IdentityKey, MAX_RECORD_PLAINTEXT,
};
use sgx_ra_core::record::RecordError;
use sgx_ra_core::rng::{Rng, RngError};
use sgx_ra_core::session::{ClientChannel, MessageTransport};
use sgx_ra_core::sgx::{Measurement, Report, ReportBody};
use sgx_ra_core::wire::{self, MAX_PAYLOAD};

struct OsRng(File);

impl OsRng {
    fn new() -> Self {
        Self(File::open("/dev/urandom").expect("open /dev/urandom"))
    }
}

impl Rng for OsRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        self.0.read_exact(dst).map_err(|_| RngError { code: 0 })
    }
}

/// Layer-1 framing over the simulation host's stdin/stdout.
struct SimTransport {
    child: Child,
    /// `None` once closed (EOF ends the host's session loop).
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
}

#[derive(Debug)]
enum TransportError {
    Io(io::Error),
    /// The host answered with a failure status byte.
    Status(u8),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Status(s) => write!(f, "host status {s:#04x}"),
        }
    }
}

impl SimTransport {
    /// Starts the host and reads the report announcement.
    fn start() -> (Self, Report) {
        let command = std::env::var("SGX_RA_SIM_HOST").expect("SGX_RA_SIM_HOST is not set");
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn simulation host");
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut len = [0u8; 4];
        stdout.read_exact(&mut len).expect("read announcement");
        let mut report = vec![0u8; u32::from_be_bytes(len) as usize];
        stdout.read_exact(&mut report).expect("read report");
        let report = Report::from_bytes(&report).expect("announcement is a report");
        (
            Self {
                child,
                stdin: Some(stdin),
                stdout,
            },
            report,
        )
    }
}

impl Drop for SimTransport {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

impl MessageTransport for SimTransport {
    type Error = TransportError;

    fn send(&mut self, message: &[u8]) -> Result<(), TransportError> {
        let mut frame = Vec::new();
        wire::encode_request(message, &mut frame).map_err(|e| {
            TransportError::Io(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
        })?;
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(&frame).map_err(TransportError::Io)?;
        stdin.flush().map_err(TransportError::Io)
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut status = [0u8; 1];
        self.stdout
            .read_exact(&mut status)
            .map_err(TransportError::Io)?;
        if status[0] != 0 {
            return Err(TransportError::Status(status[0]));
        }
        let mut len = [0u8; 4];
        self.stdout
            .read_exact(&mut len)
            .map_err(TransportError::Io)?;
        let len = u32::from_be_bytes(len) as usize;
        assert!(len <= MAX_PAYLOAD, "host sent an oversized response");
        let mut payload = vec![0u8; len];
        self.stdout
            .read_exact(&mut payload)
            .map_err(TransportError::Io)?;
        Ok(payload)
    }
}

/// Checks what a verifier's policy would check on the report body.
fn check_body(body: &ReportBody) {
    let attributes = body.attributes();
    assert!(attributes.is_mode64bit());
    assert!(!attributes.is_debug());
    assert_eq!(body.isv_prod_id(), 1, "Enclave.config.xml ProdID");
    assert_eq!(body.isv_svn(), 1, "Enclave.config.xml ISVSVN");
    assert_eq!(&body.report_data().as_bytes()[32..], &[0u8; 32]);
    if let Ok(hex) = std::env::var("SGX_RA_SIM_MRENCLAVE") {
        let expected = Measurement::from_hex(hex.trim()).expect("SGX_RA_SIM_MRENCLAVE");
        assert_eq!(
            body.mr_enclave(),
            expected,
            "MRENCLAVE differs from gendata"
        );
    }
}

#[test]
#[ignore = "needs the SGX simulation build (enclave-sys/sim/build.sh) and SGX_RA_SIM_HOST"]
fn echo_over_attested_channel() {
    let (transport, report) = SimTransport::start();
    let body = report.body();
    check_body(&body);
    let claims = VerifiedClaims::new(body, TcbStatus::UpToDate, Vec::new());
    let mut rng = OsRng::new();
    let mut channel = ClientChannel::connect(transport, claims, &mut rng).expect("handshake");

    assert_eq!(
        channel.request(b"Hello, SGX server!").unwrap(),
        b"Hello, SGX server!"
    );
    let largest: Vec<u8> = (0..MAX_RECORD_PLAINTEXT).map(|i| i as u8).collect();
    assert_eq!(channel.request(&largest).unwrap(), largest);
    for i in 0..50u32 {
        let msg = i.to_be_bytes();
        assert_eq!(channel.request(&msg).unwrap(), msg);
    }
    assert_eq!(channel.request(b"").unwrap(), b"");
}

#[test]
#[ignore = "needs the SGX simulation build (enclave-sys/sim/build.sh) and SGX_RA_SIM_HOST"]
fn tampering_and_replay_end_the_session() {
    let (mut transport, report) = SimTransport::start();
    let body = report.body();
    check_body(&body);
    let claims = VerifiedClaims::new(body, TcbStatus::UpToDate, Vec::new());
    let mut rng = OsRng::new();

    let (handshake, hello) = ClientHandshake::start(&claims, &mut rng).unwrap();
    transport.send(&hello.encode()).unwrap();
    let reply = transport.recv().unwrap();
    let mut session = handshake
        .finish_payload(&reply)
        .expect("key binding + confirm");

    // A good record works.
    let record = session.seal(b"first").unwrap();
    transport.send(&record).unwrap();
    assert_eq!(session.open(&transport.recv().unwrap()).unwrap(), b"first");

    // Replaying it is rejected ...
    transport.send(&record).unwrap();
    assert!(matches!(
        transport.recv(),
        Err(TransportError::Status(0x02))
    ));
    // ... and the enclave has destroyed the session: the next valid record
    // fails too, as does a fresh handshake on this instance.
    let next = session.seal(b"second").unwrap();
    transport.send(&next).unwrap();
    assert!(matches!(
        transport.recv(),
        Err(TransportError::Status(0x02))
    ));
    transport.send(&hello.encode()).unwrap();
    assert!(matches!(
        transport.recv(),
        Err(TransportError::Status(0x02))
    ));
}

#[test]
#[ignore = "needs the SGX simulation build (enclave-sys/sim/build.sh) and SGX_RA_SIM_HOST"]
fn bit_flip_is_rejected() {
    let (mut transport, report) = SimTransport::start();
    let claims = VerifiedClaims::new(report.body(), TcbStatus::UpToDate, Vec::new());
    let mut rng = OsRng::new();
    let (handshake, hello) = ClientHandshake::start(&claims, &mut rng).unwrap();
    transport.send(&hello.encode()).unwrap();
    let mut session = handshake
        .finish_payload(&transport.recv().unwrap())
        .unwrap();
    let mut record = session.seal(b"payload").unwrap();
    let last = record.len() - 1;
    record[last] ^= 1;
    transport.send(&record).unwrap();
    assert!(matches!(
        transport.recv(),
        Err(TransportError::Status(0x02))
    ));
}

#[test]
#[ignore = "needs the SGX simulation build (enclave-sys/sim/build.sh) and SGX_RA_SIM_HOST"]
fn each_instance_has_its_own_key() {
    let (_t1, r1) = SimTransport::start();
    let (_t2, r2) = SimTransport::start();
    assert_eq!(r1.body().mr_enclave(), r2.body().mr_enclave());
    assert_ne!(r1.body().report_data(), r2.body().report_data());
}

#[test]
#[ignore = "needs the SGX simulation build (enclave-sys/sim/build.sh) and SGX_RA_SIM_HOST"]
fn substituted_public_key_fails_report_data_binding() {
    // A man in the middle replaces the enclave's HELLO_REPLY by one for its
    // own key, with a key confirmation that is correct for that key. Only
    // the report_data binding can tell, and it must.
    let (mut transport, report) = SimTransport::start();
    let body = report.body();
    let claims = VerifiedClaims::new(body, TcbStatus::UpToDate, Vec::new());
    let mut rng = OsRng::new();
    let (client, hello) = ClientHandshake::start(&claims, &mut rng).unwrap();
    transport.send(&hello.encode()).unwrap();
    let genuine = HelloReply::decode(&transport.recv().unwrap()).unwrap();

    let attacker = IdentityKey::generate(&mut rng).unwrap();
    let mut raw = *body.as_bytes();
    raw[320..].copy_from_slice(attacker.report_data().as_bytes());
    let (forged, _) =
        handshake::respond(&attacker, &ReportBody::from_array(raw), &hello, &mut rng).unwrap();
    assert_ne!(forged.identity_public, genuine.identity_public);
    assert!(matches!(
        client.finish(&forged),
        Err(HandshakeError::Binding(_))
    ));

    // Swapping only the key (keeping the enclave's confirmation) fails the
    // same check.
    let (client, _) = ClientHandshake::start(&claims, &mut rng).unwrap();
    let mut swapped = genuine;
    swapped.identity_public = *attacker.public_key();
    assert!(matches!(
        client.finish(&swapped),
        Err(HandshakeError::Binding(_))
    ));
}

#[test]
#[ignore = "needs the SGX simulation build (enclave-sys/sim/build.sh) and SGX_RA_SIM_HOST"]
fn tampered_enclave_record_fails_decryption() {
    let (mut transport, report) = SimTransport::start();
    let claims = VerifiedClaims::new(report.body(), TcbStatus::UpToDate, Vec::new());
    let mut rng = OsRng::new();
    let (handshake, hello) = ClientHandshake::start(&claims, &mut rng).unwrap();
    transport.send(&hello.encode()).unwrap();
    let mut session = handshake
        .finish_payload(&transport.recv().unwrap())
        .unwrap();

    // The enclave answers a valid request; the host flips one ciphertext
    // bit of the reply on its way back.
    transport.send(&session.seal(b"secret").unwrap()).unwrap();
    let mut reply = transport.recv().unwrap();
    assert!(
        !reply.windows(6).any(|w| w == b"secret"),
        "reply is not encrypted"
    );
    reply[handshake::RECORD_HEADER_LEN] ^= 0x01;
    assert_eq!(session.open(&reply), Err(RecordError::Decryption));
    // The client wiped the session: nothing more is accepted or sent.
    reply[handshake::RECORD_HEADER_LEN] ^= 0x01;
    assert_eq!(session.open(&reply), Err(RecordError::SessionFailed));
    assert_eq!(session.seal(b"more"), Err(RecordError::SessionFailed));
}
