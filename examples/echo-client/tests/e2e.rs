//! End-to-end tests of the `echo-client` binary against a real executor:
//! the public one (`sgx-playground.blechschmidt.io:443`, the default) or a
//! local SGX host (`docker compose --profile local-sgx up host-app`, or
//! `echo-host-app --listen` behind stunnel).
//!
//! All tests are ignored by default because they need Docker (the
//! reproducible build) and, for the `live_*` tests, an executor that
//! returns a genuine DCAP quote. `scripts/e2e.sh` runs them with the right
//! environment; by hand:
//!
//! ```sh
//! SGX_RA_E2E_GENDATA=target/nix-enclave/enclave/enclave.so.gendata \
//! cargo test -p echo-client --test e2e -- --ignored --test-threads 1
//! ```
//!
//! | variable | default | meaning |
//! |---|---|---|
//! | `SGX_RA_E2E_HOST` / `SGX_RA_E2E_PORT` | `sgx-playground.blechschmidt.io` / `443` | executor |
//! | `SGX_RA_E2E_TRANSPORT` | `insecure-tls` | `tls`, `insecure-tls` or `plaintext` |
//! | `SGX_RA_E2E_TLS_CA` | – | CA PEM for `tls` |
//! | `SGX_RA_E2E_GENDATA` | – | gendata of the local build; otherwise the client builds |
//! | `SGX_RA_E2E_PCCS_URL` / `SGX_RA_E2E_PCCS_CA` | Intel PCS | collateral service |
//! | `SGX_RA_E2E_ALLOW_TCB` | – | comma-separated extra allowed TCB statuses |
//!
//! Relative paths are relative to the repository root.
//!
//! A `live_*` test whose executor sends a DCAP error text instead of a
//! quote (client exit code 3) fails with a message starting `BLOCKED:`:
//! nothing was verified, so it must not pass.
//!
//! The negative tests put a man-in-the-middle proxy ([`Mitm`]) between the
//! client and the executor. It stands for the untrusted host or network:
//! it sees and can rewrite every byte of layer 1, but holds no enclave key.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sgx_ra_client::sgx_ra_core::attestation::{TcbStatus, VerifiedClaims};
use sgx_ra_client::sgx_ra_core::channel::SecureChannel;
use sgx_ra_client::sgx_ra_core::handshake::{
    self, HandshakeError, Hello, HelloReply, IdentityKey, MessageType,
};
use sgx_ra_client::sgx_ra_core::record::RecordError;
use sgx_ra_client::sgx_ra_core::session::{ChannelError, EnclaveEndpoint};
use sgx_ra_client::sgx_ra_core::sgx::{Quote, ReportBody};
use sgx_ra_client::sgx_ra_core::wire::{self, Decoded, MAX_QUOTE_LEN, Response, Status};
use sgx_ra_client::transport::{self, TlsVerification};
use sgx_ra_client::{
    ContainerEngine, EnclaveChannel, ExecutorConnection, ExecutorError, GendataFile, OsRng,
    ReproducibleBuild,
};

const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const DOCKERFILE: &str = "containers/Dockerfile.nix-build";
const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");
/// Offset of MRENCLAVE in a DCAP v3 quote (48-byte header + 64 into the
/// report body, docs/PROTOCOL.md §3).
const QUOTE_MRENCLAVE_OFFSET: usize = 48 + 64;
/// The remote executor answers after ~60 s when its PCCS is down.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(180);

/// Files of the build context that `containers/Dockerfile.nix-build`
/// copies (plus the Dockerfile itself).
const BUILD_INPUTS: &[&str] = &[
    "flake.nix",
    "flake.lock",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "nix",
    "crates",
    "examples",
    "enclave-sys",
    DOCKERFILE,
];

// ---------------------------------------------------------------------------
// Configuration and helpers
// ---------------------------------------------------------------------------

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// A path from the environment. Relative paths are taken relative to the
/// repository root (cargo runs tests in the package directory).
fn env_path(name: &str) -> Option<String> {
    env(name).map(|p| Path::new(REPO).join(p).display().to_string())
}

#[derive(Debug, Clone)]
enum Upstream {
    Plain,
    Tls(TlsVerification),
}

#[derive(Debug, Clone)]
struct Target {
    host: String,
    port: u16,
    upstream: Upstream,
}

impl Target {
    fn from_env() -> Self {
        let upstream = match env("SGX_RA_E2E_TRANSPORT").as_deref() {
            None | Some("insecure-tls") => Upstream::Tls(TlsVerification::Insecure),
            Some("plaintext") => Upstream::Plain,
            Some("tls") => Upstream::Tls(match env_path("SGX_RA_E2E_TLS_CA") {
                Some(path) => TlsVerification::CustomCa(std::fs::read(path).expect("TLS CA")),
                None => TlsVerification::WebPki,
            }),
            Some(other) => {
                panic!("SGX_RA_E2E_TRANSPORT={other}: use tls, insecure-tls or plaintext")
            }
        };
        Self {
            host: env("SGX_RA_E2E_HOST").unwrap_or_else(|| "sgx-playground.blechschmidt.io".into()),
            port: env("SGX_RA_E2E_PORT").map_or(443, |p| p.parse().expect("SGX_RA_E2E_PORT")),
            upstream,
        }
    }

    /// Client arguments to reach this target directly.
    fn client_args(&self) -> Vec<String> {
        let mut args = vec![
            "--host".into(),
            self.host.clone(),
            "--port".into(),
            self.port.to_string(),
        ];
        match &self.upstream {
            Upstream::Plain => args.push("--plaintext".into()),
            Upstream::Tls(TlsVerification::Insecure) => args.push("--insecure-tls".into()),
            Upstream::Tls(TlsVerification::WebPki) => {}
            Upstream::Tls(TlsVerification::CustomCa(_)) => {
                args.push("--tls-ca".into());
                args.push(env_path("SGX_RA_E2E_TLS_CA").unwrap());
            }
        }
        args
    }

    fn connect(&self) -> io::Result<Box<dyn ReadWrite>> {
        let to_io = |e: transport::TransportError| io::Error::other(e.to_string());
        Ok(match &self.upstream {
            Upstream::Plain => {
                let s = transport::connect_tcp(&self.host, self.port).map_err(to_io)?;
                s.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
                Box::new(s)
            }
            Upstream::Tls(v) => {
                let s = transport::connect_tls(&self.host, self.port, v).map_err(to_io)?;
                s.sock.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
                Box::new(s)
            }
        })
    }
}

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// Arguments for the expected MRENCLAVE (local gendata or a build of the
/// repository) and the collateral service.
fn measurement_and_policy_args() -> Vec<String> {
    let mut args = Vec::new();
    match env_path("SGX_RA_E2E_GENDATA") {
        Some(gendata) => args.extend(["--gendata-path".into(), gendata]),
        None => args.extend(build_args(Path::new(REPO))),
    }
    args.extend(policy_args());
    args
}

fn policy_args() -> Vec<String> {
    let mut args = Vec::new();
    if let Some(url) = env("SGX_RA_E2E_PCCS_URL") {
        args.extend(["--pccs-url".into(), url]);
    }
    if let Some(ca) = env_path("SGX_RA_E2E_PCCS_CA") {
        args.extend(["--pccs-ca".into(), ca]);
    }
    for status in env("SGX_RA_E2E_ALLOW_TCB")
        .iter()
        .flat_map(|s| s.split(','))
    {
        args.extend(["--allow-tcb-status".into(), status.trim().to_owned()]);
    }
    args
}

fn build_args(context: &Path) -> Vec<String> {
    vec![
        "--build-context".into(),
        context.display().to_string(),
        "--dockerfile".into(),
        context.join(DOCKERFILE).display().to_string(),
    ]
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn transcript(&self) -> String {
        format!(
            "exit code {:?}\n--- stdout ---\n{}--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }

    /// Fails the test as BLOCKED when the executor produced no quote.
    fn require_quote(&self) {
        if self.code == Some(3) {
            panic!(
                "BLOCKED: the executor sent a DCAP error instead of a quote (remote attestation \
                 infrastructure unavailable); nothing was verified.\n{}",
                self.transcript()
            );
        }
    }

    fn assert_failed_with(&self, needle: &str) {
        self.require_quote();
        assert_eq!(self.code, Some(1), "{}", self.transcript());
        assert!(
            self.stderr.contains(needle),
            "expected {needle:?} on stderr\n{}",
            self.transcript()
        );
        assert!(
            !self.stdout.contains("Echo matches"),
            "{}",
            self.transcript()
        );
    }
}

fn echo_client(args: &[String]) -> Run {
    let Output {
        status,
        stdout,
        stderr,
    } = Command::new(env!("CARGO_BIN_EXE_echo-client"))
        .args(args)
        .current_dir(REPO)
        .output()
        .expect("run echo-client");
    let run = Run {
        code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    };
    eprintln!("echo-client {}\n{}", args.join(" "), run.transcript());
    run
}

fn scratch_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = Path::new(REPO)
        .join("target/e2e")
        .join(format!("{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy_tree(from: &Path, to: &Path) {
    if from.is_dir() {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            copy_tree(&entry.path(), &to.join(entry.file_name()));
        }
    } else {
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(from, to).unwrap();
    }
}

/// A copy of the build context whose echo enclave has a backdoor: it
/// behaves exactly like the original except for one magic request.
fn modified_build_context() -> PathBuf {
    let dir = scratch_dir("modified-src");
    for input in BUILD_INPUTS {
        copy_tree(&Path::new(REPO).join(input), &dir.join(input));
    }
    let lib = dir.join("examples/echo-enclave/src/lib.rs");
    let source = std::fs::read_to_string(&lib).unwrap();
    let original = "        response.extend_from_slice(request);\n";
    assert_eq!(source.matches(original).count(), 1, "patch anchor");
    let patched = source.replace(
        original,
        "        if request == b\"backdoor\" {\n            \
         response.extend_from_slice(b\"leaked\");\n            \
         return Ok(());\n        }\n        \
         response.extend_from_slice(request);\n",
    );
    std::fs::write(&lib, patched).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Man in the middle
// ---------------------------------------------------------------------------

/// What the proxy does to the traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attack {
    /// Forward unchanged (control).
    None,
    /// Replace the enclave's `HELLO_REPLY` by one for the attacker's own
    /// key, with a correct key confirmation for that key: everything is
    /// consistent except that report_data commits to a different key.
    SubstituteKey,
    /// Flip one ciphertext bit of the enclave's first record.
    FlipEnclaveRecord,
    /// Flip one ciphertext bit of the client's first record.
    FlipClientRecord,
}

struct Mitm {
    port: u16,
    applied: Arc<AtomicBool>,
}

impl Mitm {
    /// Listens on 127.0.0.1 and relays one connection to `target`.
    fn start(target: Target, attack: Attack) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let applied = Arc::new(AtomicBool::new(false));
        let flag = applied.clone();
        thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            if let Err(e) = relay(client, &target, attack, &flag) {
                eprintln!("mitm: {e}");
            }
        });
        Self { port, applied }
    }

    fn client_args(&self) -> Vec<String> {
        vec![
            "--host".into(),
            "127.0.0.1".into(),
            "--port".into(),
            self.port.to_string(),
            "--plaintext".into(),
        ]
    }

    fn applied(&self) -> bool {
        self.applied.load(Ordering::SeqCst)
    }
}

fn read_frame<T>(
    stream: &mut dyn Read,
    decode: impl Fn(&[u8]) -> Result<Decoded<T>, wire::WireError>,
) -> io::Result<Option<(T, Vec<u8>)>> {
    let mut buf = Vec::new();
    loop {
        match decode(&buf).map_err(|e| io::Error::other(e.to_string()))? {
            Decoded::Complete { value, .. } => return Ok(Some((value, buf))),
            Decoded::Incomplete { needed } => {
                let start = buf.len();
                buf.resize(start + needed, 0);
                match stream.read_exact(&mut buf[start..]) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && start == 0 => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Layer-1 relay (docs/PROTOCOL.md §2). The protocol is lockstep, so one
/// thread suffices: announcement, then request → response pairs.
fn relay(
    mut client: TcpStream,
    target: &Target,
    attack: Attack,
    applied: &AtomicBool,
) -> io::Result<()> {
    let mut upstream = target.connect()?;

    // Announcement. Anything that is not a quote frame (a DCAP error
    // text) is passed through verbatim.
    let mut len = [0u8; 4];
    upstream.read_exact(&mut len)?;
    if u32::from_be_bytes(len) as usize > MAX_QUOTE_LEN {
        client.write_all(&len)?;
        io::copy(&mut upstream, &mut client)?;
        return Ok(());
    }
    let mut quote = vec![0u8; u32::from_be_bytes(len) as usize];
    upstream.read_exact(&mut quote)?;
    client.write_all(&len)?;
    client.write_all(&quote)?;

    let mut rng = OsRng;
    while let Some((mut request, _)) = read_frame(&mut client, wire::decode_request)? {
        let hello = Hello::decode(&request).ok();
        if attack == Attack::FlipClientRecord
            && request.first() == Some(&(MessageType::Record as u8))
            && !applied.swap(true, Ordering::SeqCst)
        {
            let last = request.len() - 1;
            request[last] ^= 0x01;
        }
        let mut frame = Vec::new();
        wire::encode_request(&request, &mut frame).unwrap();
        upstream.write_all(&frame)?;
        upstream.flush()?;

        let Some((response, _)) = read_frame(&mut upstream, wire::decode_response)? else {
            return Ok(());
        };
        let response = match response {
            Response::Ok(mut payload) => {
                match (attack, payload.first().copied(), &hello) {
                    (Attack::SubstituteKey, Some(t), Some(hello))
                        if t == MessageType::HelloReply as u8 =>
                    {
                        let genuine = HelloReply::decode(&payload).unwrap();
                        let forged = forge_reply(&quote, hello, &mut rng);
                        assert_ne!(forged.identity_public, genuine.identity_public);
                        payload = forged.encode().to_vec();
                        applied.store(true, Ordering::SeqCst);
                    }
                    (Attack::FlipEnclaveRecord, Some(t), _)
                        if t == MessageType::Record as u8
                            && !applied.swap(true, Ordering::SeqCst) =>
                    {
                        // Inside the ciphertext, after the 9-byte header.
                        payload[handshake::RECORD_HEADER_LEN] ^= 0x01;
                    }
                    _ => {}
                }
                Response::Ok(payload)
            }
            failure => failure,
        };
        let mut out = Vec::new();
        wire::encode_response(&response, &mut out).unwrap();
        client.write_all(&out)?;
    }
    Ok(())
}

/// The attacker's `HELLO_REPLY`: its own identity key, and a key
/// confirmation that is correct for that key and the genuine report body
/// with report_data rewritten to commit to it.
fn forge_reply(quote: &[u8], hello: &Hello, rng: &mut OsRng) -> HelloReply {
    let identity = IdentityKey::generate(rng).unwrap();
    let mut body = *Quote::parse(quote).unwrap().report_body().as_bytes();
    body[320..].copy_from_slice(identity.report_data().as_bytes());
    let (reply, _session) =
        handshake::respond(&identity, &ReportBody::from_array(body), hello, rng).unwrap();
    reply
}

// ---------------------------------------------------------------------------
// Live tests: need an executor that returns a genuine quote
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs Docker and an SGX executor returning a quote (scripts/e2e.sh)"]
fn live_attested_echo() {
    let target = Target::from_env();
    let mut args = target.client_args();
    args.extend(measurement_and_policy_args());
    args.extend(["-m".into(), "Hello, SGX server!".into()]);
    args.extend(["-m".into(), "x".repeat(4071)]);
    let run = echo_client(&args);
    run.require_quote();
    assert_eq!(run.code, Some(0), "{}", run.transcript());
    for line in [
        "[OK] Quote signature over header and enclave report verified",
        "is identical to the local build",
        "[OK] Attested report_data binds the enclave's channel public key",
        "[OK] Handshake complete",
        "Reply received from server: Hello, SGX server!",
        "[OK] Echo matches the request",
    ] {
        assert!(
            run.stdout.contains(line),
            "missing {line:?}\n{}",
            run.transcript()
        );
    }
    assert_eq!(
        run.stdout.matches("[OK] Echo matches the request").count(),
        2
    );
}

#[test]
#[ignore = "needs Docker and an SGX executor returning a quote (scripts/e2e.sh)"]
fn live_relay_without_attack_works() {
    // Control for the MITM tests: the proxy itself is transparent.
    let mitm = Mitm::start(Target::from_env(), Attack::None);
    let mut args = mitm.client_args();
    args.extend(measurement_and_policy_args());
    let run = echo_client(&args);
    run.require_quote();
    assert_eq!(run.code, Some(0), "{}", run.transcript());
    assert!(run.stdout.contains("[OK] Echo matches the request"));
}

#[test]
#[ignore = "needs Docker and an SGX executor returning a quote (scripts/e2e.sh)"]
fn live_modified_enclave_source_is_rejected() {
    let context = modified_build_context();
    let mut args = Target::from_env().client_args();
    args.extend(build_args(&context));
    args.extend(policy_args());
    let run = echo_client(&args);
    let _ = std::fs::remove_dir_all(&context);
    run.assert_failed_with(
        "[FAIL] MRENCLAVE mismatch: the remote enclave is not the locally built code",
    );
    assert!(!run.stdout.contains("Handshake complete"));
}

#[test]
#[ignore = "needs Docker and an SGX executor returning a quote (scripts/e2e.sh)"]
fn live_substituted_public_key_is_rejected() {
    let mitm = Mitm::start(Target::from_env(), Attack::SubstituteKey);
    let mut args = mitm.client_args();
    args.extend(measurement_and_policy_args());
    let run = echo_client(&args);
    run.assert_failed_with(
        "[FAIL] The enclave's channel key is NOT the key bound in the attested report_data",
    );
    assert!(mitm.applied(), "the attack was not carried out");
    // The quote itself was genuine and passed.
    assert!(
        run.stdout
            .contains("[OK] Quote signature over header and enclave report verified")
    );
    assert!(!run.stdout.contains("Handshake complete"));
}

#[test]
#[ignore = "needs Docker and an SGX executor returning a quote (scripts/e2e.sh)"]
fn live_tampered_enclave_record_fails_decryption() {
    let mitm = Mitm::start(Target::from_env(), Attack::FlipEnclaveRecord);
    let mut args = mitm.client_args();
    args.extend(measurement_and_policy_args());
    let run = echo_client(&args);
    run.assert_failed_with("[FAIL] Secure channel failed: record authentication failed");
    assert!(mitm.applied(), "the attack was not carried out");
    assert!(run.stdout.contains("[OK] Handshake complete"));
    assert!(!run.stdout.contains("Reply received from server"));
}

#[test]
#[ignore = "needs Docker and an SGX executor returning a quote (scripts/e2e.sh)"]
fn live_tampered_client_record_is_rejected_by_enclave() {
    let mitm = Mitm::start(Target::from_env(), Attack::FlipClientRecord);
    let mut args = mitm.client_args();
    args.extend(measurement_and_policy_args());
    let run = echo_client(&args);
    // The enclave fails to authenticate the record, wipes the session and
    // the host reports status 0x02.
    run.assert_failed_with("[FAIL] Secure channel failed");
    assert!(mitm.applied(), "the attack was not carried out");
    assert!(!run.stdout.contains("Reply received from server"));
}

// ---------------------------------------------------------------------------
// Build test: needs Docker, no SGX hardware
// ---------------------------------------------------------------------------

/// A one-connection executor announcing `quote`, then closing.
fn quote_only_executor(quote: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut frame = Vec::new();
            wire::encode_quote(&quote, &mut frame).unwrap();
            let _ = stream.write_all(&frame);
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink);
        }
    });
    port
}

fn run_against(quote: &[u8], extra: Vec<String>) -> Run {
    let port = quote_only_executor(quote.to_vec());
    let mut args = vec![
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        port.to_string(),
        "--plaintext".into(),
        // Unreachable on purpose: these runs must end before collateral.
        "--pccs-url".into(),
        "http://127.0.0.1:9".into(),
    ];
    args.extend(extra);
    echo_client(&args)
}

#[test]
#[ignore = "needs Docker for the reproducible Nix build (no SGX hardware)"]
fn modified_enclave_source_changes_mrenclave() {
    // MRENCLAVE of the pristine sources.
    let pristine_gendata = match env_path("SGX_RA_E2E_GENDATA") {
        Some(path) => PathBuf::from(path),
        None => {
            let out = scratch_dir("pristine");
            let engine = ContainerEngine::detect().expect("docker or podman");
            ReproducibleBuild::new(engine, Path::new(REPO).join(DOCKERFILE), REPO)
                .run(&out)
                .expect("pristine build");
            out.join("enclave.so.gendata")
        }
    };
    let pristine_mrenclave = GendataFile::new(&pristine_gendata)
        .read()
        .expect("pristine gendata")
        .mr_enclave();
    let pristine_hex = pristine_mrenclave.to_string();

    // A quote claiming the pristine MRENCLAVE. Its signature no longer
    // matches, which is irrelevant: the MRENCLAVE comparison runs first,
    // before any collateral is fetched.
    let mut quote = QUOTE_V3.to_vec();
    quote[QUOTE_MRENCLAVE_OFFSET..QUOTE_MRENCLAVE_OFFSET + 32]
        .copy_from_slice(pristine_mrenclave.as_bytes());

    // Control: the pristine build passes the MRENCLAVE comparison and only
    // fails at DCAP verification (the forged signature / no collateral).
    let control = run_against(
        &quote,
        vec![
            "--gendata-path".into(),
            pristine_gendata.display().to_string(),
        ],
    );
    assert_eq!(control.code, Some(1), "{}", control.transcript());
    assert!(
        !control.stderr.contains("MRENCLAVE mismatch"),
        "{}",
        control.transcript()
    );
    assert!(
        control.stderr.contains("[FAIL] Quote verification failed"),
        "{}",
        control.transcript()
    );

    // The client rebuilds the modified tree itself (its real build path)
    // and must refuse the enclave.
    let context = modified_build_context();
    let run = run_against(&quote, build_args(&context));
    let _ = std::fs::remove_dir_all(&context);
    let prefix = "Expected MRENCLAVE from the local build: ";
    let modified_hex = run
        .stdout
        .lines()
        .find_map(|line| line.split_once(prefix))
        .map(|(_, hex)| hex.trim().to_owned())
        .unwrap_or_else(|| panic!("no local build MRENCLAVE\n{}", run.transcript()));
    assert_eq!(run.code, Some(1), "{}", run.transcript());
    assert_eq!(modified_hex.len(), 64, "{}", run.transcript());
    assert_ne!(
        modified_hex, pristine_hex,
        "the patch did not change MRENCLAVE"
    );
    assert!(
        run.stderr.contains("[FAIL] MRENCLAVE mismatch"),
        "{}",
        run.transcript()
    );
    assert!(
        run.stderr
            .contains(&format!("expected (local build) {modified_hex}"))
    );
    assert!(
        run.stderr
            .contains(&format!("remote quote          {pristine_hex}"))
    );
    eprintln!("pristine MRENCLAVE {pristine_hex}\nmodified MRENCLAVE {modified_hex}");
}

// ---------------------------------------------------------------------------
// Self-tests of the man in the middle (no Docker, no hardware)
// ---------------------------------------------------------------------------

/// A software stand-in for the executor, for testing [`Mitm`] only: it
/// announces the recorded quote with report_data rewritten to commit to an
/// `EnclaveEndpoint`'s key (so the quote signature no longer holds) and
/// then runs the real enclave-side protocol code with an echo handler.
fn software_executor() -> Target {
    let identity = IdentityKey::generate(&mut OsRng).unwrap();
    let mut quote = QUOTE_V3.to_vec();
    quote[48 + 320..48 + 384].copy_from_slice(identity.report_data().as_bytes());
    let body = *Quote::parse(&quote).unwrap().report_body();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut frame = Vec::new();
        wire::encode_quote(&quote, &mut frame).unwrap();
        stream.write_all(&frame).unwrap();
        let mut endpoint = EnclaveEndpoint::new(identity);
        endpoint.set_report_body(body);
        while let Ok(Some((request, _))) = read_frame(&mut stream, wire::decode_request) {
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
    Target {
        host: "127.0.0.1".into(),
        port,
        upstream: Upstream::Plain,
    }
}

/// Connects through `mitm`, trusts the announced report body as if it had
/// been verified, runs the handshake and one echo.
fn echo_through(mitm: &Mitm) -> Result<Vec<u8>, ChannelError<ExecutorError>> {
    let stream = TcpStream::connect(("127.0.0.1", mitm.port)).unwrap();
    let mut conn = ExecutorConnection::new(stream);
    let quote = conn.read_quote().unwrap();
    let body = *Quote::parse(&quote).unwrap().report_body();
    let claims = VerifiedClaims::new(body, TcbStatus::UpToDate, Vec::new());
    let mut channel = EnclaveChannel::establish(conn, claims, &mut OsRng)?;
    channel.request(b"ping")
}

#[test]
fn mitm_without_attack_is_transparent() {
    let mitm = Mitm::start(software_executor(), Attack::None);
    assert_eq!(echo_through(&mitm).unwrap(), b"ping");
    assert!(!mitm.applied());
}

#[test]
fn mitm_key_substitution_is_caught_by_report_data_binding() {
    let mitm = Mitm::start(software_executor(), Attack::SubstituteKey);
    let err = echo_through(&mitm).unwrap_err();
    assert!(
        matches!(err, ChannelError::Handshake(HandshakeError::Binding(_))),
        "{err}"
    );
    assert!(mitm.applied());
}

#[test]
fn mitm_enclave_record_bit_flip_fails_decryption() {
    let mitm = Mitm::start(software_executor(), Attack::FlipEnclaveRecord);
    let err = echo_through(&mitm).unwrap_err();
    assert!(
        matches!(err, ChannelError::Record(RecordError::Decryption)),
        "{err}"
    );
    assert!(mitm.applied());
}

#[test]
fn mitm_client_record_bit_flip_is_rejected_by_enclave() {
    let mitm = Mitm::start(software_executor(), Attack::FlipClientRecord);
    let err = echo_through(&mitm).unwrap_err();
    assert!(
        matches!(
            err,
            ChannelError::Transport(ExecutorError::Status(Status::EnclaveCommunicationFailure))
        ),
        "{err}"
    );
    assert!(mitm.applied());
}
