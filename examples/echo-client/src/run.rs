//! The attest-and-connect flow with step-by-step reporting.

use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use sgx_ra_client::sgx_ra_core::attestation::{EnclavePolicy, PolicyViolation, TcbStatus};
use sgx_ra_client::sgx_ra_core::binding::{REPORT_DATA_LABEL, report_data_for};
use sgx_ra_client::sgx_ra_core::channel::{AttestedChannel, SecureChannel};
use sgx_ra_client::sgx_ra_core::handshake::HandshakeError;
use sgx_ra_client::sgx_ra_core::hex::Hex;
use sgx_ra_client::sgx_ra_core::session::{ChannelError, MessageTransport};
use sgx_ra_client::sgx_ra_core::sgx::{Gendata, Measurement};
use sgx_ra_client::sgx_ra_verifier::{INTEL_SGX_ROOT_CA_SHA256, parse_and_check_structure};
use sgx_ra_client::transport::{self, QUOTE_READ_TIMEOUT};
use sgx_ra_client::{
    CollateralService, EnclaveChannel, ExecutorConnection, ExecutorError, GendataFile,
    INTEL_PCS_URL, OsRng, PccsConfig, ReproducibleBuild, TlsVerification, Transport, VerifiedQuote,
    VerifierOptions, VerifyError, dcap_verifier,
};

use crate::args::{ConnectArgs, DEFAULT_DOCKERFILE, DEFAULT_MESSAGE, MeasurementArgs, ServiceArg};
use crate::exit;

/// A failed step: printed as `[FAIL] <message>`, exits with `code`.
#[derive(Debug)]
struct Failure {
    code: u8,
    message: String,
}

fn fail(message: impl Into<String>) -> Failure {
    Failure {
        code: exit::FAILURE,
        message: message.into(),
    }
}

/// Reports a passed check.
fn ok(message: impl AsRef<str>) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "[OK] {}", message.as_ref());
    let _ = out.flush();
}

/// Informational line (not a check).
fn note(message: impl AsRef<str>) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "     {}", message.as_ref());
    let _ = out.flush();
}

/// Runs the flow and maps the outcome to the exit code.
pub fn run(args: &ConnectArgs) -> ExitCode {
    match flow(args) {
        Ok(()) => ExitCode::from(exit::OK),
        Err(f) => {
            let _ = io::stdout().flush();
            eprintln!("[FAIL] {}", f.message);
            ExitCode::from(f.code)
        }
    }
}

fn flow(args: &ConnectArgs) -> Result<(), Failure> {
    // 1. What must run remotely: from our own reproducible build.
    let expected = expected_measurement(args)?;
    let policy = build_policy(args, &expected);

    // The verifier is ready before we connect, so the host gets no extra
    // time between sending the quote and our checks.
    let verifier = dcap_verifier(
        collateral_config(args)?,
        VerifierOptions {
            collateral_grace: Duration::from_secs(args.collateral.collateral_grace),
            fixed_time: None,
        },
    )
    .map_err(|e| fail(format!("collateral service: {e}")))?;

    // 2. Untrusted transport.
    let transport = connect(args)?;
    let mut conn = ExecutorConnection::new(transport);

    // 3. Quote.
    log::info!(
        "waiting for the quote announcement (up to {} s)",
        QUOTE_READ_TIMEOUT.as_secs()
    );
    let quote = conn.read_quote().map_err(|e| match e {
        ExecutorError::RemoteDiagnostic(_) => Failure {
            code: exit::REMOTE_UNAVAILABLE,
            message: format!("No quote received: {e}"),
        },
        e => fail(format!("No quote received: {e}")),
    })?;
    ok(format!("Received quote ({} bytes)", quote.len()));

    let parsed =
        parse_and_check_structure(&quote).map_err(|e| fail(format!("Malformed quote: {e}")))?;
    ok(format!(
        "Quote structure valid: DCAP v{} ECDSA-P256 quote from the Intel QE, PCK certificate chain attached",
        parsed.header().version
    ));
    // Cheap early exit before contacting the collateral service. The
    // authoritative check is the policy evaluation below.
    let claimed = parsed.report_body().mr_enclave();
    if claimed != expected.mr_enclave {
        return Err(fail(format!(
            "MRENCLAVE mismatch: the remote enclave is not the locally built code.\n       \
             expected (local build) {}\n       remote quote          {claimed}",
            expected.mr_enclave
        )));
    }

    // 4. DCAP verification + policy.
    log::info!("fetching collateral from {}", args.collateral.pccs_url);
    let verified = verifier
        .verify_detailed(&quote, &policy)
        .map_err(|e| match e {
            VerifyError::Policy(v @ PolicyViolation::AdvisoryNotAllowed { .. }) => fail(format!(
                "Policy rejected the enclave: {v} (review the advisory, then pass \
                 --allow-advisory for each acceptable one, or --any-advisory)"
            )),
            VerifyError::Policy(v) => fail(format!("Policy rejected the enclave: {v}")),
            e => fail(format!("Quote verification failed: {e}")),
        })?;
    report_verification(&verified, &policy, &expected);

    // 5. Attested channel.
    let mut channel = EnclaveChannel::establish(conn, verified.claims.clone(), &mut OsRng)
        .map_err(|e| fail(handshake_failure(&e)))?;
    report_channel(&channel);

    // 6. Application traffic.
    exchange(args, &mut channel)
}

/// The expected MRENCLAVE and, when known, the build's signing fields.
struct Expected {
    mr_enclave: Measurement,
    gendata: Option<Gendata>,
}

fn expected_measurement(args: &ConnectArgs) -> Result<Expected, Failure> {
    let m = &args.measurement;
    if let Some(pinned) = m.expected_mrenclave {
        log::warn!("--expected-mrenclave given: skipping the reproducible build");
        ok(format!(
            "Expected MRENCLAVE (pinned on the command line): {pinned}"
        ));
        return Ok(Expected {
            mr_enclave: pinned,
            gendata: None,
        });
    }
    if let Some(path) = &m.gendata_path {
        log::warn!("--gendata-path given: skipping the reproducible build");
        let gendata = GendataFile::new(path)
            .read()
            .map_err(|e| fail(format!("Cannot use {}: {e}", path.display())))?;
        ok(format!(
            "Expected MRENCLAVE from {}: {}",
            path.display(),
            gendata.mr_enclave()
        ));
        return Ok(Expected {
            mr_enclave: gendata.mr_enclave(),
            gendata: Some(gendata),
        });
    }

    let engine = m.container_engine.resolve().ok_or_else(|| {
        fail("Reproducible build impossible: neither docker nor podman found (use --gendata-path or --expected-mrenclave)")
    })?;
    let (dockerfile, context) = build_inputs(m)?;
    let mut build = ReproducibleBuild::new(engine, &dockerfile, &context).no_cache(m.no_cache);
    for (k, v) in &m.build_args {
        build = build.build_arg(k, v);
    }
    let (output_dir, _cleanup) = match &m.build_output {
        Some(dir) => (dir.clone(), None),
        None => {
            let tmp = TempDir::new()
                .map_err(|e| fail(format!("Cannot create a temporary directory: {e}")))?;
            (tmp.path().to_owned(), Some(tmp))
        }
    };
    note(format!(
        "Building the enclave from source with {} ({}, context {}); this can take several minutes",
        engine.program(),
        dockerfile.display(),
        context.display()
    ));
    let output = build
        .run(&output_dir)
        .map_err(|e| fail(format!("Reproducible build failed: {e}")))?;
    let gendata = output
        .gendata()
        .read()
        .map_err(|e| fail(format!("Build output unusable: {e}")))?;
    ok(format!(
        "Reproducible build finished; enclave measured by sgx_sign ({})",
        output.gendata().path().display()
    ));
    ok(format!(
        "Expected MRENCLAVE from the local build: {}",
        output.mr_enclave()
    ));
    if let Some(signer) = output.published_mr_signer() {
        note(format!(
            "Build signing key MRSIGNER: {signer} (pin with --mrsigner if wanted)"
        ));
    }
    Ok(Expected {
        mr_enclave: output.mr_enclave(),
        gendata: Some(gendata),
    })
}

/// The Dockerfile and build context. With the defaults (relative to the
/// working directory) missing, falls back to the source tree this client
/// was compiled from, so `cargo run` works from any directory.
fn build_inputs(m: &MeasurementArgs) -> Result<(PathBuf, PathBuf), Failure> {
    if m.dockerfile.is_file() {
        return Ok((m.dockerfile.clone(), m.build_context.clone()));
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let defaults =
        m.dockerfile == Path::new(DEFAULT_DOCKERFILE) && m.build_context == Path::new(".");
    if defaults && workspace.join(DEFAULT_DOCKERFILE).is_file() {
        let workspace = workspace.canonicalize().unwrap_or(workspace);
        return Ok((workspace.join(DEFAULT_DOCKERFILE), workspace));
    }
    Err(fail(format!(
        "Dockerfile {} not found (run from the repository root or pass --dockerfile/--build-context)",
        m.dockerfile.display()
    )))
}

/// MRENCLAVE from the build; ISVPRODID / minimum ISVSVN default to the
/// values the build signed in (they are not part of MRENCLAVE).
fn build_policy(args: &ConnectArgs, expected: &Expected) -> EnclavePolicy {
    let p = &args.policy;
    let mut policy = EnclavePolicy::new(expected.mr_enclave);
    if let Some(signer) = p.mrsigner {
        policy = policy.with_mr_signer(signer);
    }
    let gendata_body = expected.gendata.as_ref().map(|g| g.body);
    if let Some(id) = p.isv_prod_id.or(gendata_body.map(|b| b.isv_prod_id)) {
        policy = policy.with_isv_prod_id(id);
    }
    if let Some(svn) = p.min_isv_svn.or(gendata_body.map(|b| b.isv_svn)) {
        policy = policy.with_min_isv_svn(svn);
    }
    for status in p.tcb_statuses() {
        policy = policy.allow_tcb_status(status);
    }
    if let Some(ids) = p.advisory_allowlist() {
        policy = policy.allow_advisories(ids);
    }
    policy
}

fn collateral_config(args: &ConnectArgs) -> Result<PccsConfig, Failure> {
    let c = &args.collateral;
    let url = c.pccs_url.trim_end_matches('/');
    let service = match c.collateral_service {
        ServiceArg::Pccs => CollateralService::Pccs,
        ServiceArg::IntelPcs => CollateralService::IntelPcs,
        ServiceArg::Auto if url == INTEL_PCS_URL => CollateralService::IntelPcs,
        ServiceArg::Auto => CollateralService::Pccs,
    };
    let mut config = PccsConfig {
        service,
        ..PccsConfig::pccs(url)
    };
    if let Some(path) = &c.pccs_ca {
        config = config.with_ca_pem(read_file(path)?);
    }
    Ok(config)
}

fn read_file(path: &Path) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|e| fail(format!("Cannot read {}: {e}", path.display())))
}

fn connect(args: &ConnectArgs) -> Result<Box<dyn Transport>, Failure> {
    let t = &args.transport;
    let (host, port) = (args.host.as_str(), args.port);
    if t.plaintext {
        let tcp = transport::connect_tcp(host, port).map_err(|e| fail(e.to_string()))?;
        ok(format!(
            "Connected to {host}:{port} via plain TCP (transport only; trust comes from attestation)"
        ));
        return Ok(Box::new(tcp));
    }
    let verification = if t.insecure_tls {
        log::warn!("--insecure-tls: the TLS server certificate is not checked");
        TlsVerification::Insecure
    } else if let Some(path) = &t.tls_ca {
        TlsVerification::CustomCa(read_file(path)?)
    } else {
        TlsVerification::WebPki
    };
    let tls = transport::connect_tls(host, port, &verification).map_err(|e| {
        let hint = if matches!(verification, TlsVerification::Insecure) {
            ""
        } else {
            "\n       (TLS is only the transport; if the executor's certificate is expired, \
             --insecure-tls is safe to use because attestation does not rely on it)"
        };
        fail(format!("{e}{hint}"))
    })?;
    let cert_note = match verification {
        TlsVerification::WebPki => "certificate verified against the Mozilla roots",
        TlsVerification::CustomCa(_) => "certificate verified against --tls-ca",
        TlsVerification::Insecure => "certificate NOT verified",
    };
    ok(format!(
        "Connected to {host}:{port} via TLS ({}, {cert_note}); TLS ends outside the enclave and is treated as an untrusted pipe",
        transport::describe_tls(&tls)
    ));
    Ok(Box::new(tls))
}

fn report_verification(v: &VerifiedQuote, policy: &EnclavePolicy, expected: &Expected) {
    let claims = &v.claims;
    let id = claims.identity();
    ok(format!(
        "PCK certificate chain verified up to the pinned Intel SGX Root CA (SHA-256 {INTEL_SGX_ROOT_CA_SHA256}); \
         {} and Root CA CRLs checked, PCK certificate not revoked",
        v.pck_ca.common_name()
    ));
    ok(format!(
        "TCB Info (FMSPC {}) and QE Identity signed by Intel SGX TCB Signing; collateral valid until {} (TCB evaluation data number {})",
        Hex(&v.pck.fmspc),
        format_time(v.collateral_expiry),
        v.tcb_evaluation_data_number
    ));
    ok(format!(
        "Quoting enclave report signed by the PCK key and matches QE Identity (QE TCB status {}); attestation key bound to it",
        v.qe_tcb_status
    ));
    ok("Quote signature over header and enclave report verified with the attestation key");
    ok(format!(
        "Platform TCB status {} (platform {}, TCB date {}); allowed by policy",
        claims.tcb_status(),
        v.platform_tcb_status,
        v.platform_tcb_date
    ));
    if !claims.advisory_ids().is_empty() {
        let checked = if policy.allowed_advisories().is_some() {
            "all on the advisory allowlist"
        } else {
            "not checked (--any-advisory)"
        };
        note(format!(
            "Intel security advisories: {} ({checked})",
            claims.advisory_ids().join(", ")
        ));
    }
    if let Some(gap) = &v.platform_tcb_gap {
        note(format!(
            "The best TCB level Intel defines for this platform type is {} (TCB date {}); \
             this platform falls short of it:",
            gap.best.status, gap.best.tcb_date
        ));
        for s in &gap.shortfalls {
            note(format!("  {s}: {}", s.remedy()));
        }
        note(
            "Only the operator of the physical machine can raise these SVNs (docs/TCB_STATUS.md); \
             nothing in the enclave, the host app or the client changes them",
        );
    }
    ok("Enclave is not in debug mode (DEBUG attribute clear) and is 64-bit");
    ok(format!(
        "Remote MRENCLAVE {} is identical to the local build: the remote runs exactly the code we built",
        id.mr_enclave
    ));
    match policy.mr_signer() {
        Some(s) => ok(format!("MRSIGNER {s} matches")),
        None => note(format!("MRSIGNER {} (not pinned)", id.mr_signer)),
    }
    let from_build = if expected.gendata.is_some() {
        " (from the build's SIGSTRUCT)"
    } else {
        ""
    };
    match policy.isv_prod_id() {
        Some(p) => ok(format!("ISVPRODID {} = {p}{from_build}", id.isv_prod_id)),
        None => note(format!("ISVPRODID {} (not pinned)", id.isv_prod_id)),
    }
    match policy.min_isv_svn() {
        Some(m) => ok(format!("ISVSVN {} >= {m}{from_build}", id.isv_svn)),
        None => note(format!("ISVSVN {} (not pinned)", id.isv_svn)),
    }
    if claims.tcb_status() != TcbStatus::UpToDate {
        log::warn!(
            "accepted a platform with TCB status {}{}; pass --strict-tcb to require UpToDate",
            claims.tcb_status(),
            match claims.advisory_ids() {
                [] => String::new(),
                ids => format!(" (affected by {})", ids.join(", ")),
            }
        );
    }
}

fn report_channel<M: MessageTransport>(channel: &EnclaveChannel<M>) {
    let key = channel.enclave_public_key();
    let report_data = channel.peer_claims().report_data();
    // Re-derive for display; the handshake already enforced equality.
    debug_assert_eq!(report_data_for(key), report_data);
    ok(format!(
        "Attested report_data binds the enclave's channel public key {}: \
         report_data = SHA-256(\"{}\" || 00 01 || key) || 0^32 = {}…",
        Hex(key),
        String::from_utf8_lossy(REPORT_DATA_LABEL),
        Hex(&report_data.as_bytes()[..32]),
    ));
    ok(
        "Handshake complete: the enclave proved possession of the attested private key \
         (key confirmation verified); the key exists only inside the enclave with the verified MRENCLAVE",
    );
    ok("Confidential channel established (X25519 + HKDF-SHA256, ChaCha20-Poly1305 records)");
}

fn handshake_failure<E: std::fmt::Display>(e: &ChannelError<E>) -> String {
    match e {
        ChannelError::Handshake(HandshakeError::Binding(_)) => format!(
            "The enclave's channel key is NOT the key bound in the attested report_data ({e}); \
             the host may be relaying to a different enclave or key"
        ),
        ChannelError::Handshake(HandshakeError::ConfirmationFailed) => {
            format!("The enclave did not prove possession of the attested key ({e})")
        }
        ChannelError::Transport(_) => format!("Attested channel handshake failed: {e}"),
        _ => format!("Attested channel handshake failed: {e}"),
    }
}

fn exchange<C: SecureChannel>(args: &ConnectArgs, channel: &mut C) -> Result<(), Failure> {
    let defaults = [DEFAULT_MESSAGE.to_owned()];
    let messages: &[String] = if args.messages.is_empty() && !args.interactive {
        &defaults
    } else {
        &args.messages
    };
    for message in messages {
        echo(channel, message.as_bytes())?;
    }
    if args.interactive {
        interactive(channel)?;
    }
    Ok(())
}

/// One request/response; the echo enclave must return the request.
fn echo<C: SecureChannel>(channel: &mut C, message: &[u8]) -> Result<(), Failure> {
    if message.len() > channel.max_message_len() {
        return Err(fail(format!(
            "Message of {} bytes exceeds the {}-byte record limit",
            message.len(),
            channel.max_message_len()
        )));
    }
    let reply = channel
        .request(message)
        .map_err(|e| fail(format!("Secure channel failed: {e}")))?;
    ok(format!(
        "Sent {} bytes encrypted; reply of {} bytes decrypted and authenticated",
        message.len(),
        reply.len()
    ));
    println!(
        "Reply received from server: {}",
        String::from_utf8_lossy(&reply)
    );
    if reply != message {
        return Err(fail("The echo enclave's reply differs from the request"));
    }
    ok("Echo matches the request");
    Ok(())
}

fn interactive<C: SecureChannel>(channel: &mut C) -> Result<(), Failure> {
    let stdin = io::stdin();
    let tty = stdin.is_terminal();
    if tty {
        eprintln!("Interactive mode: each line is sent through the attested channel; Ctrl-D ends.");
    }
    let mut lines = stdin.lock();
    let mut line = String::new();
    loop {
        if tty {
            eprint!("> ");
            let _ = io::stderr().flush();
        }
        line.clear();
        match lines.read_line(&mut line) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(fail(format!("Cannot read stdin: {e}"))),
        }
        let text = line.trim_end_matches(['\n', '\r']);
        if text.len() > channel.max_message_len() {
            eprintln!(
                "line of {} bytes skipped: the limit is {} bytes",
                text.len(),
                channel.max_message_len()
            );
            continue;
        }
        echo(channel, text.as_bytes())?;
    }
}

fn format_time(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| unix.to_string())
}

/// A private temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        let mut nonce = [0u8; 8];
        sgx_ra_client::sgx_ra_core::rng::Rng::fill_bytes(&mut OsRng, &mut nonce)
            .map_err(io::Error::other)?;
        let path = std::env::temp_dir().join(format!("echo-client-build-{}", Hex(&nonce)));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.0) {
            log::warn!("cannot remove {}: {e}", self.0.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A channel answering each request with `transform(request)`.
    struct Mock {
        transform: fn(&[u8]) -> Vec<u8>,
        sent: Vec<Vec<u8>>,
        pending: Option<Vec<u8>>,
    }

    impl Mock {
        fn new(transform: fn(&[u8]) -> Vec<u8>) -> Self {
            Self {
                transform,
                sent: Vec::new(),
                pending: None,
            }
        }
    }

    impl SecureChannel for Mock {
        type Error = String;

        fn max_message_len(&self) -> usize {
            32
        }

        fn send(&mut self, plaintext: &[u8]) -> Result<(), String> {
            self.sent.push(plaintext.to_vec());
            self.pending = Some((self.transform)(plaintext));
            Ok(())
        }

        fn recv(&mut self) -> Result<Vec<u8>, String> {
            self.pending.take().ok_or_else(|| "nothing pending".into())
        }
    }

    fn args(extra: &[&str]) -> ConnectArgs {
        use clap::Parser;
        let mut argv = vec!["echo-client"];
        argv.extend_from_slice(extra);
        crate::args::Cli::try_parse_from(argv).unwrap().connect
    }

    #[test]
    fn default_message_is_the_blueprint_greeting() {
        let mut ch = Mock::new(<[u8]>::to_vec);
        assert!(exchange(&args(&[]), &mut ch).is_ok());
        assert_eq!(ch.sent, [DEFAULT_MESSAGE.as_bytes()]);

        let mut ch = Mock::new(<[u8]>::to_vec);
        assert!(exchange(&args(&["-m", "a", "-m", "b"]), &mut ch).is_ok());
        assert_eq!(ch.sent, [b"a", b"b"]);
    }

    #[test]
    fn wrong_echo_and_oversized_messages_fail() {
        let mut ch = Mock::new(|_| b"tampered".to_vec());
        let err = echo(&mut ch, b"hello").err().unwrap();
        assert_eq!(err.code, exit::FAILURE);
        assert!(err.message.contains("differs"));

        let mut ch = Mock::new(<[u8]>::to_vec);
        let err = echo(&mut ch, &[0u8; 33]).err().unwrap();
        assert!(err.message.contains("exceeds"));
        assert!(ch.sent.is_empty());
    }

    #[test]
    fn policy_defaults_to_the_build_signing_fields() {
        let raw = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/blueprint_enclave.so.gendata"
        ))
        .unwrap();
        let gendata = Gendata::parse(&raw).unwrap();
        let expected = Expected {
            mr_enclave: gendata.mr_enclave(),
            gendata: Some(gendata),
        };
        let p = build_policy(&args(&[]), &expected);
        assert_eq!(p.mr_enclave(), gendata.mr_enclave());
        assert_eq!(p.isv_prod_id(), Some(gendata.body.isv_prod_id));
        assert_eq!(p.min_isv_svn(), Some(gendata.body.isv_svn));
        assert_eq!(p.mr_signer(), None);
        assert!(p.allowed_tcb_statuses().contains(TcbStatus::OutOfDate));
        assert!(!p.allowed_tcb_statuses().contains(TcbStatus::Revoked));
        assert_eq!(p.allowed_advisories().map(<[_]>::len), Some(6));
        let p = build_policy(&args(&["--strict-tcb"]), &expected);
        assert!(!p.allowed_tcb_statuses().contains(TcbStatus::OutOfDate));
        assert_eq!(p.allowed_advisories(), None);
        let p = build_policy(&args(&["--allow-advisory", "INTEL-SA-00615"]), &expected);
        assert_eq!(
            p.allowed_advisories(),
            Some(&["INTEL-SA-00615".to_owned()][..])
        );

        let p = build_policy(
            &args(&[
                "--isv-prod-id",
                "7",
                "--min-isv-svn",
                "0",
                "--allow-tcb-status",
                "OutOfDate",
            ]),
            &expected,
        );
        assert_eq!(p.isv_prod_id(), Some(7));
        assert_eq!(p.min_isv_svn(), Some(0));
        assert!(p.allowed_tcb_statuses().contains(TcbStatus::OutOfDate));
        assert!(
            !p.allowed_tcb_statuses()
                .contains(TcbStatus::OutOfDateConfigurationNeeded)
        );

        let pinned = Expected {
            mr_enclave: Measurement([1; 32]),
            gendata: None,
        };
        let p = build_policy(&args(&[]), &pinned);
        assert_eq!((p.isv_prod_id(), p.min_isv_svn()), (None, None));
    }

    #[test]
    fn collateral_service_auto_detection() {
        let c = collateral_config(&args(&[])).unwrap();
        assert_eq!(c.service, CollateralService::IntelPcs);
        let c = collateral_config(&args(&["--pccs-url", "http://127.0.0.1:8080"])).unwrap();
        assert_eq!(c.service, CollateralService::Pccs);
        let c = collateral_config(&args(&[
            "--pccs-url",
            "https://pcs.example",
            "--collateral-service",
            "intel-pcs",
        ]))
        .unwrap();
        assert_eq!(c.service, CollateralService::IntelPcs);
    }
}
