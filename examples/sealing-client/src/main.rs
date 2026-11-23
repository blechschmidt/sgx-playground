//! `sealing-client`: attests the sealing enclave, then
//!
//! * `identity`: verifies the enclave's long-term identity proof and pins
//!   the key (trust on first use) across restarts;
//! * `seal` / `unseal`: has the enclave seal a file to its MRENCLAVE, or
//!   open such a blob again.
//!
//! Every command opens its own attested session: the quote is verified
//! (DCAP, pinned Intel root) against the expected MRENCLAVE, the SGXRA v1
//! handshake binds the channel to the quoted key, and only then is the
//! request sent. See `docs/SEALING.md`.
//!
//! `--simulation-host CMD` runs a local host over stdin/stdout that
//! announces a raw report (`--quoter unattested-report`) instead of a
//! quote. That is **not** attestation; it exists for SGX simulation tests.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command as Process, ExitCode, Stdio};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use sealing_protocol::{ErrorCode, MAX_SEAL_INPUT, Request, Response};
use sgx_ra_client::sgx_ra_core::attestation::{EnclavePolicy, TcbStatus, VerifiedClaims};
use sgx_ra_client::sgx_ra_core::channel::SecureChannel;
use sgx_ra_client::sgx_ra_core::hex::Hex;
use sgx_ra_client::sgx_ra_core::identity::{IdentityChallenge, IdentityOrigin};
use sgx_ra_client::sgx_ra_core::sgx::{Measurement, Report};
use sgx_ra_client::transport::{self, TlsVerification, Transport};
use sgx_ra_client::{
    CollateralService, ContainerEngine, EnclaveChannel, ExecutorConnection, GendataFile,
    INTEL_PCS_URL, IdentityPin, OsRng, PccsConfig, PinOutcome, ReproducibleBuild, VerifierOptions,
    dcap_verifier, verify_assertion,
};

/// Attest the sealing enclave, pin its long-term identity, seal and unseal.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    #[command(flatten)]
    connect: ConnectArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    /// Host forwarding to the enclave (an sgx-ra host app with --listen,
    /// behind TLS or not).
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Port of the host.
    #[arg(long, default_value_t = 7000)]
    port: u16,
    /// Plain TCP instead of TLS.
    #[arg(long, conflicts_with_all = ["insecure_tls", "tls_ca"])]
    plaintext: bool,
    /// Do not check the TLS certificate (TLS is an untrusted pipe anyway).
    #[arg(long, conflicts_with = "tls_ca")]
    insecure_tls: bool,
    /// Trust only these PEM CA certificates for TLS.
    #[arg(long, value_name = "PEM")]
    tls_ca: Option<PathBuf>,

    /// Expect this MRENCLAVE (64 hex digits) instead of building.
    #[arg(long, value_name = "HEX", value_parser = parse_measurement, conflicts_with = "gendata_path")]
    expected_mrenclave: Option<Measurement>,
    /// Take the expected MRENCLAVE from this enclave.so.gendata.
    #[arg(long, value_name = "FILE")]
    gendata_path: Option<PathBuf>,
    /// Dockerfile of the reproducible build (used unless the expected
    /// MRENCLAVE is given); built with ENCLAVE=sealing-enclave.
    #[arg(
        long,
        value_name = "FILE",
        default_value = "containers/Dockerfile.nix-build"
    )]
    dockerfile: PathBuf,
    /// Build context (the repository root).
    #[arg(long, value_name = "DIR", default_value = ".")]
    build_context: PathBuf,
    /// Flake attribute of the enclave to build.
    #[arg(long, value_name = "ATTR", default_value = "sealing-enclave")]
    enclave_attr: String,

    /// Also require this MRSIGNER.
    #[arg(long, value_name = "HEX", value_parser = parse_measurement)]
    mrsigner: Option<Measurement>,
    /// Collateral service: Intel PCS (default) or a PCCS URL.
    #[arg(long, value_name = "URL", default_value = INTEL_PCS_URL)]
    pccs_url: String,

    /// SGX SIMULATION ONLY: spawn this shell command as the host over
    /// stdin/stdout and accept its raw, unsigned report. Not attestation.
    #[arg(long, value_name = "CMD")]
    simulation_host: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify the enclave's long-term identity proof and pin the key.
    Identity {
        /// Pin file (one line of hex). Created on first use.
        #[arg(long, value_name = "FILE", default_value = "sealing-enclave.pin")]
        pin: PathBuf,
    },
    /// Have the enclave seal a file to its MRENCLAVE.
    Seal {
        /// Data to seal.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        /// Where to write the blob.
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Have the enclave open a blob from `seal`.
    Unseal {
        /// The blob.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        /// Where to write the data (default: stdout).
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

fn parse_measurement(s: &str) -> Result<Measurement, String> {
    Measurement::from_hex(s.trim()).map_err(|e| e.to_string())
}

/// Exit codes.
mod exit {
    pub const OK: u8 = 0;
    pub const FAILURE: u8 = 1;
    /// The enclave answered with an application error.
    pub const ENCLAVE_ERROR: u8 = 3;
    /// The long-term identity differs from the pin.
    pub const PIN_MISMATCH: u8 = 4;
}

struct Failure(u8, String);

fn fail(message: impl Into<String>) -> Failure {
    Failure(exit::FAILURE, message.into())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::from(exit::OK),
        Err(Failure(code, message)) => {
            eprintln!("[FAIL] {message}");
            ExitCode::from(code)
        }
    }
}

fn run(cli: &Cli) -> Result<(), Failure> {
    let expected = expected_mrenclave(&cli.connect)?;
    eprintln!("[ OK ] expected MRENCLAVE {expected}");
    let mut channel = open_channel(&cli.connect, expected)?;
    match &cli.command {
        Command::Identity { pin } => identity(&mut channel, pin),
        Command::Seal { input, output } => {
            let data = read(input)?;
            if data.is_empty() || data.len() > MAX_SEAL_INPUT {
                return Err(fail(format!(
                    "{} must hold 1..={MAX_SEAL_INPUT} bytes",
                    input.display()
                )));
            }
            match request(&mut channel, &Request::Seal(&data))? {
                Response::Sealed(blob) => {
                    write(output, &blob)?;
                    eprintln!(
                        "[ OK ] sealed {} bytes into {} ({} bytes; opens only in this enclave on this CPU)",
                        data.len(),
                        output.display(),
                        blob.len()
                    );
                    Ok(())
                }
                other => Err(unexpected(other)),
            }
        }
        Command::Unseal { input, output } => {
            let blob = read(input)?;
            match request(&mut channel, &Request::Unseal(&blob))? {
                Response::Unsealed(data) => {
                    match output {
                        Some(path) => write(path, &data)?,
                        None => io::stdout()
                            .write_all(&data)
                            .map_err(|e| fail(format!("stdout: {e}")))?,
                    }
                    eprintln!("[ OK ] unsealed {} bytes", data.len());
                    Ok(())
                }
                other => Err(unexpected(other)),
            }
        }
    }
}

fn identity<C: SecureChannel>(channel: &mut AttestedSession<C>, pin: &Path) -> Result<(), Failure>
where
    C::Error: std::fmt::Display,
{
    let challenge =
        IdentityChallenge::new(&mut OsRng).map_err(|e| fail(format!("challenge: {e}")))?;
    let assertion = match request(channel, &Request::Identity(*challenge.public_key()))? {
        Response::Identity(a) => a,
        other => return Err(unexpected(other)),
    };
    verify_assertion(challenge, &channel.channel_key, &assertion)
        .map_err(|e| fail(format!("identity proof rejected: {e}")))?;
    eprintln!(
        "[ OK ] enclave proved possession of long-term key {} ({}; sealed to {}), bound to this attested session",
        Hex(&assertion.public_key),
        assertion.origin,
        assertion.policy
    );
    match IdentityPin::new(pin).check(&assertion) {
        Ok(PinOutcome::Pinned) => {
            eprintln!("[ OK ] pinned it in {} (trust on first use)", pin.display())
        }
        Ok(PinOutcome::Matches) => eprintln!("[ OK ] matches the key pinned in {}", pin.display()),
        Ok(PinOutcome::NotPersistent) => eprintln!(
            "[WARN] the host has no sealed storage: this key dies with the enclave instance and was not pinned"
        ),
        Err(e) => {
            return Err(Failure(
                exit::PIN_MISMATCH,
                format!(
                    "{e}\n       The sealed identity was lost or replaced (code change under the MRENCLAVE policy, \
                     another CPU, deleted or rolled-back storage). Delete {} only once you know why.",
                    pin.display()
                ),
            ));
        }
    }
    println!("{}", Hex(&assertion.public_key));
    if assertion.origin == IdentityOrigin::Migrated {
        eprintln!("[NOTE] the key was migrated from an older ISVSVN and re-sealed");
    }
    Ok(())
}

/// An established channel plus the attested channel key it is bound to.
struct AttestedSession<C> {
    channel: C,
    channel_key: [u8; 32],
}

type BoxedChannel = EnclaveChannel<ExecutorConnection<Box<dyn Transport>>>;

fn open_channel(
    args: &ConnectArgs,
    expected: Measurement,
) -> Result<AttestedSession<BoxedChannel>, Failure> {
    let mut policy = EnclavePolicy::new(expected);
    if let Some(signer) = args.mrsigner {
        policy = policy.with_mr_signer(signer);
    }
    let transport: Box<dyn Transport> = match &args.simulation_host {
        Some(cmd) => Box::new(ChildTransport::spawn(cmd)?),
        None => connect(args)?,
    };
    let mut conn = ExecutorConnection::new(transport);
    let evidence = conn
        .read_quote()
        .map_err(|e| fail(format!("no quote received: {e}")))?;
    let claims = if args.simulation_host.is_some() {
        simulation_claims(&evidence, &policy)?
    } else {
        let mut config = PccsConfig::pccs(args.pccs_url.trim_end_matches('/'));
        if args.pccs_url.trim_end_matches('/') == INTEL_PCS_URL {
            config.service = CollateralService::IntelPcs;
        }
        let verifier = dcap_verifier(config, VerifierOptions::default())
            .map_err(|e| fail(format!("collateral service: {e}")))?;
        let verified = verifier
            .verify_detailed(&evidence, &policy)
            .map_err(|e| fail(format!("attestation rejected: {e}")))?;
        eprintln!(
            "[ OK ] DCAP quote verified up to the pinned Intel root; TCB {}; MRENCLAVE matches",
            verified.claims.tcb_status()
        );
        verified.claims
    };
    let channel = EnclaveChannel::establish(conn, claims, &mut OsRng)
        .map_err(|e| fail(format!("attested channel handshake failed: {e}")))?;
    let channel_key = *channel.enclave_public_key();
    eprintln!(
        "[ OK ] attested channel established (enclave channel key {})",
        Hex(&channel_key)
    );
    Ok(AttestedSession {
        channel,
        channel_key,
    })
}

/// Simulation only: the announcement is a raw report; check what a policy
/// would check on its body, and trust it without any signature.
fn simulation_claims(evidence: &[u8], policy: &EnclavePolicy) -> Result<VerifiedClaims, Failure> {
    eprintln!(
        "[WARN] --simulation-host: accepting an UNSIGNED report; this is not remote attestation"
    );
    let report = Report::from_bytes(evidence)
        .map_err(|e| fail(format!("simulation host did not announce a report: {e}")))?;
    let claims = VerifiedClaims::new(report.body(), TcbStatus::UpToDate, Vec::new());
    use sgx_ra_client::sgx_ra_core::attestation::Policy;
    policy
        .check(&claims)
        .map_err(|e| fail(format!("policy rejected the enclave: {e}")))?;
    Ok(claims)
}

fn request<C: SecureChannel>(
    session: &mut AttestedSession<C>,
    req: &Request<'_>,
) -> Result<Response, Failure>
where
    C::Error: std::fmt::Display,
{
    session
        .channel
        .send(&req.encode())
        .map_err(|e| fail(format!("send: {e}")))?;
    let reply = session
        .channel
        .recv()
        .map_err(|e| fail(format!("receive: {e}")))?;
    match Response::decode(&reply).map_err(|e| fail(e.to_string()))? {
        Response::Error(code) => Err(enclave_error(code)),
        r => Ok(r),
    }
}

fn enclave_error(code: ErrorCode) -> Failure {
    Failure(exit::ENCLAVE_ERROR, format!("enclave: {code}"))
}

fn unexpected(r: Response) -> Failure {
    fail(format!("unexpected response {r:?}"))
}

fn expected_mrenclave(args: &ConnectArgs) -> Result<Measurement, Failure> {
    if let Some(m) = args.expected_mrenclave {
        return Ok(m);
    }
    if let Some(path) = &args.gendata_path {
        return GendataFile::new(path)
            .read()
            .map(|g| g.mr_enclave())
            .map_err(|e| fail(format!("{}: {e}", path.display())));
    }
    let engine = ContainerEngine::detect()
        .ok_or_else(|| fail("no docker/podman for the reproducible build (use --gendata-path or --expected-mrenclave)"))?;
    let out = std::env::temp_dir().join(format!("sealing-client-build-{}", std::process::id()));
    eprintln!(
        "[....] building {} reproducibly with {} ({}); this can take minutes",
        args.enclave_attr,
        engine.program(),
        args.dockerfile.display()
    );
    let output = ReproducibleBuild::new(engine, &args.dockerfile, &args.build_context)
        .build_arg("ENCLAVE", &args.enclave_attr)
        .run(&out)
        .map_err(|e| fail(format!("reproducible build failed: {e}")))?;
    let m = output.mr_enclave();
    let _ = fs::remove_dir_all(&out);
    Ok(m)
}

fn connect(args: &ConnectArgs) -> Result<Box<dyn Transport>, Failure> {
    let (host, port) = (args.host.as_str(), args.port);
    if args.plaintext {
        let tcp = transport::connect_tcp(host, port).map_err(|e| fail(e.to_string()))?;
        return Ok(Box::new(tcp));
    }
    let verification = if args.insecure_tls {
        TlsVerification::Insecure
    } else if let Some(ca) = &args.tls_ca {
        TlsVerification::CustomCa(read(ca)?)
    } else {
        TlsVerification::WebPki
    };
    let tls = transport::connect_tls(host, port, &verification).map_err(|e| fail(e.to_string()))?;
    Ok(Box::new(tls))
}

fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|e| fail(format!("{}: {e}", path.display())))
}

fn write(path: &Path, data: &[u8]) -> Result<(), Failure> {
    fs::write(path, data).map_err(|e| fail(format!("{}: {e}", path.display())))
}

/// A host process speaking layer 1 on its stdin/stdout.
struct ChildTransport {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
}

impl ChildTransport {
    fn spawn(command: &str) -> Result<Self, Failure> {
        let mut child = Process::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| fail(format!("cannot start the simulation host: {e}")))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }
}

impl Read for ChildTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stdout.read(buf)
    }
}

impl Write for ChildTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdin
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.stdin {
            Some(s) => s.flush(),
            None => Ok(()),
        }
    }
}

impl Transport for ChildTransport {
    fn set_read_timeout(&mut self, _timeout: Option<Duration>) -> io::Result<()> {
        // Pipes have no timeout; the child is local.
        Ok(())
    }
}

impl Drop for ChildTransport {
    fn drop(&mut self) {
        // EOF ends the host's session loop.
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_commands() {
        let cli = Cli::try_parse_from([
            "sealing-client",
            "--plaintext",
            "--expected-mrenclave",
            &"ab".repeat(32),
            "identity",
            "--pin",
            "x.pin",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Identity { ref pin } if pin == Path::new("x.pin")));
        assert!(
            Cli::try_parse_from(["sealing-client", "--expected-mrenclave", "00", "identity"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["sealing-client"]).is_err());
    }
}
