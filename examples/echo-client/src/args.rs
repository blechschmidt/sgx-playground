//! Command line.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use sgx_ra_client::sgx_ra_core::attestation::TcbStatus;
use sgx_ra_client::sgx_ra_core::sgx::Measurement;
use sgx_ra_client::sgx_ra_verifier::tcb;
use sgx_ra_client::{ContainerEngine, INTEL_PCS_URL};

/// The message sent when neither `--message` nor `--interactive` is given
/// (the blueprint's greeting).
pub const DEFAULT_MESSAGE: &str = "Hello, SGX server!";

/// The reproducible build's Dockerfile, relative to the repository root.
pub const DEFAULT_DOCKERFILE: &str = "containers/Dockerfile.nix-build";

/// Rebuild the echo enclave reproducibly, attest the remote enclave and talk
/// to it over a channel whose key provably lives only inside that enclave.
#[derive(Debug, Parser)]
#[command(version, args_conflicts_with_subcommands = true)]
pub struct Cli {
    /// Log level of diagnostics on stderr: error, warn, info, debug, trace.
    #[arg(long, global = true, default_value = "info", value_parser = parse_level)]
    pub loglevel: log::LevelFilter,

    #[command(flatten)]
    pub connect: ConnectArgs,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Options of the default attest-and-connect flow.
#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Host forwarding traffic to the enclave (the executor's TLS endpoint).
    #[arg(long, default_value = "sgx-playground.blechschmidt.io")]
    pub host: String,

    /// Port of the executor.
    #[arg(long, default_value_t = 443)]
    pub port: u16,

    #[command(flatten)]
    pub transport: TransportArgs,

    #[command(flatten)]
    pub measurement: MeasurementArgs,

    #[command(flatten)]
    pub policy: PolicyArgs,

    #[command(flatten)]
    pub collateral: CollateralArgs,

    /// Message to send through the attested channel (repeatable). Default:
    /// "Hello, SGX server!" unless --interactive is given.
    #[arg(long = "message", short = 'm', value_name = "TEXT")]
    pub messages: Vec<String>,

    /// After the --message exchanges, send each line read from stdin and
    /// print the decrypted reply, until EOF.
    #[arg(long, short = 'i')]
    pub interactive: bool,
}

/// Outer transport. Never trusted; these only affect who can watch the
/// ciphertext.
#[derive(Debug, Args)]
pub struct TransportArgs {
    /// Accept any TLS server certificate (handshake signatures are still
    /// checked). Use when the executor's certificate is expired or
    /// self-signed; attestation does not depend on TLS.
    #[arg(long, conflicts_with_all = ["tls_ca", "plaintext"])]
    pub insecure_tls: bool,

    /// Trust only these PEM CA certificates for TLS instead of the Mozilla
    /// roots.
    #[arg(long, value_name = "PEM", conflicts_with = "plaintext")]
    pub tls_ca: Option<PathBuf>,

    /// Plain TCP instead of TLS, e.g. to a local `echo-host-app --listen`.
    #[arg(long)]
    pub plaintext: bool,
}

/// Where the expected MRENCLAVE comes from. Default: the reproducible build.
#[derive(Debug, Args)]
pub struct MeasurementArgs {
    /// Dockerfile of the reproducible Nix build container.
    #[arg(long, value_name = "FILE", default_value = DEFAULT_DOCKERFILE)]
    pub dockerfile: PathBuf,

    /// Build context directory (the repository root). If the defaults do not
    /// exist in the working directory, the source tree the client was built
    /// from is used.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub build_context: PathBuf,

    /// Extra `--build-arg KEY=VALUE` for the build (repeatable), e.g.
    /// ENCLAVE=enclave.
    #[arg(long = "build-arg", value_name = "KEY=VALUE", value_parser = parse_key_value)]
    pub build_args: Vec<(String, String)>,

    /// Container engine running the build.
    #[arg(long, value_enum, default_value_t = EngineArg::Auto)]
    pub container_engine: EngineArg,

    /// Keep the exported build artefacts in this (new or empty) directory
    /// instead of a temporary one.
    #[arg(long, value_name = "DIR")]
    pub build_output: Option<PathBuf>,

    /// Pass --no-cache to the build.
    #[arg(long)]
    pub no_cache: bool,

    /// Use this existing enclave.so.gendata instead of building (e.g. the
    /// output of an earlier `scripts/nix-build-enclave.sh`).
    #[arg(long, value_name = "FILE", conflicts_with = "expected_mrenclave")]
    pub gendata_path: Option<PathBuf>,

    /// Expect this MRENCLAVE (64 hex digits) and skip the build.
    #[arg(long, value_name = "HEX", value_parser = parse_measurement)]
    pub expected_mrenclave: Option<Measurement>,
}

/// Container engine selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EngineArg {
    /// docker if installed, else podman.
    Auto,
    /// Docker (BuildKit).
    Docker,
    /// Podman.
    Podman,
}

impl EngineArg {
    /// Resolves `auto`.
    pub fn resolve(self) -> Option<ContainerEngine> {
        match self {
            Self::Auto => ContainerEngine::detect(),
            Self::Docker => Some(ContainerEngine::Docker),
            Self::Podman => Some(ContainerEngine::Podman),
        }
    }
}

/// Acceptance policy beyond MRENCLAVE. Debug enclaves are always refused.
#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// Also require this MRSIGNER (64 hex digits).
    #[arg(long, value_name = "HEX", value_parser = parse_measurement)]
    pub mrsigner: Option<Measurement>,

    /// Also require this ISVPRODID.
    #[arg(long, value_name = "ID")]
    pub isv_prod_id: Option<u16>,

    /// Also require ISVSVN >= this value.
    #[arg(long, value_name = "SVN")]
    pub min_isv_svn: Option<u16>,

    /// Accept only UpToDate platforms plus these TCB statuses (repeatable):
    /// SWHardeningNeeded, ConfigurationNeeded,
    /// ConfigurationAndSWHardeningNeeded, OutOfDate,
    /// OutOfDateConfigurationNeeded. Revoked can never be accepted.
    /// Default: the statuses of current Ice Lake SP servers (SWHardeningNeeded,
    /// ConfigurationAndSWHardeningNeeded, OutOfDate,
    /// OutOfDateConfigurationNeeded; the public executor is
    /// OutOfDateConfigurationNeeded), gated by the advisory allowlist.
    #[arg(long = "allow-tcb-status", value_name = "STATUS", value_parser = parse_tcb_status)]
    pub allowed_tcb_statuses: Vec<TcbStatus>,

    /// Accept a non-UpToDate platform only if every Intel advisory it is
    /// affected by is one of these (repeatable, e.g. INTEL-SA-00615).
    /// Replaces the default allowlist: INTEL-SA-00615, -00657, -00767,
    /// -01079, -01103, -01153 (Ice Lake SP since the 2024-03-13 TCB
    /// recovery). Any other advisory is rejected.
    #[arg(long = "allow-advisory", value_name = "ID", value_parser = parse_advisory_id)]
    pub allowed_advisories: Vec<String>,

    /// Do not check advisories; accept every allowed TCB status whatever
    /// advisories apply.
    #[arg(long, conflicts_with = "allowed_advisories")]
    pub any_advisory: bool,

    /// Accept only platforms with TCB status UpToDate.
    #[arg(
        long,
        conflicts_with_all = ["allowed_tcb_statuses", "allowed_advisories", "any_advisory"]
    )]
    pub strict_tcb: bool,
}

impl PolicyArgs {
    /// The TCB statuses accepted besides UpToDate.
    pub fn tcb_statuses(&self) -> Vec<TcbStatus> {
        if self.strict_tcb {
            Vec::new()
        } else if self.allowed_tcb_statuses.is_empty() {
            tcb::ICE_LAKE_SP_TCB_STATUSES.to_vec()
        } else {
            self.allowed_tcb_statuses.clone()
        }
    }

    /// The advisory allowlist, or `None` if advisories are not checked
    /// (`--any-advisory`; `--strict-tcb` admits UpToDate only anyway).
    pub fn advisory_allowlist(&self) -> Option<Vec<String>> {
        if self.strict_tcb || self.any_advisory {
            None
        } else if self.allowed_advisories.is_empty() {
            Some(tcb::ICE_LAKE_SP_ADVISORIES.map(String::from).to_vec())
        } else {
            Some(self.allowed_advisories.clone())
        }
    }
}

/// DCAP collateral source. It is not trusted: all collateral is verified
/// against the pinned Intel SGX Root CA.
#[derive(Debug, Args)]
pub struct CollateralArgs {
    /// Collateral service base URL: Intel PCS (default) or a PCCS such as
    /// http://127.0.0.1:8080 (the blueprint's default).
    #[arg(long, value_name = "URL", default_value = INTEL_PCS_URL)]
    pub pccs_url: String,

    /// API flavour of --pccs-url. auto: Intel PCS for
    /// api.trustedservices.intel.com, PCCS otherwise.
    #[arg(long, value_enum, default_value_t = ServiceArg::Auto)]
    pub collateral_service: ServiceArg,

    /// Trust only these PEM CA certificates for an HTTPS PCCS.
    #[arg(long, value_name = "PEM")]
    pub pccs_ca: Option<PathBuf>,

    /// Accept collateral (CRLs, TCB Info, QE Identity) up to this many
    /// seconds past its nextUpdate. Certificates never get grace.
    #[arg(long, value_name = "SECONDS", default_value_t = 0)]
    pub collateral_grace: u64,
}

/// Collateral API flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ServiceArg {
    /// Decide from the URL.
    Auto,
    /// Intel PCCS.
    Pccs,
    /// Intel PCS.
    IntelPcs,
}

/// Offline inspection helpers (structure only, no signature checks).
#[derive(Debug, Subcommand)]
#[allow(clippy::enum_variant_names)] // the names are the subcommands
pub enum Command {
    /// Print the fields of a DCAP quote file.
    InspectQuote(InspectQuoteArgs),
    /// Print the fields of an enclave.so.gendata file.
    InspectGendata {
        /// The gendata file.
        path: PathBuf,
    },
    /// Print the fields of a SIGSTRUCT file.
    InspectSigstruct {
        /// The SIGSTRUCT file.
        path: PathBuf,
    },
}

/// `inspect-quote` arguments.
#[derive(Debug, Args)]
pub struct InspectQuoteArgs {
    /// The quote file.
    pub path: PathBuf,
    /// Compare the quote's MRENCLAVE with this value.
    #[arg(long, value_name = "HEX", value_parser = parse_measurement, conflicts_with = "expect_gendata")]
    pub expect_mrenclave: Option<Measurement>,
    /// Compare the quote's MRENCLAVE with this gendata file's.
    #[arg(long, value_name = "FILE")]
    pub expect_gendata: Option<PathBuf>,
}

fn parse_level(s: &str) -> Result<log::LevelFilter, String> {
    s.parse()
        .map_err(|_| format!("unknown log level {s:?} (error, warn, info, debug, trace, off)"))
}

fn parse_measurement(s: &str) -> Result<Measurement, String> {
    Measurement::from_hex(s.trim()).map_err(|e| e.to_string())
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err(format!("expected KEY=VALUE, got {s:?}")),
    }
}

fn parse_tcb_status(s: &str) -> Result<TcbStatus, String> {
    match TcbStatus::from_name(s) {
        Some(TcbStatus::Revoked) => Err("a Revoked platform can never be accepted".into()),
        Some(status) => Ok(status),
        None => Err(format!(
            "unknown TCB status {s:?}; one of: {}",
            TcbStatus::ALL
                .iter()
                .filter(|s| **s != TcbStatus::Revoked)
                .map(TcbStatus::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn parse_advisory_id(s: &str) -> Result<String, String> {
    let id = s.trim().to_ascii_uppercase();
    match id.strip_prefix("INTEL-SA-") {
        Some(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => Ok(id),
        _ => Err(format!(
            "{s:?} is not an Intel advisory ID like INTEL-SA-00615"
        )),
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
    fn defaults_match_the_blueprint() {
        let cli = Cli::try_parse_from(["echo-client"]).unwrap();
        assert!(cli.command.is_none());
        let c = cli.connect;
        assert_eq!(c.host, "sgx-playground.blechschmidt.io");
        assert_eq!(c.port, 443);
        assert_eq!(
            c.measurement.dockerfile,
            PathBuf::from("containers/Dockerfile.nix-build")
        );
        assert!(c.measurement.expected_mrenclave.is_none());
        assert!(c.messages.is_empty() && !c.interactive);
        assert!(!c.transport.insecure_tls && !c.transport.plaintext);
        // Allowlists that admit the public executor's
        // OutOfDateConfigurationNeeded platform and nothing else.
        let tcb = c.policy.tcb_statuses();
        assert!(tcb.contains(&TcbStatus::OutOfDateConfigurationNeeded));
        assert!(!tcb.contains(&TcbStatus::Revoked));
        assert!(!tcb.contains(&TcbStatus::ConfigurationNeeded));
        let advisories = c.policy.advisory_allowlist().unwrap();
        assert_eq!(advisories.len(), 6);
        assert!(advisories.contains(&"INTEL-SA-00615".to_owned()));
        let strict = Cli::try_parse_from(["echo-client", "--strict-tcb"]).unwrap();
        assert!(strict.connect.policy.tcb_statuses().is_empty());
        assert_eq!(strict.connect.policy.advisory_allowlist(), None);
        let any = Cli::try_parse_from(["echo-client", "--any-advisory"]).unwrap();
        assert_eq!(any.connect.policy.advisory_allowlist(), None);
        let own = Cli::try_parse_from([
            "echo-client",
            "--allow-advisory",
            "intel-sa-00615",
            "--allow-advisory",
            "INTEL-SA-00657",
        ])
        .unwrap();
        assert_eq!(
            own.connect.policy.advisory_allowlist().unwrap(),
            ["INTEL-SA-00615", "INTEL-SA-00657"]
        );
    }

    #[test]
    fn rejects_bad_values() {
        for args in [
            &["echo-client", "--expected-mrenclave", "abcd"][..],
            &["echo-client", "--allow-tcb-status", "Revoked"],
            &["echo-client", "--allow-tcb-status", "Fine"],
            &["echo-client", "--build-arg", "novalue"],
            &["echo-client", "--insecure-tls", "--plaintext"],
            &[
                "echo-client",
                "--gendata-path",
                "x",
                "--expected-mrenclave",
                &"0".repeat(64),
            ],
            &["echo-client", "--loglevel", "loud"],
            &[
                "echo-client",
                "--strict-tcb",
                "--allow-tcb-status",
                "OutOfDate",
            ],
            &["echo-client", "--allow-advisory", "CVE-2022-21233"],
            &["echo-client", "--allow-advisory", "INTEL-SA-"],
            &["echo-client", "--strict-tcb", "--any-advisory"],
            &[
                "echo-client",
                "--strict-tcb",
                "--allow-advisory",
                "INTEL-SA-00615",
            ],
            &[
                "echo-client",
                "--any-advisory",
                "--allow-advisory",
                "INTEL-SA-00615",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
        let ok = Cli::try_parse_from([
            "echo-client",
            "--allow-tcb-status",
            "SWHardeningNeeded",
            "--build-arg",
            "ENCLAVE=enclave",
            "-m",
            "a",
            "-m",
            "b",
            "-i",
        ])
        .unwrap();
        assert_eq!(
            ok.connect.policy.allowed_tcb_statuses,
            [TcbStatus::SwHardeningNeeded]
        );
        assert_eq!(ok.connect.messages, ["a", "b"]);
    }
}
