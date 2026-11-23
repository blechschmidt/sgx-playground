//! The command line shared by all host apps.
//!
//! ```text
//! HOST [--enclave PATH] [--quoter dcap|unattested-report] [--sgx-lib-dir DIR]
//!      [--listen ADDR [--max-sessions N] [--idle-timeout SECS]]
//!      [--sealed-dir DIR] [--verbose]
//! ```
//!
//! Without `--listen` the host serves exactly one session on stdin/stdout
//! and exits when the client closes the connection: the drop-in replacement
//! for the blueprint `app` behind `stunnel`'s `exec`. With `--listen` it
//! serves TCP, one enclave instance per connection.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use crate::tcp::TcpOptions;

/// Default enclave image, relative to the working directory, as in the
/// blueprint `App.cpp`.
pub const DEFAULT_ENCLAVE: &str = "enclave.signed.so";

/// How the host turns the enclave's report into evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoterKind {
    /// DCAP quote from `libsgx_dcap_ql` (production).
    Dcap,
    /// The raw report, unattested
    /// ([`UnattestedReportQuoter`](crate::quoter::UnattestedReportQuoter)).
    /// For SGX simulation tests only.
    UnattestedReport,
}

/// Parsed options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Signed enclave image (`--enclave`, env `SGX_RA_ENCLAVE`).
    pub enclave: PathBuf,
    /// Evidence source (`--quoter`).
    pub quoter: QuoterKind,
    /// DCAP runtime directory (`--sgx-lib-dir`, env `SGX_RA_SGX_LIB_DIR`).
    pub sgx_lib_dir: Option<PathBuf>,
    /// TCP listen address (`--listen`); `None` serves stdin/stdout.
    pub listen: Option<String>,
    /// TCP limits (`--max-sessions`, `--idle-timeout`; 0 disables it).
    pub tcp: TcpOptions,
    /// Directory serving the sealed-storage OCALLs (`--sealed-dir`, env
    /// `SGX_RA_SEALED_DIR`); `None` answers them with "unavailable".
    pub sealed_dir: Option<PathBuf>,
    /// Per-request diagnostics on stderr (`--verbose`).
    pub verbose: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            enclave: PathBuf::from(DEFAULT_ENCLAVE),
            quoter: QuoterKind::Dcap,
            sgx_lib_dir: None,
            listen: None,
            tcp: TcpOptions::default(),
            sealed_dir: None,
            verbose: false,
        }
    }
}

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Serve.
    Run(Options),
    /// `--help`.
    Help,
    /// `--version`.
    Version,
}

/// Usage text for `name`.
pub fn usage(name: &str) -> String {
    format!(
        "\
Usage: {name} [OPTIONS]

Untrusted SGX host: loads the enclave, announces its DCAP quote and relays
requests (docs/PROTOCOL.md section 2). Without --listen it serves one session
on stdin/stdout (for stunnel's exec); all diagnostics go to stderr.

Options:
  --enclave PATH        signed enclave image [env SGX_RA_ENCLAVE, default: {DEFAULT_ENCLAVE}]
  --quoter KIND         dcap (default) or unattested-report (SGX simulation tests only:
                        announces the raw report, which no verifier accepts)
  --sgx-lib-dir DIR     directory with libsgx_dcap_ql.so.1, the QE3/PCE/IDE images and
                        libdcap_quoteprov.so.1 [env SGX_RA_SGX_LIB_DIR]
  --listen ADDR         serve TCP on ADDR (e.g. 0.0.0.0:7000), one enclave per connection
  --max-sessions N      concurrent TCP sessions [default: 8]
  --idle-timeout SECS   end a TCP session after SECS without input, 0 = never [default: 300]
  --sealed-dir DIR      keep the enclave's sealed blobs in DIR (created with mode 0700),
                        for enclaves linked with enclave-sys/sealed-storage/Enclave.edl
                        [env SGX_RA_SEALED_DIR]
  -v, --verbose         log every request (sizes and statuses only)
  -h, --help            print this help
  -V, --version         print the version
"
    )
}

/// Parses the arguments (without the program name). Environment defaults
/// are taken from `env`.
pub fn parse<I, E>(args: I, env: E) -> Result<Command, String>
where
    I: IntoIterator<Item = OsString>,
    E: Fn(&str) -> Option<OsString>,
{
    let mut opts = Options::default();
    if let Some(path) = env("SGX_RA_ENCLAVE").filter(|v| !v.is_empty()) {
        opts.enclave = path.into();
    }
    opts.sgx_lib_dir = env("SGX_RA_SGX_LIB_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    opts.sealed_dir = env("SGX_RA_SEALED_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg
            .into_string()
            .map_err(|a| format!("invalid argument {a:?}"))?;
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_owned(), Some(OsString::from(v))),
            _ => (arg, None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| args.next())
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "-v" | "--verbose" => opts.verbose = true,
            "--enclave" => opts.enclave = value("--enclave")?.into(),
            "--sgx-lib-dir" => opts.sgx_lib_dir = Some(value("--sgx-lib-dir")?.into()),
            "--sealed-dir" => opts.sealed_dir = Some(value("--sealed-dir")?.into()),
            "--quoter" => {
                opts.quoter = match value("--quoter")?.to_str() {
                    Some("dcap") => QuoterKind::Dcap,
                    Some("unattested-report") => QuoterKind::UnattestedReport,
                    other => {
                        return Err(format!(
                            "--quoter must be dcap or unattested-report, not {other:?}"
                        ));
                    }
                }
            }
            "--listen" => opts.listen = Some(string(value("--listen")?)?),
            "--max-sessions" => {
                opts.tcp.max_sessions = number(value("--max-sessions")?, "--max-sessions")?;
                if opts.tcp.max_sessions == 0 {
                    return Err("--max-sessions must be at least 1".into());
                }
            }
            "--idle-timeout" => {
                let secs: u64 = number(value("--idle-timeout")?, "--idle-timeout")?;
                opts.tcp.idle_timeout = (secs > 0).then(|| Duration::from_secs(secs));
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Command::Run(opts))
}

fn string(v: OsString) -> Result<String, String> {
    v.into_string().map_err(|v| format!("invalid value {v:?}"))
}

fn number<T: std::str::FromStr>(v: OsString, name: &str) -> Result<T, String> {
    let s = string(v)?;
    s.parse()
        .map_err(|_| format!("{name} needs a non-negative integer, not {s:?}"))
}

#[cfg(feature = "sgx")]
pub use self::run::{main, run};

#[cfg(feature = "sgx")]
mod run {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::ExitCode;

    use super::{Command, Options, QuoterKind, parse, usage};
    use crate::log::info;
    use crate::quoter::UnattestedReportQuoter;
    use crate::sealed_store::{self, FileSealedStore};
    use crate::sgx::{DcapConfig, DcapQuoter, SIMULATION, SgxEnclave};
    use crate::{HostError, Quoter, run_session, set_verbose, stdio, tcp};

    /// Entry point of a host app: parses `std::env::args`, serves, and
    /// maps the outcome to an exit code (0 = client closed normally,
    /// 1 = failure, 2 = usage error).
    pub fn main(name: &str) -> ExitCode {
        let cmd = parse(std::env::args_os().skip(1), |k| std::env::var_os(k));
        match cmd {
            Ok(Command::Help) => {
                print!("{}", usage(name));
                ExitCode::SUCCESS
            }
            Ok(Command::Version) => {
                let mode = if SIMULATION {
                    " (SGX simulation build)"
                } else {
                    ""
                };
                println!("{name} {}{mode}", env!("CARGO_PKG_VERSION"));
                ExitCode::SUCCESS
            }
            Ok(Command::Run(opts)) => match run(&opts) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    info!("error: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("{name}: {e}\n\n{}", usage(name));
                ExitCode::from(2)
            }
        }
    }

    /// Serves according to `opts`.
    pub fn run(opts: &Options) -> Result<(), HostError> {
        set_verbose(opts.verbose);
        if SIMULATION {
            info!("WARNING: SGX simulation build: the enclave has no hardware protection");
        }
        if let Some(dir) = &opts.sealed_dir {
            let store = FileSealedStore::open(dir)
                .map_err(|e| HostError::Config(format!("--sealed-dir {}: {e}", dir.display())))?;
            info!("sealed storage in {}", store.dir().display());
            // A second `run` in one process keeps the first directory.
            let _ = sealed_store::install(store);
        }
        match &opts.listen {
            None => {
                // First, before any SGX library is loaded: from here on
                // nothing but frames reaches the original stdout.
                let wire = stdio::claim()?;
                let mut quoter = make_quoter(opts)?;
                let mut enclave = SgxEnclave::create(&opts.enclave)?;
                info!(
                    "loaded {} (enclave id {:#x})",
                    opts.enclave.display(),
                    enclave.id()
                );
                let summary = run_session(&mut enclave, &mut quoter, wire.reader, wire.writer)?;
                info!(
                    "client closed the session after {} requests ({} failed)",
                    summary.requests, summary.failures
                );
                Ok(())
            }
            Some(addr) => {
                let quoter = make_quoter(opts)?;
                let listener = TcpListener::bind(addr)?;
                let enclave: PathBuf = opts.enclave.clone();
                // Fail at startup, not on the first connection, if the image
                // cannot be loaded.
                drop(SgxEnclave::create(&enclave)?);
                tcp::serve_tcp(
                    listener,
                    opts.tcp,
                    move || SgxEnclave::create(&enclave),
                    quoter,
                )?;
                Ok(())
            }
        }
    }

    fn make_quoter(opts: &Options) -> Result<Box<dyn Quoter + Send>, HostError> {
        Ok(match opts.quoter {
            QuoterKind::Dcap => {
                let mut config = DcapConfig::from_env();
                if let Some(dir) = &opts.sgx_lib_dir {
                    config.lib_dir = Some(dir.clone());
                }
                Box::new(DcapQuoter::load(&config)?)
            }
            QuoterKind::UnattestedReport => {
                info!(
                    "WARNING: --quoter unattested-report: announcing the raw report; \
                     this is not remote attestation (simulation tests only)"
                );
                Box::new(UnattestedReportQuoter)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(OsString::from), |_| None)
    }

    #[test]
    fn defaults_match_the_blueprint() {
        assert_eq!(p(&[]).unwrap(), Command::Run(Options::default()));
        let Command::Run(o) = p(&[]).unwrap() else {
            panic!()
        };
        assert_eq!(o.enclave, PathBuf::from("enclave.signed.so"));
        assert_eq!(o.quoter, QuoterKind::Dcap);
        assert_eq!(o.listen, None);
    }

    #[test]
    fn parses_all_options() {
        let cmd = p(&[
            "--enclave",
            "/e/enclave.signed.so",
            "--quoter=unattested-report",
            "--sgx-lib-dir",
            "/lib/sgx",
            "--listen",
            "127.0.0.1:7000",
            "--max-sessions=2",
            "--idle-timeout",
            "0",
            "--sealed-dir",
            "/var/lib/sealed",
            "-v",
        ])
        .unwrap();
        assert_eq!(
            cmd,
            Command::Run(Options {
                enclave: "/e/enclave.signed.so".into(),
                quoter: QuoterKind::UnattestedReport,
                sgx_lib_dir: Some("/lib/sgx".into()),
                listen: Some("127.0.0.1:7000".into()),
                tcp: TcpOptions {
                    max_sessions: 2,
                    idle_timeout: None
                },
                sealed_dir: Some("/var/lib/sealed".into()),
                verbose: true,
            })
        );
    }

    #[test]
    fn environment_defaults_and_overrides() {
        let env = |k: &str| match k {
            "SGX_RA_ENCLAVE" => Some(OsString::from("/env/enclave.signed.so")),
            "SGX_RA_SGX_LIB_DIR" => Some(OsString::from("/env/lib")),
            "SGX_RA_SEALED_DIR" => Some(OsString::from("/env/sealed")),
            _ => None,
        };
        let Command::Run(o) = parse(Vec::<OsString>::new(), env).unwrap() else {
            panic!()
        };
        assert_eq!(o.enclave, PathBuf::from("/env/enclave.signed.so"));
        assert_eq!(o.sgx_lib_dir, Some(PathBuf::from("/env/lib")));
        assert_eq!(o.sealed_dir, Some(PathBuf::from("/env/sealed")));
        let Command::Run(o) = parse(["--enclave", "x.so"].map(OsString::from), env).unwrap() else {
            panic!()
        };
        assert_eq!(o.enclave, PathBuf::from("x.so"));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(p(&["--quoter", "epid"]).is_err());
        assert!(p(&["--enclave"]).is_err());
        assert!(p(&["--sealed-dir"]).is_err());
        assert!(p(&["--max-sessions", "0"]).is_err());
        assert!(p(&["--idle-timeout", "-1"]).is_err());
        assert!(p(&["--frobnicate"]).is_err());
        assert_eq!(p(&["--help"]).unwrap(), Command::Help);
        assert_eq!(p(&["-V"]).unwrap(), Command::Version);
    }
}
