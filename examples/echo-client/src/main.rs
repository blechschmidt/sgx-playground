//! Example client for the echo enclave: the Rust counterpart of the
//! blueprint's `sgx-client/main.py`, built on `sgx-ra-client`.
//!
//! ```text
//! echo-client [OPTIONS]                       build → attest → secure channel → echo
//! echo-client inspect-quote <quote.dat> …     offline inspection (no verification)
//! echo-client inspect-gendata <file>
//! echo-client inspect-sigstruct <file>
//! ```
//!
//! The default flow:
//!
//! 1. **Expected MRENCLAVE.** Rebuild the enclave from source with the
//!    reproducible Nix container (`docker build -f
//!    containers/Dockerfile.nix-build --output type=local,dest=<tmp> .`) and
//!    read MRENCLAVE from the exported `enclave.so.gendata`.
//!    `--gendata-path` uses an existing gendata file, `--expected-mrenclave`
//!    a pinned value; both skip the build.
//! 2. **Transport.** Connect to the executor with TLS (rustls, Mozilla
//!    roots). TLS ends outside the enclave, so it is only a pipe.
//! 3. **Attestation.** Receive the DCAP quote, verify it against the pinned
//!    Intel SGX Root CA with collateral from Intel PCS or a PCCS, and apply
//!    the policy (MRENCLAVE = local build, no debug, allowed TCB status).
//! 4. **Channel.** SGXRA v1 handshake: the enclave's channel key must hash
//!    to the attested report_data and the enclave must prove it holds the
//!    private key. Then exchange encrypted messages.
//!
//! Every check is reported as an `[OK]` line on stdout; any failure prints
//! `[FAIL]` on stderr and exits non-zero (see [`exit`]).

mod args;
mod inspect;
mod logger;
mod run;

use std::process::ExitCode;

use clap::Parser;

use crate::args::{Cli, Command};

/// Process exit codes.
pub mod exit {
    /// Everything verified; all echoes matched.
    pub const OK: u8 = 0;
    /// A verification step, the channel, or the echo failed.
    pub const FAILURE: u8 = 1;
    /// Invalid command line (clap's convention).
    pub const USAGE: u8 = 2;
    /// The remote host could not produce a quote (it sent a DCAP error
    /// text instead). Nothing about the enclave was learned.
    pub const REMOTE_UNAVAILABLE: u8 = 3;
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    logger::init(cli.loglevel);
    match cli.command {
        Some(Command::InspectQuote(a)) => inspect::quote(&a),
        Some(Command::InspectGendata { path }) => inspect::gendata(&path),
        Some(Command::InspectSigstruct { path }) => inspect::sigstruct(&path),
        None => run::run(&cli.connect),
    }
}
