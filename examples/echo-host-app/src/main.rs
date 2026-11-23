//! Example untrusted host for the echo enclave: the Rust port of the
//! blueprint `server/App/App.cpp`.
//!
//! It loads `enclave.signed.so` (from the working directory unless
//! `--enclave` says otherwise), announces its DCAP quote and relays
//! requests on stdin/stdout, so it runs unchanged behind the remote
//! executor's `stunnel` `exec`. `--listen ADDR` serves TCP instead. All the
//! logic lives in `sgx-ra-host`; see `--help`.
//!
//! The host is untrusted. It never handles a key: the echo enclave's
//! identity and session keys stay inside the enclave and the host only
//! forwards ciphertext.

use std::process::ExitCode;

#[cfg(feature = "sgx")]
fn main() -> ExitCode {
    sgx_ra_host::cli::main(env!("CARGO_PKG_NAME"))
}

#[cfg(not(feature = "sgx"))]
fn main() -> ExitCode {
    // All diagnostics go to stderr: stdout is the wire (docs/PROTOCOL.md Q5).
    eprintln!(
        "{}: built without the `sgx` feature, so there is no SGX backend. \
         Build with `nix build .#host-app` or `cargo build --features sgx` \
         (needs the Intel SGX SDK, see crates/sgx-ra-host/build.rs).",
        env!("CARGO_PKG_NAME")
    );
    ExitCode::from(2)
}
