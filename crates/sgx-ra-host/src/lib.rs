//! Untrusted host side of the `sgx-ra` framework.
//!
//! The host loads the enclave, obtains a quote for it and relays layer-1
//! frames ([`sgx_ra_core::wire`], `docs/PROTOCOL.md` §2) between the client
//! and the enclave. It is **not** trusted: everything it relays is either
//! signed by Intel's quoting enclave or protected by the attested channel.
//! It never sees a key: the identity key and the session keys exist only in
//! the enclave, and the host only forwards ciphertext.
//!
//! The SGX-specific operations sit behind two traits so the serving logic
//! can be tested without SGX hardware:
//!
//! * [`EnclaveBackend`]: the two ECALLs of the blueprint `Enclave.edl`.
//! * [`Quoter`]: the DCAP quote library (`sgx_qe_get_target_info`,
//!   `sgx_qe_get_quote`).
//!
//! The real implementations, [`sgx::SgxEnclave`] (`libsgx_urts` and the
//! edger8r bridge) and [`sgx::DcapQuoter`] (`libsgx_dcap_ql`), are behind
//! the `sgx` cargo feature. Everything else is plain Rust:
//!
//! * [`serve`]: one session of the executor protocol over any
//!   `Read`/`Write` pair. It is wire-compatible with the blueprint
//!   `App.cpp`, without its quirks (bounded reads, clean EOF handling,
//!   write errors propagated).
//! * [`stdio`]: claims stdin/stdout as the wire and points fd 1 at stderr,
//!   so no library `printf` can corrupt the stream (quirks Q5/Q6). This is
//!   the mode for the operator's `stunnel` `exec`.
//! * [`tcp`]: a TCP listener with one enclave instance per connection,
//!   for local testing and containers without stunnel.
//! * [`cli`]: the command line every host app shares; an application's
//!   `main` is a single call to `cli::main`.
//! * [`sealed_store`]: a directory of sealed blobs behind the storage
//!   OCALLs (`--sealed-dir`); the blobs are opaque to the host.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;
use std::io;

pub use sgx_ra_core;

use sgx_ra_core::sgx::{Report, TargetInfo};
use sgx_ra_core::wire::{MAX_PAYLOAD, WireError};

pub mod cli;
mod log;
pub mod quoter;
pub mod sealed_store;
pub mod serve;
pub mod stdio;
pub mod tcp;

#[cfg(feature = "sgx")]
pub mod sgx;

pub use log::set_verbose;
pub use serve::{SessionSummary, attest, run_session, serve_session};

/// The ECALL interface of a framework enclave (blueprint `Enclave.edl`).
pub trait EnclaveBackend {
    /// ECALL `enclave_create_report`: creates a report targeted at
    /// `qe_target` whose report data binds the enclave's identity key.
    fn create_report(&mut self, qe_target: &TargetInfo) -> Result<Report, HostError>;

    /// ECALL `enclave_message`: passes one request payload into the enclave
    /// and returns the length of the response written to `output`.
    fn message(&mut self, input: &[u8], output: &mut [u8; MAX_PAYLOAD])
    -> Result<usize, HostError>;
}

impl<E: EnclaveBackend + ?Sized> EnclaveBackend for Box<E> {
    fn create_report(&mut self, qe_target: &TargetInfo) -> Result<Report, HostError> {
        (**self).create_report(qe_target)
    }

    fn message(
        &mut self,
        input: &[u8],
        output: &mut [u8; MAX_PAYLOAD],
    ) -> Result<usize, HostError> {
        (**self).message(input, output)
    }
}

/// The quoting stack: turns an enclave report into the bytes the host
/// announces to the client (normally a DCAP quote).
pub trait Quoter {
    /// Target info of the quoting enclave.
    fn target_info(&mut self) -> Result<TargetInfo, HostError>;

    /// Converts a report targeted at the quoting enclave into a quote.
    fn quote(&mut self, report: &Report) -> Result<Vec<u8>, HostError>;
}

impl<Q: Quoter + ?Sized> Quoter for Box<Q> {
    fn target_info(&mut self) -> Result<TargetInfo, HostError> {
        (**self).target_info()
    }

    fn quote(&mut self, report: &Report) -> Result<Vec<u8>, HostError> {
        (**self).quote(report)
    }
}

/// Host-side failures.
#[derive(Debug)]
pub enum HostError {
    /// An SGX SDK or DCAP call failed.
    Sgx {
        /// Name of the failing call.
        call: &'static str,
        /// The returned `sgx_status_t` / `quote3_error_t`.
        status: u32,
    },
    /// The enclave rejected a request: the ECALL itself succeeded but the
    /// enclave returned a non-success status.
    EnclaveRejected {
        /// Name of the ECALL.
        call: &'static str,
        /// The enclave's return value.
        status: u32,
    },
    /// The enclave reported a response larger than its output buffer.
    InvalidResponseLength(usize),
    /// A runtime library could not be loaded or lacks a symbol.
    Library {
        /// What was being loaded.
        what: String,
        /// The loader's message.
        reason: String,
    },
    /// Invalid host configuration (paths, options).
    Config(String),
    /// Framing violation by the peer.
    Wire(WireError),
    /// The peer closed the connection in the middle of a request.
    TruncatedRequest,
    /// I/O on the client connection failed.
    Io(io::Error),
}

impl HostError {
    /// Shorthand for [`HostError::Sgx`].
    pub fn sgx(call: &'static str, status: u32) -> Self {
        Self::Sgx { call, status }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sgx { call, status } => write!(f, "{call} failed with status {status:#06x}"),
            Self::EnclaveRejected { call, status } => {
                write!(f, "enclave rejected {call} with status {status:#06x}")
            }
            Self::InvalidResponseLength(len) => write!(
                f,
                "enclave reported a {len}-byte response (limit {MAX_PAYLOAD})"
            ),
            Self::Library { what, reason } => write!(f, "cannot load {what}: {reason}"),
            Self::Config(msg) => f.write_str(msg),
            Self::Wire(e) => write!(f, "framing error: {e}"),
            Self::TruncatedRequest => f.write_str("connection closed in the middle of a request"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<WireError> for HostError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

impl From<io::Error> for HostError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
