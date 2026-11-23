//! Shared, `no_std` + `alloc` building blocks of the `sgx-ra` framework.
//!
//! This crate is used on both sides of the trust boundary: inside the SGX
//! enclave (`sgx-ra-enclave`) and on the untrusted host / remote client
//! (`sgx-ra-host`, `sgx-ra-verifier`, `sgx-ra-client`). It contains no I/O and
//! no platform code, so all of it is unit-testable on an ordinary build host.
//!
//! * [`sgx`]: strict, offset-based parsers for DCAP quotes (v3 and v4, SGX
//!   TEE), the SGX report body, `TARGETINFO`/`REPORT`, and the enclave
//!   signature structure (`SIGSTRUCT` and the `sgx_sign gendata` output).
//! * [`wire`]: layer-1 framing of the remote executor protocol
//!   (`docs/PROTOCOL.md` §2).
//! * [`binding`]: the commitment of the enclave's channel key in
//!   report_data (`docs/PROTOCOL.md` §6.2).
//! * [`handshake`]: messages and key exchange of the attested channel
//!   protocol "SGXRA v1" (`docs/PROTOCOL.md` §6.3–6.4).
//! * [`record`]: the record layer: per-direction ChaCha20-Poly1305 with
//!   counter nonces, replay and reordering rejection (§6.5).
//! * [`session`]: transport-agnostic protocol endpoints: the enclave state
//!   machine [`EnclaveEndpoint`] and the client [`ClientChannel`].
//! * [`attestation`]: the reusable framework traits [`Attester`],
//!   [`Verifier`] and [`Policy`], the verified claims they exchange, and the
//!   standard [`EnclavePolicy`].
//! * [`channel`]: the [`SecureChannel`] trait.
//! * [`rng`]: the [`Rng`] abstraction (`sgx_read_rand` in the enclave,
//!   the OS RNG on the client).
//! * [`storage`]: the sealing key policies and the contract of the
//!   sealed-blob storage OCALLs (`docs/SEALING.md`).
//! * [`identity`]: the optional sealed long-term identity key and its
//!   in-session proof of possession (`docs/SEALING.md`).
//!
//! All integers inside SGX structures are little-endian; all integers on the
//! wire are big-endian.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod attestation;
pub mod binding;
pub mod channel;
pub mod handshake;
pub mod hex;
pub mod identity;
pub mod record;
pub mod rng;
pub mod session;
pub mod sgx;
pub mod storage;
pub mod wire;

mod reader;
#[cfg(test)]
mod testutil;

pub use attestation::{
    Attester, EnclaveIdentity, EnclavePolicy, Policy, PolicyViolation, TcbStatus, TcbStatusSet,
    VerifiedClaims, Verifier,
};
pub use channel::{AttestedChannel, SecureChannel};
pub use handshake::{ClientHandshake, HandshakeError, IdentityKey};
pub use record::{RecordError, Session};
pub use rng::{Rng, RngError};
pub use session::{ClientChannel, EnclaveEndpoint, MessageTransport};
pub use sgx::{Measurement, ReportData};
