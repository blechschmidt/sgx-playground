//! Client side of the `sgx-ra` framework.
//!
//! A client (1) obtains the expected MRENCLAVE from a trusted source,
//! normally a local reproducible build ([`ReproducibleBuild`], or any
//! [`MeasurementSource`]), (2) connects to the untrusted host over a
//! [`Transport`] (TCP or TLS, never trusted) and reads the quote
//! ([`ExecutorConnection`]), (3) verifies the quote with a
//! [`sgx_ra_core::Verifier`] against an [`sgx_ra_core::EnclavePolicy`], and
//! (4) runs the SGXRA v1 handshake to obtain an [`EnclaveChannel`] whose
//! key is bound to the attested report data. [`attest_and_connect`] does
//! steps 2–4 in one call.
//!
//! Quote verification is [`DcapVerifier`] (crate `sgx-ra-verifier`) with
//! collateral from a [`PccsClient`]: a PCCS (default
//! [`DEFAULT_PCCS_URL`], HTTP or HTTPS with a custom CA) or Intel PCS
//! directly. See [`dcap_verifier`].
//!
//! Enclaves with a sealed long-term identity (`docs/SEALING.md`) can be
//! pinned across restarts with [`identity_pin`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod build;
pub mod connect;
pub mod error;
pub mod executor;
pub mod identity_pin;
pub mod measurement;
pub mod pccs;
pub mod rng;
pub mod transport;

pub use build::{BuildError, BuildOutput, ContainerEngine, ReproducibleBuild};
pub use connect::{ConnectError, EnclaveChannel, attest_and_connect};
pub use error::ClientError;
pub use executor::{ExecutorConnection, ExecutorError};
pub use identity_pin::{IdentityPin, PinError, PinOutcome, verify_assertion};
pub use measurement::{FixedMeasurement, GendataFile, MeasurementSource};
pub use pccs::{
    CollateralService, DEFAULT_PCCS_URL, INTEL_PCS_URL, PccsClient, PccsConfig, PccsError,
};
pub use rng::OsRng;
pub use sgx_ra_core;
pub use sgx_ra_verifier;
pub use sgx_ra_verifier::{DcapVerifier, VerifiedQuote, VerifierOptions, VerifyError};
pub use transport::{TlsVerification, Transport, TransportError};

/// A DCAP verifier fetching collateral from the service described by
/// `config`.
pub fn dcap_verifier(
    config: PccsConfig,
    options: VerifierOptions,
) -> Result<DcapVerifier<PccsClient>, PccsError> {
    Ok(DcapVerifier::new(PccsClient::new(config)?).with_options(options))
}
