//! The attest-then-connect flow.
//!
//! ```text
//! ExecutorConnection::read_quote   quote announcement (layer 1)
//! Verifier::verify(quote, policy)  DCAP signature chain + policy → VerifiedClaims
//! EnclaveChannel::establish        SGXRA v1 handshake: the enclave key must be the
//!                                  one committed to in the attested report_data,
//!                                  and the enclave must prove it holds it
//! ```
//!
//! [`attest_and_connect`] runs all three steps. Applications that want to
//! report each step (like the `echo-client` example) call them one by one;
//! the types make it impossible to open a channel without
//! [`VerifiedClaims`].

use std::fmt;
use std::sync::{Arc, OnceLock};

use sgx_ra_core::attestation::{Policy, VerifiedClaims, Verifier};
use sgx_ra_core::channel::{AttestedChannel, SecureChannel};
use sgx_ra_core::handshake::{HelloReply, PUBLIC_KEY_LEN};
use sgx_ra_core::rng::Rng;
use sgx_ra_core::session::{ChannelError, ClientChannel, MessageTransport};

use crate::executor::{ExecutorConnection, ExecutorError};
use crate::transport::Transport;

/// Passes messages through and keeps a copy of the first received one
/// (the `HELLO_REPLY`), so the enclave's identity key can be reported.
struct ReplyTap<M> {
    inner: M,
    first_reply: Arc<OnceLock<Vec<u8>>>,
}

impl<M: MessageTransport> MessageTransport for ReplyTap<M> {
    type Error = M::Error;

    fn send(&mut self, message: &[u8]) -> Result<(), M::Error> {
        self.inner.send(message)
    }

    fn recv(&mut self) -> Result<Vec<u8>, M::Error> {
        let payload = self.inner.recv()?;
        if self.first_reply.get().is_none() {
            let _ = self.first_reply.set(payload.clone());
        }
        Ok(payload)
    }
}

/// An established attested channel to an enclave.
///
/// Wraps [`ClientChannel`]; additionally exposes the enclave's channel
/// identity key, which the handshake proved is the key committed to in the
/// attested report_data.
pub struct EnclaveChannel<M: MessageTransport> {
    inner: ClientChannel<ReplyTap<M>>,
    enclave_public_key: [u8; PUBLIC_KEY_LEN],
}

impl<M: MessageTransport> EnclaveChannel<M> {
    /// Runs the SGXRA v1 handshake over `transport` against the enclave
    /// described by `claims`, which must come from verifying the quote
    /// received on this same connection.
    pub fn establish(
        transport: M,
        claims: VerifiedClaims,
        rng: &mut impl Rng,
    ) -> Result<Self, ChannelError<M::Error>> {
        let first_reply = Arc::new(OnceLock::new());
        let tap = ReplyTap {
            inner: transport,
            first_reply: Arc::clone(&first_reply),
        };
        let inner = ClientChannel::connect(tap, claims, rng)?;
        // `connect` only succeeds after decoding and checking this reply.
        let reply = first_reply
            .get()
            .and_then(|payload| HelloReply::decode(payload).ok())
            .expect("a successful handshake received a well-formed HELLO_REPLY");
        Ok(Self {
            inner,
            enclave_public_key: reply.identity_public,
        })
    }

    /// The enclave's X25519 channel identity key. Its hash is the attested
    /// report_data (`docs/PROTOCOL.md` §6.2), and the enclave proved
    /// possession of the private key during the handshake.
    pub fn enclave_public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.enclave_public_key
    }
}

impl<M: MessageTransport> SecureChannel for EnclaveChannel<M> {
    type Error = ChannelError<M::Error>;

    fn max_message_len(&self) -> usize {
        self.inner.max_message_len()
    }

    fn send(&mut self, plaintext: &[u8]) -> Result<(), Self::Error> {
        self.inner.send(plaintext)
    }

    fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.inner.recv()
    }
}

impl<M: MessageTransport> AttestedChannel for EnclaveChannel<M> {
    fn peer_claims(&self) -> &VerifiedClaims {
        self.inner.peer_claims()
    }
}

impl<M: MessageTransport> fmt::Debug for EnclaveChannel<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnclaveChannel")
            .field("inner", &self.inner)
            .field(
                "enclave_public_key",
                &sgx_ra_core::hex::Hex(&self.enclave_public_key),
            )
            .finish()
    }
}

/// Failures of [`attest_and_connect`].
#[derive(Debug)]
pub enum ConnectError<E> {
    /// Receiving the quote failed (including remote diagnostics).
    Executor(ExecutorError),
    /// The quote failed verification or the policy rejected it.
    Verification(E),
    /// The handshake failed (e.g. the enclave key is not the attested one).
    Channel(ChannelError<ExecutorError>),
}

impl<E: fmt::Display> fmt::Display for ConnectError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Executor(e) => write!(f, "receiving the quote failed: {e}"),
            Self::Verification(e) => write!(f, "attestation rejected: {e}"),
            Self::Channel(e) => write!(f, "attested channel handshake failed: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for ConnectError<E> {}

/// Reads the quote from `transport`, verifies it with `verifier` against
/// `policy`, and establishes the attested channel.
pub fn attest_and_connect<T: Transport, V: Verifier>(
    transport: T,
    verifier: &V,
    policy: &dyn Policy,
    rng: &mut impl Rng,
) -> Result<EnclaveChannel<ExecutorConnection<T>>, ConnectError<V::Error>> {
    let mut conn = ExecutorConnection::new(transport);
    let quote = conn.read_quote().map_err(ConnectError::Executor)?;
    let claims = verifier
        .verify(&quote, policy)
        .map_err(ConnectError::Verification)?;
    EnclaveChannel::establish(conn, claims, rng).map_err(ConnectError::Channel)
}
