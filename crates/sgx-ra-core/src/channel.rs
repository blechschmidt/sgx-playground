//! The secure channel abstraction.

use alloc::vec::Vec;
use core::fmt;

use crate::attestation::VerifiedClaims;

/// An encrypted, integrity-protected, framed message channel.
///
/// Every message is delivered whole, in order, exactly once; any tampering,
/// replay or reordering makes the channel fail permanently (there is no
/// downgrade to plaintext). Messages are limited to
/// [`SecureChannel::max_message_len`] bytes; larger application data must be
/// chunked by the caller.
pub trait SecureChannel {
    /// Error type.
    type Error: fmt::Debug + fmt::Display;

    /// Largest plaintext accepted by [`SecureChannel::send`].
    fn max_message_len(&self) -> usize;

    /// Encrypts and sends one message.
    fn send(&mut self, plaintext: &[u8]) -> Result<(), Self::Error>;

    /// Receives and decrypts one message.
    fn recv(&mut self) -> Result<Vec<u8>, Self::Error>;

    /// Sends one message and waits for the reply, matching the strict
    /// request/response lockstep of the remote executor.
    fn request(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.send(plaintext)?;
        self.recv()
    }
}

/// A channel whose remote end has been attested.
///
/// Implemented by client-side channels: the peer's claims were verified, and
/// the channel keys were bound to the report data in those claims.
pub trait AttestedChannel: SecureChannel {
    /// The verified claims about the enclave at the other end.
    fn peer_claims(&self) -> &VerifiedClaims;
}
