//! The application interface of an enclave.

use alloc::vec::Vec;
use core::fmt;

use sgx_ra_core::handshake::{MAX_RECORD_PLAINTEXT, PUBLIC_KEY_LEN};

/// Largest response an [`EnclaveApp`] may produce: one record's plaintext.
pub const MAX_RESPONSE_LEN: usize = MAX_RECORD_PLAINTEXT;

/// An application running inside the enclave behind the attested channel.
///
/// The framework calls [`EnclaveApp::handle`] once per decrypted request
/// and encrypts the response. Requests and responses are at most
/// [`MAX_RESPONSE_LEN`] bytes; a longer response is treated as an error.
pub trait EnclaveApp: Sized + 'static {
    /// Creates the application state. Called once per enclave instance,
    /// after the enclave identity key exists.
    fn init() -> Self;

    /// Handles one request, appending the reply to `response` (initially
    /// empty).
    ///
    /// Returning an error terminates the secure session: the framework
    /// wipes the session keys and the host reports a failure status. Error
    /// details never leave the enclave.
    fn handle(&mut self, request: &[u8], response: &mut Vec<u8>) -> Result<(), AppError>;

    /// [`EnclaveApp::handle`] with facts about the attested session. This
    /// is what the framework calls; the default ignores the context.
    /// Override it to bind application statements to the session, e.g. a
    /// long-term identity proof ([`crate::identity::LongTermIdentity::prove`]).
    fn handle_with_context(
        &mut self,
        context: &SessionContext,
        request: &[u8],
        response: &mut Vec<u8>,
    ) -> Result<(), AppError> {
        let _ = context;
        self.handle(request, response)
    }
}

/// The attested session a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionContext {
    identity_public: [u8; PUBLIC_KEY_LEN],
}

impl SessionContext {
    /// Context of a session whose channel key is `identity_public`.
    pub const fn new(identity_public: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self { identity_public }
    }

    /// This instance's channel identity key `ek_pub`: the key committed to
    /// in the attested report_data, which the client already holds
    /// (`EnclaveChannel::enclave_public_key`).
    pub fn identity_public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.identity_public
    }
}

/// An application-level failure. Its message is for in-enclave diagnostics
/// only and is never sent to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppError {
    message: &'static str,
}

impl AppError {
    /// Creates an error with a static description.
    pub const fn new(message: &'static str) -> Self {
        Self { message }
    }

    /// The description.
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl core::error::Error for AppError {}
