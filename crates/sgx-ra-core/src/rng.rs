//! Randomness abstraction shared by enclave and client.

use core::fmt;

/// Failure of the underlying random number generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError {
    /// Platform-specific error code (e.g. an `sgx_status_t`), or 0.
    pub code: u32,
}

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "random number generator failed (code {:#x})", self.code)
    }
}

impl core::error::Error for RngError {}

/// A cryptographically secure random number generator.
///
/// The enclave implements it with `sgx_read_rand` (RDRAND inside the
/// enclave, never host-provided); the client with the OS RNG. Failures must
/// be reported, never papered over with weak randomness.
pub trait Rng {
    /// Fills `dst` with random bytes.
    fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError>;
}

impl<R: Rng + ?Sized> Rng for &mut R {
    fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        (**self).fill_bytes(dst)
    }
}
