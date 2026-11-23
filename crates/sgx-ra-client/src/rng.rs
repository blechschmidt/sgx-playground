//! The client's [`Rng`]: the operating system's CSPRNG.

use sgx_ra_core::rng::{Rng, RngError};

/// Randomness from the OS (`getrandom(2)` on Linux).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        getrandom::getrandom(dst).map_err(|e| RngError {
            code: e.code().get(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_output() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        OsRng.fill_bytes(&mut a).unwrap();
        OsRng.fill_bytes(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
