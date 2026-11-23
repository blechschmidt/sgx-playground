//! Test helpers shared by the protocol tests.

use sha2::{Digest, Sha256};

use crate::handshake::IdentityKey;
use crate::rng::{Rng, RngError};
use crate::sgx::{Quote, ReportBody};

/// The recorded DCAP v3 quote of the blueprint enclave.
pub const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");

/// Offset of report_data in a report body.
const REPORT_DATA_OFFSET: usize = 320;

/// Deterministic test RNG: SHA-256(seed ‖ counter) blocks. Not for
/// production use.
pub struct TestRng {
    seed: u8,
    counter: u64,
}

impl TestRng {
    pub fn new(seed: u8) -> Self {
        Self { seed, counter: 0 }
    }
}

impl Rng for TestRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        for chunk in dst.chunks_mut(32) {
            let block = Sha256::new()
                .chain_update([self.seed])
                .chain_update(self.counter.to_be_bytes())
                .finalize();
            self.counter += 1;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

/// An RNG that always fails.
pub struct FailingRng;

impl Rng for FailingRng {
    fn fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), RngError> {
        Err(RngError { code: 0x1234 })
    }
}

/// The fixture's report body with report_data replaced by `identity`'s
/// commitment, as the enclave's report would look.
pub fn attested_body(identity: &IdentityKey) -> ReportBody {
    let mut raw = *Quote::parse(QUOTE_V3).unwrap().report_body().as_bytes();
    raw[REPORT_DATA_OFFSET..].copy_from_slice(identity.report_data().as_bytes());
    ReportBody::from_array(raw)
}
