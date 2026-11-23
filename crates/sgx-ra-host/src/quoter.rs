//! Quoters that need no SGX library.

use sgx_ra_core::sgx::report::TARGET_INFO_LEN;
use sgx_ra_core::sgx::{Report, TargetInfo};

use crate::{HostError, Quoter};

/// **Testing only.** Announces the raw 432-byte `sgx_report_t` instead of
/// a quote, with the report targeted at an all-zero target info.
///
/// This is what an SGX simulation setup can offer (there is no quoting
/// enclave in simulation mode), and it matches the announcement of
/// `enclave-sys/sim/sim_host`, so the simulation end-to-end test
/// (`crates/sgx-ra-client/tests/sim_enclave.rs`) runs against the real
/// host. Nothing about it is attested: a report's MAC can only be checked
/// by its target enclave, and no verifier accepts a bare report.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnattestedReportQuoter;

impl Quoter for UnattestedReportQuoter {
    fn target_info(&mut self) -> Result<TargetInfo, HostError> {
        Ok(TargetInfo::from_bytes(&[0u8; TARGET_INFO_LEN]).expect("exact size"))
    }

    fn quote(&mut self, report: &Report) -> Result<Vec<u8>, HostError> {
        Ok(report.as_bytes().to_vec())
    }
}
