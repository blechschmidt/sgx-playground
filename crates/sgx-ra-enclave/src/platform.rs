//! Safe wrappers around the SGX trusted runtime: status codes, randomness
//! (`sgx_read_rand`) and local attestation (`sgx_create_report`).

use core::fmt;

use sgx_ra_core::attestation::Attester;
use sgx_ra_core::rng::{Rng, RngError};
use sgx_ra_core::sgx::{Report, ReportData, TargetInfo};

use crate::ffi;

/// An `sgx_status_t` value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SgxStatus(pub u32);

impl SgxStatus {
    /// `SGX_SUCCESS`.
    pub const SUCCESS: Self = Self(0x0000);
    /// `SGX_ERROR_UNEXPECTED`.
    pub const UNEXPECTED: Self = Self(0x0001);
    /// `SGX_ERROR_INVALID_PARAMETER`.
    pub const INVALID_PARAMETER: Self = Self(0x0002);
    /// `SGX_ERROR_OUT_OF_MEMORY`.
    pub const OUT_OF_MEMORY: Self = Self(0x0003);
    /// `SGX_ERROR_INVALID_STATE`.
    pub const INVALID_STATE: Self = Self(0x0005);
    /// `SGX_ERROR_MAC_MISMATCH` (sealed data failed authentication).
    pub const MAC_MISMATCH: Self = Self(0x3001);

    /// Converts a raw status into `Ok(())` for `SGX_SUCCESS`, `Err` otherwise.
    pub fn check(raw: u32) -> Result<(), Self> {
        if raw == Self::SUCCESS.0 {
            Ok(())
        } else {
            Err(Self(raw))
        }
    }

    /// The raw value.
    pub fn code(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for SgxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SgxStatus({:#06x})", self.0)
    }
}

impl fmt::Display for SgxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sgx_status_t {:#06x}", self.0)
    }
}

impl core::error::Error for SgxStatus {}

impl From<SgxStatus> for RngError {
    fn from(status: SgxStatus) -> Self {
        RngError { code: status.0 }
    }
}

/// Fills `dst` from the CPU's hardware RNG (`RDRAND`, via `sgx_read_rand`).
///
/// The bytes never pass through the untrusted host.
pub fn read_rand(dst: &mut [u8]) -> Result<(), SgxStatus> {
    if dst.is_empty() {
        return Ok(());
    }
    // SAFETY: `dst` is a valid, writable buffer of `dst.len()` bytes.
    SgxStatus::check(unsafe { ffi::sgx_read_rand(dst.as_mut_ptr(), dst.len()) })
}

/// The enclave's [`Rng`]: `sgx_read_rand`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SgxRng;

impl Rng for SgxRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        read_rand(dst).map_err(RngError::from)
    }
}

/// Creates a report (`EREPORT`) of the calling enclave for `target`
/// carrying `report_data` verbatim.
pub fn create_report(target: &TargetInfo, report_data: &ReportData) -> Result<Report, SgxStatus> {
    let mut raw = [0u8; sgx_ra_core::sgx::report::REPORT_LEN];
    // SAFETY: all three pointers reference live, correctly sized buffers;
    // the SDK copies them into aligned scratch space before EREPORT.
    let status = unsafe {
        ffi::sgx_create_report(
            target.as_bytes(),
            report_data.as_bytes(),
            &mut raw as *mut ffi::RawReport,
        )
    };
    SgxStatus::check(status)?;
    Report::from_bytes(&raw).map_err(|_| SgxStatus::UNEXPECTED)
}

/// The SGX [`Attester`]: local reports targeted at one enclave, normally
/// the quoting enclave whose target info the host passed in.
#[derive(Debug, Clone, Copy)]
pub struct SgxAttester {
    target: TargetInfo,
}

impl SgxAttester {
    /// An attester producing reports for `target`.
    pub fn new(target: TargetInfo) -> Self {
        Self { target }
    }
}

impl Attester for SgxAttester {
    type Evidence = Report;
    type Error = SgxStatus;

    fn attest(&mut self, report_data: &ReportData) -> Result<Report, SgxStatus> {
        let report = create_report(&self.target, report_data)?;
        // EREPORT copies report_data verbatim; anything else means the
        // runtime is broken, and binding a key to it would be unsafe.
        if report.body().report_data() != *report_data {
            return Err(SgxStatus::UNEXPECTED);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn rng_fills_and_reports_failures() {
        let mut buf = [0u8; 64];
        SgxRng.fill_bytes(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 64]);

        ffi::fake::FAIL_RAND.with(|f| f.set(Some(0x0001)));
        assert_eq!(SgxRng.fill_bytes(&mut buf), Err(RngError { code: 1 }));
        // Empty requests never reach the runtime.
        read_rand(&mut []).unwrap();
    }

    #[test]
    fn attester_embeds_report_data() {
        let target = TargetInfo::from_bytes(&[7u8; 512]).unwrap();
        let mut report_data = ReportData::ZERO;
        report_data.0[..4].copy_from_slice(b"abcd");
        let report = SgxAttester::new(target).attest(&report_data).unwrap();
        assert_eq!(report.body().report_data(), report_data);
        assert_eq!(report.key_id()[0], 7);
    }

    #[test]
    fn status_check() {
        assert_eq!(SgxStatus::check(0), Ok(()));
        assert_eq!(SgxStatus::check(2), Err(SgxStatus::INVALID_PARAMETER));
        assert_eq!(SgxStatus(0x3001).to_string(), "sgx_status_t 0x3001");
    }
}
