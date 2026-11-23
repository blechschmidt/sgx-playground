//! Enclave loading and the two ECALLs, through `libsgx_urts`.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use sgx_ra_core::sgx::report::REPORT_LEN;
use sgx_ra_core::sgx::{Report, TargetInfo};
use sgx_ra_core::wire::MAX_PAYLOAD;

use super::ffi::{self, EnclaveId, RawReport, RawTargetInfo, SUCCESS};
use crate::{EnclaveBackend, HostError};

/// A loaded enclave. Destroyed on drop.
///
/// Always launched in production mode (`debug = 0`): the framework's
/// enclaves set `DisableDebug = 1`, and a debug launch would give the host
/// read access to enclave memory.
#[derive(Debug)]
pub struct SgxEnclave {
    eid: EnclaveId,
    path: PathBuf,
}

impl SgxEnclave {
    /// `sgx_create_enclave(path, 0, …)`.
    pub fn create(path: &Path) -> Result<Self, HostError> {
        std::hint::black_box(super::ocalls::keep());
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| HostError::Config(format!("enclave path {path:?} contains NUL")))?;
        let mut token = [0u8; ffi::LAUNCH_TOKEN_LEN];
        let mut token_updated = 0;
        let mut eid: EnclaveId = 0;
        // SAFETY: every pointer refers to a live local of the declared type;
        // the path is NUL-terminated and outlives the call. misc_attr may be
        // NULL.
        let status = unsafe {
            ffi::sgx_create_enclave(
                c_path.as_ptr(),
                0,
                &mut token,
                &mut token_updated,
                &mut eid,
                ptr::null_mut(),
            )
        };
        if status != SUCCESS {
            return Err(HostError::sgx("sgx_create_enclave", status));
        }
        Ok(Self {
            eid,
            path: path.to_owned(),
        })
    }

    /// The enclave id assigned by the untrusted runtime.
    pub fn id(&self) -> u64 {
        self.eid
    }

    /// The image this enclave was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl EnclaveBackend for SgxEnclave {
    fn create_report(&mut self, qe_target: &TargetInfo) -> Result<Report, HostError> {
        let target = RawTargetInfo(*qe_target.as_bytes());
        let mut report = RawReport([0u8; REPORT_LEN]);
        let mut retval: u32 = 0;
        // SAFETY: `target` and `report` have the exact size and at least the
        // alignment of sgx_target_info_t / sgx_report_t; the bridge copies
        // `[in]` and `[out]` through the declared sizes only.
        let status =
            unsafe { ffi::enclave_create_report(self.eid, &mut retval, &target, &mut report) };
        if status != SUCCESS {
            return Err(HostError::sgx("enclave_create_report", status));
        }
        if retval != SUCCESS {
            return Err(HostError::EnclaveRejected {
                call: "enclave_create_report",
                status: retval,
            });
        }
        Ok(Report::from_bytes(&report.0).expect("exact size"))
    }

    fn message(
        &mut self,
        input: &[u8],
        output: &mut [u8; MAX_PAYLOAD],
    ) -> Result<usize, HostError> {
        if input.is_empty() || input.len() > MAX_PAYLOAD {
            return Err(HostError::Config(format!(
                "request of {} bytes is outside 1..={MAX_PAYLOAD}",
                input.len()
            )));
        }
        // The EDL declares p_data as [in, count=4096]: the bridge always
        // reads 4096 bytes, so the request is passed in a full-size buffer.
        let mut request = Box::new([0u8; MAX_PAYLOAD]);
        request[..input.len()].copy_from_slice(input);
        let mut response_len: u32 = 0;
        let mut retval: ffi::SgxStatus = 0;
        // SAFETY: both buffers are exactly 4096 bytes, matching
        // [count=4096]; input.len() <= 4096 fits in u32; the out-pointers
        // refer to live locals.
        let status = unsafe {
            ffi::enclave_message(
                self.eid,
                &mut retval,
                request.as_ptr(),
                input.len() as u32,
                output.as_mut_ptr(),
                &mut response_len,
            )
        };
        if status != SUCCESS {
            return Err(HostError::sgx("enclave_message", status));
        }
        if retval != SUCCESS {
            return Err(HostError::EnclaveRejected {
                call: "enclave_message",
                status: retval,
            });
        }
        let len = response_len as usize;
        if len > MAX_PAYLOAD {
            return Err(HostError::InvalidResponseLength(len));
        }
        Ok(len)
    }
}

impl Drop for SgxEnclave {
    fn drop(&mut self) {
        // SAFETY: `eid` came from a successful sgx_create_enclave and is
        // destroyed exactly once.
        let status = unsafe { ffi::sgx_destroy_enclave(self.eid) };
        if status != SUCCESS {
            crate::log::info!("sgx_destroy_enclave failed with status {status:#06x}");
        }
    }
}
