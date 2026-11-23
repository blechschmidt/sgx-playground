//! Hand-written bindings: `sgx_urts.h`, the edger8r-generated
//! `Enclave_u.h` of `enclave-sys/Enclave.edl`, `sgx_dcap_ql_wrapper.h` and
//! the libc dynamic loader.
//!
//! SGX structures cross the boundary as opaque, suitably aligned byte
//! arrays; their layout is parsed by `sgx_ra_core::sgx`.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_void};

use sgx_ra_core::sgx::report::{REPORT_LEN, TARGET_INFO_LEN};

/// `sgx_enclave_id_t`.
pub(crate) type EnclaveId = u64;
/// `sgx_status_t`.
pub(crate) type SgxStatus = u32;
/// `quote3_error_t`.
pub(crate) type Quote3Error = u32;

/// `SGX_SUCCESS` / `SGX_QL_SUCCESS`.
pub(crate) const SUCCESS: u32 = 0;
/// `sgx_launch_token_t` size.
pub(crate) const LAUNCH_TOKEN_LEN: usize = 1024;

/// `sgx_target_info_t`.
#[repr(C, align(16))]
pub(crate) struct RawTargetInfo(pub(crate) [u8; TARGET_INFO_LEN]);

/// `sgx_report_t`.
#[repr(C, align(16))]
pub(crate) struct RawReport(pub(crate) [u8; REPORT_LEN]);

unsafe extern "C" {
    // libsgx_urts / libsgx_urts_sim
    pub(crate) fn sgx_create_enclave(
        file_name: *const c_char,
        debug: c_int,
        launch_token: *mut [u8; LAUNCH_TOKEN_LEN],
        launch_token_updated: *mut c_int,
        enclave_id: *mut EnclaveId,
        misc_attr: *mut c_void,
    ) -> SgxStatus;
    pub(crate) fn sgx_destroy_enclave(enclave_id: EnclaveId) -> SgxStatus;

    // Enclave_u.c (edger8r, enclave-sys/Enclave.edl)
    pub(crate) fn enclave_create_report(
        eid: EnclaveId,
        retval: *mut u32,
        p_qe3_target: *const RawTargetInfo,
        p_report: *mut RawReport,
    ) -> SgxStatus;
    /// Both buffers are `[count=4096]`: the bridge copies 4096 bytes from
    /// `p_data` and to/from `p_response`, whatever `data_size` says.
    pub(crate) fn enclave_message(
        eid: EnclaveId,
        retval: *mut SgxStatus,
        p_data: *const u8,
        data_size: u32,
        p_response: *mut u8,
        p_response_size: *mut u32,
    ) -> SgxStatus;

    // libc dynamic loader
    pub(crate) fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    pub(crate) fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    pub(crate) fn dlerror() -> *const c_char;
}

/// `RTLD_NOW`.
pub(crate) const RTLD_NOW: c_int = 2;

// libsgx_dcap_ql function types (resolved with dlsym).

/// `sgx_ql_request_policy_t::SGX_QL_PERSISTENT`.
pub(crate) const SGX_QL_PERSISTENT: u32 = 0;

/// `sgx_ql_path_type_t`.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub(crate) enum QlPathType {
    Qe3 = 0,
    Pce = 1,
    Qpl = 2,
    Ide = 3,
}

pub(crate) type SetEnclaveLoadPolicyFn = unsafe extern "C" fn(policy: u32) -> Quote3Error;
pub(crate) type SetPathFn =
    unsafe extern "C" fn(path_type: u32, path: *const c_char) -> Quote3Error;
pub(crate) type GetTargetInfoFn = unsafe extern "C" fn(target: *mut RawTargetInfo) -> Quote3Error;
pub(crate) type GetQuoteSizeFn = unsafe extern "C" fn(size: *mut u32) -> Quote3Error;
pub(crate) type GetQuoteFn =
    unsafe extern "C" fn(report: *const RawReport, size: u32, quote: *mut u8) -> Quote3Error;
pub(crate) type CleanupByPolicyFn = unsafe extern "C" fn() -> Quote3Error;
