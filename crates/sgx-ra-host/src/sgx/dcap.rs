//! DCAP quote generation through `libsgx_dcap_ql` (Intel DCAP 1.23).
//!
//! The library is loaded with `dlopen` rather than linked, so a host binary
//! starts (and can report a clear error) on machines without DCAP, and a
//! simulation build never pulls the hardware runtime into the process.
//!
//! Like `App.cpp`, the quoter runs in **in-process** mode: QE3, PCE and the
//! ID enclave are loaded into this process from Intel's signed images,
//! which needs `/dev/sgx_enclave` and `/dev/sgx_provision`, and the quote
//! provider library (QPL) fetches the PCK certificate data from the service
//! configured in `/etc/sgx_default_qcnl.conf`: Intel's PCS v4 in our host
//! image (no API key needed, docs/NO_API_KEY.md) or a PCCS. If `SGX_AESM_ADDR` is set,
//! the library uses out-of-process mode (AESM) instead and none of the
//! paths are set, also as in `App.cpp`.

#![allow(unsafe_code)]

use std::env;
use std::ffi::{CStr, CString, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use sgx_ra_core::sgx::report::{REPORT_LEN, TARGET_INFO_LEN};
use sgx_ra_core::sgx::{Report, TargetInfo};
use sgx_ra_core::wire::MAX_QUOTE_LEN;

use super::ffi::{self, QlPathType, RawReport, RawTargetInfo, SUCCESS};
use crate::log::{debug, info};
use crate::{HostError, Quoter};

/// File name of the quote library.
pub const DCAP_QL_LIB: &str = "libsgx_dcap_ql.so.1";
const QE3_IMAGE: &str = "libsgx_qe3.signed.so.1";
const PCE_IMAGE: &str = "libsgx_pce.signed.so.1";
const IDE_IMAGE: &str = "libsgx_id_enclave.signed.so.1";
const QPL_LIB: &str = "libdcap_quoteprov.so.1";

/// Distribution directories tried when no library directory is configured
/// (Debian/Ubuntu, then RHEL), as in `App.cpp`.
const SYSTEM_LIB_DIRS: [&str; 2] = ["/usr/lib/x86_64-linux-gnu", "/usr/lib64"];

/// Where the DCAP runtime lives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DcapConfig {
    /// Directory containing `libsgx_dcap_ql.so.1`, the signed QE3/PCE/IDE
    /// images and `libdcap_quoteprov.so.1`. `None`: the dynamic linker's
    /// search path for the library and the distribution directories for
    /// the enclaves.
    pub lib_dir: Option<PathBuf>,
}

impl DcapConfig {
    /// `SGX_RA_SGX_LIB_DIR` if set, else the directory baked in at build
    /// time (`SGX_RA_DEFAULT_SGX_LIB_DIR`, set by the Nix build), else
    /// `None`.
    pub fn from_env() -> Self {
        let lib_dir = env::var_os("SGX_RA_SGX_LIB_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| option_env!("SGX_RA_DEFAULT_SGX_LIB_DIR").map(PathBuf::from));
        Self { lib_dir }
    }
}

/// [`Quoter`] backed by `libsgx_dcap_ql`.
#[derive(Debug)]
pub struct DcapQuoter {
    get_target_info: ffi::GetTargetInfoFn,
    get_quote_size: ffi::GetQuoteSizeFn,
    get_quote: ffi::GetQuoteFn,
    cleanup_by_policy: ffi::CleanupByPolicyFn,
    in_process: bool,
}

impl DcapQuoter {
    /// Loads the library and, in in-process mode, configures the enclave
    /// load policy and the QE3/PCE/IDE/QPL paths.
    pub fn load(config: &DcapConfig) -> Result<Self, HostError> {
        if super::SIMULATION {
            return Err(HostError::Config(
                "this host is built for SGX simulation (SGX_MODE=SIM): DCAP quoting is unavailable"
                    .into(),
            ));
        }
        let lib_path = match &config.lib_dir {
            Some(dir) => dir.join(DCAP_QL_LIB),
            None => PathBuf::from(DCAP_QL_LIB),
        };
        let handle = dl_open(&lib_path)?;
        let what = lib_path.display().to_string();
        // SAFETY: these are the C functions of sgx_dcap_ql_wrapper.h, and
        // the fn pointer types in `ffi` match their DCAP 1.23 signatures.
        let (set_policy, set_path, quoter) = unsafe {
            let set_policy: ffi::SetEnclaveLoadPolicyFn =
                dl_fn(handle, &what, c"sgx_qe_set_enclave_load_policy")?;
            let set_path: ffi::SetPathFn = dl_fn(handle, &what, c"sgx_ql_set_path")?;
            let quoter = Self {
                get_target_info: dl_fn(handle, &what, c"sgx_qe_get_target_info")?,
                get_quote_size: dl_fn(handle, &what, c"sgx_qe_get_quote_size")?,
                get_quote: dl_fn(handle, &what, c"sgx_qe_get_quote")?,
                cleanup_by_policy: dl_fn(handle, &what, c"sgx_qe_cleanup_by_policy")?,
                in_process: env::var_os("SGX_AESM_ADDR").is_none(),
            };
            (set_policy, set_path, quoter)
        };
        debug!("loaded {what}");

        if !quoter.in_process {
            info!("SGX_AESM_ADDR is set: quoting through AESM (out-of-process mode)");
            return Ok(quoter);
        }
        // SAFETY: plain enum argument.
        let status = unsafe { set_policy(ffi::SGX_QL_PERSISTENT) };
        check("sgx_qe_set_enclave_load_policy", status)?;
        configure_paths(set_path, config.lib_dir.as_deref())?;
        Ok(quoter)
    }
}

impl Quoter for DcapQuoter {
    fn target_info(&mut self) -> Result<TargetInfo, HostError> {
        let mut target = RawTargetInfo([0u8; TARGET_INFO_LEN]);
        // SAFETY: `target` is a properly sized and aligned sgx_target_info_t.
        let status = unsafe { (self.get_target_info)(&mut target) };
        check("sgx_qe_get_target_info", status)?;
        Ok(TargetInfo::from_bytes(&target.0).expect("exact size"))
    }

    fn quote(&mut self, report: &Report) -> Result<Vec<u8>, HostError> {
        let mut size: u32 = 0;
        // SAFETY: valid out-pointer.
        let status = unsafe { (self.get_quote_size)(&mut size) };
        check("sgx_qe_get_quote_size", status)?;
        let len = size as usize;
        if len == 0 || len > MAX_QUOTE_LEN {
            return Err(HostError::Config(format!(
                "sgx_qe_get_quote_size returned an implausible size {len}"
            )));
        }
        let raw_report = RawReport(*report.as_bytes());
        debug_assert_eq!(raw_report.0.len(), REPORT_LEN);
        let mut quote = vec![0u8; len];
        // SAFETY: `raw_report` is a properly sized and aligned sgx_report_t;
        // `quote` is exactly `size` writable bytes.
        let status = unsafe { (self.get_quote)(&raw_report, size, quote.as_mut_ptr()) };
        check("sgx_qe_get_quote", status)?;
        Ok(quote)
    }
}

impl Drop for DcapQuoter {
    fn drop(&mut self) {
        if self.in_process {
            // SAFETY: no arguments; releases the persistently loaded QE3/PCE.
            let status = unsafe { (self.cleanup_by_policy)() };
            if status != SUCCESS {
                info!("sgx_qe_cleanup_by_policy failed with status {status:#06x}");
            }
        }
    }
}

fn check(call: &'static str, status: u32) -> Result<(), HostError> {
    if status == SUCCESS {
        Ok(())
    } else {
        Err(HostError::sgx(call, status))
    }
}

/// Points the library at Intel's signed QE3/PCE/IDE images and the QPL.
fn configure_paths(set_path: ffi::SetPathFn, lib_dir: Option<&Path>) -> Result<(), HostError> {
    let candidates: Vec<PathBuf> = match lib_dir {
        Some(dir) => vec![dir.to_owned()],
        None => SYSTEM_LIB_DIRS.iter().map(PathBuf::from).collect(),
    };
    let set = |kind: QlPathType, path: &Path| -> bool {
        if !path.is_file() {
            return false;
        }
        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: NUL-terminated path that outlives the call; the library
        // copies it.
        let status = unsafe { set_path(kind as u32, c_path.as_ptr()) };
        if status != SUCCESS {
            info!(
                "sgx_ql_set_path({kind:?}, {}) failed with status {status:#06x}",
                path.display()
            );
        }
        status == SUCCESS
    };

    let Some(dir) = candidates.iter().find(|dir| {
        set(QlPathType::Pce, &dir.join(PCE_IMAGE))
            && set(QlPathType::Qe3, &dir.join(QE3_IMAGE))
            && set(QlPathType::Ide, &dir.join(IDE_IMAGE))
    }) else {
        let tried = candidates
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if lib_dir.is_some() {
            return Err(HostError::Config(format!(
                "{PCE_IMAGE}, {QE3_IMAGE} and {IDE_IMAGE} are not all in {tried}"
            )));
        }
        info!("QE3/PCE/IDE images not found in {tried}; using libsgx_dcap_ql's default lookup");
        return Ok(());
    };
    debug!("QE3/PCE/IDE images: {}", dir.display());

    if !set(QlPathType::Qpl, &dir.join(QPL_LIB)) {
        // Not fatal, as in App.cpp: without a QPL the quote carries the
        // encrypted PPID instead of the PCK certificate chain.
        info!(
            "warning: no {QPL_LIB} in {}: quotes will carry the encrypted PPID (cert type 3)",
            dir.display()
        );
    }
    Ok(())
}

fn dl_open(path: &Path) -> Result<*mut c_void, HostError> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| HostError::Config(format!("library path {path:?} contains NUL")))?;
    // SAFETY: NUL-terminated path. Loading runs the library's constructors,
    // which is the point. The handle is never closed: the library stays
    // loaded for the life of the process.
    let handle = unsafe { ffi::dlopen(c_path.as_ptr(), ffi::RTLD_NOW) };
    if handle.is_null() {
        return Err(HostError::Library {
            what: path.display().to_string(),
            reason: dl_error(),
        });
    }
    Ok(handle)
}

/// Resolves `symbol` as a function pointer of type `F`.
///
/// # Safety
///
/// `F` must be an `extern "C"` fn pointer type matching the symbol's real
/// signature.
unsafe fn dl_fn<F: Copy>(handle: *mut c_void, what: &str, symbol: &CStr) -> Result<F, HostError> {
    const { assert!(size_of::<F>() == size_of::<*mut c_void>()) };
    // SAFETY: `handle` is a live dlopen handle; `symbol` is NUL-terminated.
    let ptr = unsafe { ffi::dlsym(handle, symbol.as_ptr()) };
    if ptr.is_null() {
        return Err(HostError::Library {
            what: what.to_owned(),
            reason: format!(
                "missing symbol {}: {}",
                symbol.to_string_lossy(),
                dl_error()
            ),
        });
    }
    // SAFETY: non-null code address of the symbol; the caller guarantees
    // that `F` is its signature, and the sizes match (checked above).
    Ok(unsafe { std::mem::transmute_copy::<*mut c_void, F>(&ptr) })
}

fn dl_error() -> String {
    // SAFETY: dlerror returns NULL or a NUL-terminated, thread-local string
    // that stays valid until the next dl* call on this thread; it is copied
    // immediately.
    unsafe {
        let msg = ffi::dlerror();
        if msg.is_null() {
            "unknown error".to_owned()
        } else {
            CStr::from_ptr(msg).to_string_lossy().into_owned()
        }
    }
}
