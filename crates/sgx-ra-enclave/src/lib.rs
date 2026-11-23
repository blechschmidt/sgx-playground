//! Enclave-side runtime of the `sgx-ra` framework.
//!
//! An enclave application is a `#![no_std]` Rust `staticlib` that implements
//! [`EnclaveApp`] and invokes [`export_enclave!`]. It is linked against the
//! Intel SGX SDK trusted runtime (`sgx_trts`, `sgx_tstdc`, `sgx_tservice`) and
//! the edger8r glue for the blueprint `Enclave.edl`, then measured and signed
//! with `sgx_sign`, producing an `enclave.signed.so` that the existing remote
//! executor host can load unchanged (`docs/ARCHITECTURE.md` §3.2).
//!
//! This crate provides:
//!
//! * [`EnclaveApp`]: the only trait an application implements. It sees
//!   decrypted requests; the handshake, record protection and the identity
//!   key are handled by the framework.
//! * [`SgxAllocator`]: a global allocator backed by the SDK's tlibc heap.
//! * [`abort`] and a panic handler (installed by [`export_enclave!`]) that
//!   abort the enclave; unwinding is not supported.
//! * [`export_enclave!`]: emits the two ECALL entry points of `Enclave.edl`
//!   (`enclave_create_report`, `enclave_message`), backed by [`Runtime`].
//! * Safe wrappers over the trusted runtime: [`SgxRng`] (`sgx_read_rand`),
//!   [`SgxAttester`] (`sgx_create_report`) and [`sealing`]
//!   (`sgx_seal_data_ex`/`sgx_unseal_data` with the MRENCLAVE or MRSIGNER
//!   key policy).
//! * [`storage`]: untrusted storage for sealed blobs: the host's, through
//!   the OCALLs of `enclave-sys/sealed-storage/Enclave.edl` (feature
//!   `sealed-storage`), or in enclave memory.
//! * [`identity`]: an optional long-term identity key, sealed and
//!   persisted, that clients can pin across restarts while every session
//!   is still attested with a fresh channel key (`docs/SEALING.md`).
//!
//! The enclave image itself is linked and signed by `enclave-sys/build.sh`
//! (see `enclave-sys/README.md`).

#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod allocator;
mod app;
mod ffi;
pub mod identity;
mod platform;
pub mod runtime;
pub mod sealing;
pub mod storage;

pub use allocator::SgxAllocator;
pub use app::{AppError, EnclaveApp, MAX_RESPONSE_LEN, SessionContext};
pub use platform::{SgxAttester, SgxRng, SgxStatus, create_report, read_rand};
pub use runtime::{EcallError, Runtime};
pub use sgx_ra_core;

mod abort_ffi {
    unsafe extern "C" {
        /// tRTS `abort`: puts the enclave into the crashed state.
        pub(crate) fn abort() -> !;
    }
}

/// Aborts the enclave. All further ECALLs into this enclave instance fail,
/// so no secret state can be observed after a panic.
pub fn abort() -> ! {
    // SAFETY: `abort` takes no arguments and never returns; it is provided
    // by the SGX SDK tlibc inside the enclave (and by libc in host tests).
    unsafe { abort_ffi::abort() }
}

/// Registers an [`EnclaveApp`] implementation: emits the ECALL entry points
/// and installs the enclave's global allocator and panic handler.
///
/// Use it exactly once, in the enclave's `staticlib` crate:
///
/// ```ignore
/// #![cfg_attr(not(test), no_std)]
/// sgx_ra_enclave::export_enclave!(MyApp);
/// ```
///
/// The generated symbols, called by the edger8r bridge `Enclave_t.c`:
///
/// ```c
/// uint32_t     enclave_create_report(const sgx_target_info_t*, sgx_report_t*);
/// sgx_status_t enclave_message(const uint8_t*, uint32_t, uint8_t*, uint32_t*);
/// ```
///
/// The ECALLs, allocator and panic handler are omitted under `cfg(test)`, so
/// the application crate can be unit-tested on the build host with `std`.
#[macro_export]
macro_rules! export_enclave {
    ($app:ty) => {
        const _: () = {
            const fn assert_enclave_app<T: $crate::EnclaveApp + ::core::marker::Send>() {}
            assert_enclave_app::<$app>();
        };

        #[cfg(not(test))]
        static __SGX_RA_RUNTIME: $crate::Runtime<$app> = $crate::Runtime::new();

        /// ECALL `enclave_create_report` (see `sgx_ra_enclave::runtime`).
        ///
        /// # Safety
        ///
        /// Only to be called by the edger8r bridge.
        #[cfg(not(test))]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn enclave_create_report(
            p_qe3_target: *const u8,
            p_report: *mut u8,
        ) -> u32 {
            // SAFETY: the bridge passes trusted copies of the EDL buffers.
            unsafe {
                $crate::runtime::ecall_create_report(&__SGX_RA_RUNTIME, p_qe3_target, p_report)
            }
        }

        /// ECALL `enclave_message` (see `sgx_ra_enclave::runtime`).
        ///
        /// # Safety
        ///
        /// Only to be called by the edger8r bridge.
        #[cfg(not(test))]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn enclave_message(
            p_data: *const u8,
            data_size: u32,
            p_response: *mut u8,
            p_response_size: *mut u32,
        ) -> u32 {
            // SAFETY: the bridge passes trusted copies of the EDL buffers.
            unsafe {
                $crate::runtime::ecall_message(
                    &__SGX_RA_RUNTIME,
                    p_data,
                    data_size,
                    p_response,
                    p_response_size,
                )
            }
        }

        #[cfg(not(test))]
        #[global_allocator]
        static __SGX_RA_GLOBAL_ALLOCATOR: $crate::SgxAllocator = $crate::SgxAllocator;

        #[cfg(not(test))]
        #[panic_handler]
        fn __sgx_ra_panic(_info: &::core::panic::PanicInfo<'_>) -> ! {
            $crate::abort()
        }
    };
}
