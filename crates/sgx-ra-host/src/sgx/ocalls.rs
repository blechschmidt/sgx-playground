//! Untrusted implementations of the storage OCALLs declared in
//! `enclave-sys/sealed-storage/Enclave.edl`, called by the edger8r bridge
//! `Enclave_u.c`. They serve [`crate::sealed_store::installed`].
//!
//! Everything arriving here comes from the enclave via the bridge, which
//! has already copied the `[in]` buffers into untrusted memory and will copy
//! the `[out]` buffers back. The pointers are therefore host memory of the
//! declared sizes; they are still checked for null.

#![allow(unsafe_code)]

use sgx_ra_core::storage::{NAMESPACE_LEN, StorageStatus};

use crate::log::info;
use crate::sealed_store::{self, StoreMode};

/// `sgx_ra_ocall_load_sealed`.
///
/// # Safety
///
/// Called by the edger8r bridge only: `p_namespace` points to 32 readable
/// bytes, `p_blob` to `capacity` writable bytes and `p_blob_len` to a
/// writable `size_t` (or any of them is null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sgx_ra_ocall_load_sealed(
    p_namespace: *const u8,
    slot: u32,
    p_blob: *mut u8,
    capacity: usize,
    p_blob_len: *mut usize,
) -> u32 {
    let Some(store) = sealed_store::installed() else {
        return StorageStatus::Unavailable.code();
    };
    if p_namespace.is_null() || p_blob.is_null() || p_blob_len.is_null() {
        return StorageStatus::InvalidArgument.code();
    }
    // SAFETY: non-null and 32 bytes per the EDL ([in, count=32]).
    let namespace = unsafe { *p_namespace.cast::<[u8; NAMESPACE_LEN]>() };
    match store.load(&namespace, slot, capacity) {
        Ok(Some(blob)) => {
            // SAFETY: `blob.len() <= capacity` (checked by `load`), and the
            // bridge provides `capacity` writable bytes and a size_t.
            unsafe {
                std::ptr::copy_nonoverlapping(blob.as_ptr(), p_blob, blob.len());
                p_blob_len.write_unaligned(blob.len());
            }
            info!("sealed storage: loaded slot {slot} ({} bytes)", blob.len());
            StorageStatus::Ok.code()
        }
        Ok(None) => StorageStatus::NotFound.code(),
        Err(status) => status.code(),
    }
}

/// `sgx_ra_ocall_store_sealed`.
///
/// # Safety
///
/// Called by the edger8r bridge only: `p_namespace` points to 32 readable
/// bytes and `p_blob` to `blob_len` readable bytes (or either is null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sgx_ra_ocall_store_sealed(
    p_namespace: *const u8,
    slot: u32,
    p_blob: *const u8,
    blob_len: usize,
    replace: u32,
) -> u32 {
    let Some(store) = sealed_store::installed() else {
        return StorageStatus::Unavailable.code();
    };
    if p_namespace.is_null() || p_blob.is_null() {
        return StorageStatus::InvalidArgument.code();
    }
    if blob_len > sealed_store::MAX_SEALED_BLOB_LEN {
        return StorageStatus::TooLarge.code();
    }
    // SAFETY: non-null and of the sizes the EDL declares.
    let (namespace, blob) = unsafe {
        (
            *p_namespace.cast::<[u8; NAMESPACE_LEN]>(),
            std::slice::from_raw_parts(p_blob, blob_len),
        )
    };
    let mode = if replace != 0 {
        StoreMode::Replace
    } else {
        StoreMode::CreateNew
    };
    match store.store(&namespace, slot, blob, mode) {
        Ok(()) => {
            info!("sealed storage: stored slot {slot} ({blob_len} bytes, {mode:?})");
            StorageStatus::Ok.code()
        }
        Err(status) => status.code(),
    }
}

/// Keeps the OCALL symbols in the link even if the linker considers this
/// object unused before it sees `Enclave_u.o`.
pub(crate) fn keep() -> [usize; 2] {
    [
        sgx_ra_ocall_load_sealed as usize,
        sgx_ra_ocall_store_sealed as usize,
    ]
}
