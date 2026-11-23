//! Untrusted storage for sealed blobs.
//!
//! [`SealedStorage`] is what the enclave asks the host to keep. Everything
//! coming back is untrusted: callers must unseal (which authenticates) and
//! must tolerate missing, stale or replayed blobs. See `docs/SEALING.md`.
//!
//! * [`OcallStorage`] (feature `sealed-storage`): the host's store, reached
//!   through the OCALLs of `enclave-sys/sealed-storage/Enclave.edl`. Link
//!   the enclave with that EDL (`enclave-sys/build.sh --edl …`, or
//!   `mkEnclave { edl = …; }`). The `sgx-ra-host` CLI serves them with
//!   `--sealed-dir`; a host without them (e.g. the blueprint C++ `app`)
//!   makes every call fail with [`StorageError::Unavailable`].
//! * [`MemoryStorage`]: an in-enclave map, for tests and for applications
//!   that only need sealing within one instance.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

pub use sgx_ra_core::storage::{MAX_SEALED_BLOB_LEN, NAMESPACE_LEN, StorageStatus};

use crate::platform::SgxStatus;

/// How [`SealedStorage::store`] treats an occupied slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
    /// Fail with [`StorageError::AlreadyExists`] if the slot is taken. The
    /// host implements this atomically, so two instances racing to create
    /// the same blob agree on one winner.
    CreateNew,
    /// Overwrite (atomically: readers see the old or the new blob).
    Replace,
}

/// Storage failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// The host has no sealed storage (not configured, or its OCALL table
    /// lacks the storage OCALLs).
    Unavailable,
    /// [`StoreMode::CreateNew`] and the slot is taken.
    AlreadyExists,
    /// The blob exceeds [`MAX_SEALED_BLOB_LEN`].
    TooLarge,
    /// The host answered inconsistently (e.g. a length beyond the buffer).
    Malformed,
    /// The host reported another failure.
    Host(StorageStatus),
    /// The OCALL transition itself failed.
    Ocall(SgxStatus),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("sealed storage unavailable on this host"),
            Self::AlreadyExists => f.write_str("sealed storage slot already taken"),
            Self::TooLarge => f.write_str("sealed blob too large for storage"),
            Self::Malformed => f.write_str("host returned a malformed storage answer"),
            Self::Host(status) => write!(f, "sealed storage: {status}"),
            Self::Ocall(status) => write!(f, "storage OCALL failed: {status}"),
        }
    }
}

impl core::error::Error for StorageError {}

/// Untrusted storage of sealed blobs, addressed by a namespace
/// ([`sgx_ra_core::storage::namespace`]) and a slot number.
pub trait SealedStorage {
    /// The blob in `slot`, `None` if there is none.
    fn load(
        &mut self,
        namespace: &[u8; NAMESPACE_LEN],
        slot: u32,
    ) -> Result<Option<Vec<u8>>, StorageError>;

    /// Stores `blob` in `slot`.
    fn store(
        &mut self,
        namespace: &[u8; NAMESPACE_LEN],
        slot: u32,
        blob: &[u8],
        mode: StoreMode,
    ) -> Result<(), StorageError>;
}

impl<S: SealedStorage + ?Sized> SealedStorage for &mut S {
    fn load(
        &mut self,
        namespace: &[u8; NAMESPACE_LEN],
        slot: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        (**self).load(namespace, slot)
    }

    fn store(
        &mut self,
        namespace: &[u8; NAMESPACE_LEN],
        slot: u32,
        blob: &[u8],
        mode: StoreMode,
    ) -> Result<(), StorageError> {
        (**self).store(namespace, slot, blob, mode)
    }
}

/// Sealed blobs kept in enclave memory (lost when the instance ends).
#[derive(Debug, Default, Clone)]
pub struct MemoryStorage {
    blobs: BTreeMap<([u8; NAMESPACE_LEN], u32), Vec<u8>>,
}

impl MemoryStorage {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SealedStorage for MemoryStorage {
    fn load(
        &mut self,
        namespace: &[u8; NAMESPACE_LEN],
        slot: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.blobs.get(&(*namespace, slot)).cloned())
    }

    fn store(
        &mut self,
        namespace: &[u8; NAMESPACE_LEN],
        slot: u32,
        blob: &[u8],
        mode: StoreMode,
    ) -> Result<(), StorageError> {
        if blob.len() > MAX_SEALED_BLOB_LEN {
            return Err(StorageError::TooLarge);
        }
        let key = (*namespace, slot);
        if mode == StoreMode::CreateNew && self.blobs.contains_key(&key) {
            return Err(StorageError::AlreadyExists);
        }
        self.blobs.insert(key, blob.to_vec());
        Ok(())
    }
}

/// The host's sealed storage, through the storage OCALLs.
#[cfg(feature = "sealed-storage")]
#[derive(Debug, Default, Clone, Copy)]
pub struct OcallStorage;

#[cfg(feature = "sealed-storage")]
mod ocall {
    use super::*;
    use crate::ffi;
    use alloc::vec;

    /// `SGX_ERROR_INVALID_FUNCTION`: the host's OCALL table has no such
    /// entry (a host built for the plain `Enclave.edl`).
    const INVALID_FUNCTION: SgxStatus = SgxStatus(0x1001);

    fn host_status(transition: u32, retval: u32) -> Result<StorageStatus, StorageError> {
        match SgxStatus::check(transition) {
            Ok(()) => {}
            Err(INVALID_FUNCTION) => return Err(StorageError::Unavailable),
            Err(status) => return Err(StorageError::Ocall(status)),
        }
        match StorageStatus::from_code(retval) {
            Some(StorageStatus::Unavailable) => Err(StorageError::Unavailable),
            Some(status) => Ok(status),
            None => Err(StorageError::Host(StorageStatus::Io)),
        }
    }

    impl SealedStorage for OcallStorage {
        fn load(
            &mut self,
            namespace: &[u8; NAMESPACE_LEN],
            slot: u32,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            // The bridge copies the whole capacity back into enclave memory
            // after the OCALL returns, so the host cannot race our parsing.
            let mut buf = vec![0u8; MAX_SEALED_BLOB_LEN];
            let mut len = 0usize;
            let mut retval = u32::MAX;
            // SAFETY: all pointers refer to live enclave buffers of the
            // sizes the EDL declares (32-byte namespace, `capacity` bytes,
            // one size_t); the bridge marshals them through untrusted memory.
            let transition = unsafe {
                ffi::sgx_ra_ocall_load_sealed(
                    &mut retval,
                    namespace.as_ptr(),
                    slot,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut len,
                )
            };
            match host_status(transition, retval)? {
                StorageStatus::Ok if len <= buf.len() => {
                    buf.truncate(len);
                    Ok(Some(buf))
                }
                StorageStatus::Ok => Err(StorageError::Malformed),
                StorageStatus::NotFound => Ok(None),
                StorageStatus::TooLarge => Err(StorageError::TooLarge),
                status => Err(StorageError::Host(status)),
            }
        }

        fn store(
            &mut self,
            namespace: &[u8; NAMESPACE_LEN],
            slot: u32,
            blob: &[u8],
            mode: StoreMode,
        ) -> Result<(), StorageError> {
            if blob.len() > MAX_SEALED_BLOB_LEN {
                return Err(StorageError::TooLarge);
            }
            let mut retval = u32::MAX;
            // SAFETY: the namespace and blob are live enclave buffers of the
            // declared sizes; the bridge copies them out.
            let transition = unsafe {
                ffi::sgx_ra_ocall_store_sealed(
                    &mut retval,
                    namespace.as_ptr(),
                    slot,
                    blob.as_ptr(),
                    blob.len(),
                    u32::from(mode == StoreMode::Replace),
                )
            };
            match host_status(transition, retval)? {
                StorageStatus::Ok => Ok(()),
                StorageStatus::AlreadyExists => Err(StorageError::AlreadyExists),
                StorageStatus::TooLarge => Err(StorageError::TooLarge),
                status => Err(StorageError::Host(status)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: [u8; 32] = [7; 32];

    fn exercise(storage: &mut impl SealedStorage) {
        assert_eq!(storage.load(&NS, 1).unwrap(), None);
        storage.store(&NS, 1, b"one", StoreMode::CreateNew).unwrap();
        assert_eq!(
            storage.store(&NS, 1, b"two", StoreMode::CreateNew),
            Err(StorageError::AlreadyExists)
        );
        assert_eq!(storage.load(&NS, 1).unwrap().unwrap(), b"one");
        storage.store(&NS, 1, b"two", StoreMode::Replace).unwrap();
        assert_eq!(storage.load(&NS, 1).unwrap().unwrap(), b"two");
        // Slots and namespaces are separate.
        assert_eq!(storage.load(&NS, 2).unwrap(), None);
        assert_eq!(storage.load(&[8; 32], 1).unwrap(), None);
        let big = alloc::vec![0u8; MAX_SEALED_BLOB_LEN + 1];
        assert_eq!(
            storage.store(&NS, 3, &big, StoreMode::Replace),
            Err(StorageError::TooLarge)
        );
    }

    #[test]
    fn memory_storage() {
        exercise(&mut MemoryStorage::new());
    }

    #[cfg(feature = "sealed-storage")]
    #[test]
    fn ocall_storage() {
        use crate::ffi::fake::{FAKE_HOST, FAKE_STORE, FakeHost};
        FAKE_STORE.with(|s| s.borrow_mut().clear());
        exercise(&mut OcallStorage);

        FAKE_HOST.with(|h| h.set(FakeHost::LiesAboutLength));
        assert_eq!(OcallStorage.load(&NS, 1), Err(StorageError::Malformed));
        FAKE_HOST.with(|h| h.set(FakeHost::NoOcalls));
        assert_eq!(OcallStorage.load(&NS, 1), Err(StorageError::Unavailable));
        assert_eq!(
            OcallStorage.store(&NS, 1, b"x", StoreMode::Replace),
            Err(StorageError::Unavailable)
        );
        FAKE_HOST.with(|h| h.set(FakeHost::Storage));
    }
}
