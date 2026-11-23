//! Host storage for sealed blobs: the untrusted side of the storage OCALLs
//! (`sgx_ra_core::storage`, `enclave-sys/sealed-storage/Enclave.edl`).
//!
//! Layout under the directory given with `--sealed-dir`:
//!
//! ```text
//! DIR/<namespace as 64 hex digits>/slot-<slot as decimal>.sealed
//! ```
//!
//! The host never interprets the blobs; they are encrypted and
//! authenticated by the enclave. Its duties are availability and
//! atomicity only:
//!
//! * directories are created `0700`, files `0600`;
//! * a blob is written to a temporary file and synced first, then put in
//!   place with `link` ([`StoreMode::CreateNew`], fails if the slot is taken,
//!   so concurrent first starts of an enclave agree on one blob) or `rename`
//!   (replace); readers see the old or the new blob, never a mix;
//! * sizes are capped at [`MAX_SEALED_BLOB_LEN`].
//!
//! File names come only from the fixed-size namespace (hex) and the slot
//! number, so the enclave cannot steer the host outside `DIR`.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

pub use sgx_ra_core::storage::{MAX_SEALED_BLOB_LEN, NAMESPACE_LEN, StorageStatus};

use crate::log::info;

/// How [`FileSealedStore::store`] treats an occupied slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
    /// Fail with [`StorageStatus::AlreadyExists`] if the slot is taken.
    CreateNew,
    /// Atomically replace.
    Replace,
}

/// Sealed blobs in a directory.
#[derive(Debug, Clone)]
pub struct FileSealedStore {
    dir: PathBuf,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl FileSealedStore {
    /// Uses (and creates, mode `0700`) `dir`.
    pub fn open(dir: &Path) -> io::Result<Self> {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        if !fs::metadata(dir)?.is_dir() {
            return Err(io::Error::other(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn namespace_dir(&self, namespace: &[u8; NAMESPACE_LEN]) -> PathBuf {
        let hex: String = namespace.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(hex)
    }

    /// The file of `slot` in `namespace`.
    pub fn path(&self, namespace: &[u8; NAMESPACE_LEN], slot: u32) -> PathBuf {
        self.namespace_dir(namespace)
            .join(format!("slot-{slot}.sealed"))
    }

    /// The blob in `slot`, if any; [`StorageStatus::TooLarge`] if it does
    /// not fit `capacity` (or [`MAX_SEALED_BLOB_LEN`]).
    pub fn load(
        &self,
        namespace: &[u8; NAMESPACE_LEN],
        slot: u32,
        capacity: usize,
    ) -> Result<Option<Vec<u8>>, StorageStatus> {
        let path = self.path(namespace, slot);
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_failure("open", &path, &e)),
        };
        let limit = capacity.min(MAX_SEALED_BLOB_LEN);
        let mut blob = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut blob)
            .map_err(|e| io_failure("read", &path, &e))?;
        if blob.len() > limit {
            return Err(StorageStatus::TooLarge);
        }
        Ok(Some(blob))
    }

    /// Stores `blob` in `slot`.
    pub fn store(
        &self,
        namespace: &[u8; NAMESPACE_LEN],
        slot: u32,
        blob: &[u8],
        mode: StoreMode,
    ) -> Result<(), StorageStatus> {
        if blob.len() > MAX_SEALED_BLOB_LEN {
            return Err(StorageStatus::TooLarge);
        }
        let dir = self.namespace_dir(namespace);
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| io_failure("create", &dir, &e))?;
        let path = self.path(namespace, slot);
        let tmp = dir.join(format!(
            ".slot-{slot}.{}.{}.tmp",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = write_synced(&tmp, blob)
            .map_err(|e| io_failure("write", &tmp, &e))
            .and_then(|()| match mode {
                StoreMode::CreateNew => match fs::hard_link(&tmp, &path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        Err(StorageStatus::AlreadyExists)
                    }
                    Err(e) => Err(io_failure("link", &path, &e)),
                },
                StoreMode::Replace => {
                    fs::rename(&tmp, &path).map_err(|e| io_failure("rename", &path, &e))
                }
            });
        // After a rename the temporary name is gone already.
        let _ = fs::remove_file(&tmp);
        if result.is_ok() {
            // Make the new directory entry durable (best effort).
            if let Ok(d) = File::open(&dir) {
                let _ = d.sync_all();
            }
        }
        result
    }
}

fn write_synced(path: &Path, blob: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(blob)?;
    f.sync_all()
}

fn io_failure(what: &str, path: &Path, e: &io::Error) -> StorageStatus {
    info!("sealed storage: cannot {what} {}: {e}", path.display());
    StorageStatus::Io
}

static GLOBAL: OnceLock<FileSealedStore> = OnceLock::new();

/// Makes `store` the process-wide store the storage OCALLs use. Can be
/// called once; later calls fail.
pub fn install(store: FileSealedStore) -> Result<(), FileSealedStore> {
    GLOBAL.set(store)
}

/// The installed store, if any. Without one the OCALLs answer
/// [`StorageStatus::Unavailable`] and enclaves fall back to non-persistent
/// behaviour.
pub fn installed() -> Option<&'static FileSealedStore> {
    GLOBAL.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("sgx-ra-sealed-store-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const NS: [u8; 32] = [0xab; 32];

    #[test]
    fn create_replace_load() {
        let tmp = TempDir::new("basic");
        let store = FileSealedStore::open(&tmp.0.join("sub")).unwrap();
        assert_eq!(store.load(&NS, 0, 100).unwrap(), None);
        store.store(&NS, 0, b"one", StoreMode::CreateNew).unwrap();
        assert_eq!(
            store.store(&NS, 0, b"two", StoreMode::CreateNew),
            Err(StorageStatus::AlreadyExists)
        );
        assert_eq!(store.load(&NS, 0, 100).unwrap().unwrap(), b"one");
        store.store(&NS, 0, b"two", StoreMode::Replace).unwrap();
        assert_eq!(store.load(&NS, 0, 100).unwrap().unwrap(), b"two");
        assert_eq!(store.load(&NS, 1, 100).unwrap(), None);
        assert_eq!(store.load(&[0; 32], 0, 100).unwrap(), None);

        // Path layout, permissions, no temporary files left behind.
        let path = store.path(&NS, 0);
        assert_eq!(
            path,
            store.dir().join("ab".repeat(32)).join("slot-0.sealed")
        );
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(store.dir()), 0o700);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        let entries = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(entries, 1);
    }

    #[test]
    fn size_limits() {
        let tmp = TempDir::new("limits");
        let store = FileSealedStore::open(&tmp.0).unwrap();
        let big = vec![1u8; MAX_SEALED_BLOB_LEN + 1];
        assert_eq!(
            store.store(&NS, 0, &big, StoreMode::Replace),
            Err(StorageStatus::TooLarge)
        );
        store.store(&NS, 0, &[2u8; 10], StoreMode::Replace).unwrap();
        assert_eq!(store.load(&NS, 0, 9), Err(StorageStatus::TooLarge));
        assert_eq!(store.load(&NS, 0, 10).unwrap().unwrap().len(), 10);
        // A file planted by someone else beyond the cap.
        fs::write(store.path(&NS, 1), &big).unwrap();
        assert_eq!(store.load(&NS, 1, usize::MAX), Err(StorageStatus::TooLarge));
    }

    #[test]
    fn concurrent_create_has_one_winner() {
        let tmp = TempDir::new("race");
        let store = FileSealedStore::open(&tmp.0).unwrap();
        let winners: usize = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8u8)
                .map(|i| {
                    let store = &store;
                    s.spawn(move || store.store(&NS, 0, &[i; 16], StoreMode::CreateNew).is_ok())
                })
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum()
        });
        assert_eq!(winners, 1);
        let blob = store.load(&NS, 0, 100).unwrap().unwrap();
        assert!(blob.iter().all(|&b| b == blob[0]));
    }
}
