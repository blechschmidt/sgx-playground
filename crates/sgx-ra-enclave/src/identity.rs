//! The optional long-term identity key `LK`, sealed and persisted through
//! [`SealedStorage`] (`docs/SEALING.md`).
//!
//! The channel key `EK` stays per instance and is attested in every quote
//! (`sgx_ra_core::binding`). `LK` is an additional X25519 key that survives
//! restarts, so clients can pin `lk_pub`. The enclave asserts it inside an
//! attested session with [`LongTermIdentity::prove`]
//! (`sgx_ra_core::identity`), which ties the assertion to that session's
//! `ek_pub` and a fresh client challenge.
//!
//! [`LongTermIdentity::load_or_create`]:
//!
//! 1. derives the storage namespace from this enclave's own report
//!    (`sgx_self_report`) and the key policy;
//! 2. loads the blob in the configured slot and unseals it with exactly that
//!    policy, checking that the authenticated additional data names this
//!    purpose, policy, slot and the key's own public half;
//! 3. if there is none, generates `LK` with `sgx_read_rand`, seals it and
//!    stores it with [`StoreMode::CreateNew`]. If another instance won the
//!    race, its key is loaded instead, so concurrent first starts agree;
//! 4. if the blob came from a lower ISVSVN, re-seals it at the current one.
//!
//! Failure handling, chosen to keep the key stable rather than silently
//! rotate it:
//!
//! * no storage on this host: a fresh key with origin
//!   [`IdentityOrigin::Ephemeral`], which clients must not pin;
//! * a blob that exists but cannot be opened (tampered, other CPU, CPU TCB
//!   rolled back, …): [`IdentityError::Unreadable`]. The enclave does not
//!   overwrite it; the operator decides whether to delete it and rotate.

use alloc::vec::Vec;
use core::fmt;

use sgx_ra_core::handshake::{IdentityKey, PUBLIC_KEY_LEN};
use sgx_ra_core::hex::Hex;
use sgx_ra_core::identity::{self as proof, IdentityAssertion, IdentityProofError};
use sgx_ra_core::rng::{Rng, RngError};
use sgx_ra_core::sgx::{Measurement, Report, ReportBody};
use sgx_ra_core::storage::{KeyPolicy, NAMESPACE_LEN, namespace};
use zeroize::Zeroizing;

pub use sgx_ra_core::identity::IdentityOrigin;

use crate::ffi;
use crate::sealing::{self, SealError};
use crate::storage::{SealedStorage, StorageError, StoreMode};

/// Domain separator in the additional data of a sealed identity blob.
pub const IDENTITY_BLOB_LABEL: &[u8] = b"SGXRA-v1/sealed-long-term-identity";

/// The default storage slot of the long-term identity.
pub const DEFAULT_IDENTITY_SLOT: u32 = 0;

/// MRSIGNERs whose private key is public, so anyone can sign an enclave
/// with them: the key of `enclave-sys/reproducible-signing-key.pem`.
/// Sealing to MRSIGNER under such a signer protects nothing, and
/// [`LongTermIdentity::load_or_create`] refuses it.
pub const PUBLISHED_SIGNERS: &[Measurement] = &[Measurement([
    0x8b, 0x1b, 0xeb, 0xa6, 0x0b, 0x7c, 0x00, 0x45, 0x61, 0xb8, 0xeb, 0x5e, 0x83, 0x84, 0xff, 0x03,
    0xf9, 0x88, 0xe3, 0x91, 0x4e, 0x5c, 0x84, 0x5e, 0xe3, 0x36, 0x2b, 0x78, 0x6b, 0x34, 0xef, 0xa6,
])];

/// Where and how the long-term identity is sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityConfig {
    /// Key policy of the sealed blob.
    pub policy: KeyPolicy,
    /// Storage slot (within the policy's namespace).
    pub slot: u32,
}

impl IdentityConfig {
    /// `policy` in [`DEFAULT_IDENTITY_SLOT`].
    pub const fn new(policy: KeyPolicy) -> Self {
        Self {
            policy,
            slot: DEFAULT_IDENTITY_SLOT,
        }
    }

    /// The additional data of the blob holding `public`.
    fn additional_data(&self, public: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(IDENTITY_BLOB_LABEL.len() + 6 + PUBLIC_KEY_LEN);
        aad.extend_from_slice(IDENTITY_BLOB_LABEL);
        aad.push(0x00);
        aad.push(self.policy.to_byte());
        aad.extend_from_slice(&self.slot.to_be_bytes());
        aad.extend_from_slice(public);
        aad
    }
}

/// Why the long-term identity could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// The RNG failed.
    Rng(RngError),
    /// Sealing a new key failed.
    Seal(SealError),
    /// The host storage failed (other than being absent).
    Storage(StorageError),
    /// A stored blob exists but cannot be opened with this enclave's key
    /// for the configured policy. Fail closed: no silent rotation.
    Unreadable(SealError),
    /// A blob opened, but its contents are not an identity for this slot
    /// and policy (e.g. a blob of another purpose moved into the slot).
    Mismatch,
    /// MRSIGNER sealing was requested, but this enclave is signed with a
    /// published key ([`PUBLISHED_SIGNERS`]).
    PublishedSigner,
    /// `sgx_self_report` returned nothing.
    SelfReport,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rng(e) => write!(f, "long-term identity: {e}"),
            Self::Seal(e) => write!(f, "long-term identity: {e}"),
            Self::Storage(e) => write!(f, "long-term identity: {e}"),
            Self::Unreadable(e) => write!(f, "stored long-term identity cannot be opened: {e}"),
            Self::Mismatch => f.write_str("stored blob is not a long-term identity for this slot"),
            Self::PublishedSigner => {
                f.write_str("refusing MRSIGNER sealing: the enclave is signed with a published key")
            }
            Self::SelfReport => f.write_str("sgx_self_report failed"),
        }
    }
}

impl core::error::Error for IdentityError {}

/// This enclave's own report body (`sgx_self_report`).
pub fn self_report_body() -> Option<ReportBody> {
    // SAFETY: `sgx_self_report` takes no arguments and returns null or a
    // pointer to the tRTS's static, initialised report of this enclave.
    let raw = unsafe { ffi::sgx_self_report() };
    if raw.is_null() {
        return None;
    }
    // SAFETY: non-null, points to a REPORT_LEN-byte static (alignment 1).
    let bytes = unsafe { &*raw };
    Report::from_bytes(bytes).ok().map(|r| r.body())
}

/// The long-term identity key of this enclave instance.
pub struct LongTermIdentity {
    key: IdentityKey,
    policy: KeyPolicy,
    origin: IdentityOrigin,
}

impl LongTermIdentity {
    /// Loads the sealed identity from `storage`, or creates and stores one.
    pub fn load_or_create(
        config: IdentityConfig,
        storage: &mut impl SealedStorage,
        rng: &mut impl Rng,
    ) -> Result<Self, IdentityError> {
        let own = self_report_body().ok_or(IdentityError::SelfReport)?;
        Self::load_or_create_as(&own, config, storage, rng)
    }

    /// [`LongTermIdentity::load_or_create`] for an explicit own report
    /// body (the namespace, ISVSVN and signer checks use it).
    fn load_or_create_as(
        own: &ReportBody,
        config: IdentityConfig,
        storage: &mut impl SealedStorage,
        rng: &mut impl Rng,
    ) -> Result<Self, IdentityError> {
        if config.policy == KeyPolicy::MrSigner && PUBLISHED_SIGNERS.contains(&own.mr_signer()) {
            return Err(IdentityError::PublishedSigner);
        }
        let ns = namespace(config.policy, own);
        // Two rounds: if a concurrent instance creates the blob between our
        // load and our store, the second round loads its key.
        for _ in 0..2 {
            match storage.load(&ns, config.slot) {
                Ok(Some(blob)) => return Self::restore(own, config, storage, &ns, &blob),
                Ok(None) => {}
                Err(StorageError::Unavailable) => {
                    return Self::generate(config, IdentityOrigin::Ephemeral, rng);
                }
                Err(e) => return Err(IdentityError::Storage(e)),
            }
            let identity = Self::generate(config, IdentityOrigin::Created, rng)?;
            let blob = identity.seal(config)?;
            match storage.store(&ns, config.slot, &blob, StoreMode::CreateNew) {
                Ok(()) => return Ok(identity),
                Err(StorageError::AlreadyExists) => continue,
                Err(StorageError::Unavailable) => {
                    return Ok(Self {
                        origin: IdentityOrigin::Ephemeral,
                        ..identity
                    });
                }
                Err(e) => return Err(IdentityError::Storage(e)),
            }
        }
        // The host keeps reporting the slot as both empty and taken.
        Err(IdentityError::Storage(StorageError::Malformed))
    }

    fn generate(
        config: IdentityConfig,
        origin: IdentityOrigin,
        rng: &mut impl Rng,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            key: IdentityKey::generate(rng).map_err(IdentityError::Rng)?,
            policy: config.policy,
            origin,
        })
    }

    fn seal(&self, config: IdentityConfig) -> Result<Vec<u8>, IdentityError> {
        let secret = self.key.secret_bytes();
        sealing::seal_with(
            config.policy,
            &*secret,
            &config.additional_data(self.key.public_key()),
        )
        .map_err(IdentityError::Seal)
    }

    fn restore(
        own: &ReportBody,
        config: IdentityConfig,
        storage: &mut impl SealedStorage,
        ns: &[u8; NAMESPACE_LEN],
        blob: &[u8],
    ) -> Result<Self, IdentityError> {
        let unsealed =
            sealing::unseal_with(config.policy, blob).map_err(IdentityError::Unreadable)?;
        let secret: [u8; 32] = unsealed.plaintext[..]
            .try_into()
            .map_err(|_| IdentityError::Mismatch)?;
        let key = IdentityKey::from_secret_bytes(Zeroizing::new(secret));
        // The additional data must name this purpose, policy and slot, and
        // the public key derived from the unsealed secret.
        if unsealed.additional_data != config.additional_data(key.public_key()) {
            return Err(IdentityError::Mismatch);
        }
        let mut identity = Self {
            key,
            policy: config.policy,
            origin: IdentityOrigin::Restored,
        };
        if unsealed.isv_svn < own.isv_svn() {
            // Sealed by an older version. Re-seal at our ISVSVN so the
            // stored copy is out of reach of that version from now on (it
            // can still open any copy the host kept).
            let blob = identity.seal(config)?;
            if storage
                .store(ns, config.slot, &blob, StoreMode::Replace)
                .is_ok()
            {
                identity.origin = IdentityOrigin::Migrated;
            }
        }
        Ok(identity)
    }

    /// `lk_pub`.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        self.key.public_key()
    }

    /// How this instance obtained the key.
    pub fn origin(&self) -> IdentityOrigin {
        self.origin
    }

    /// The key policy the identity is sealed under.
    pub fn policy(&self) -> KeyPolicy {
        self.policy
    }

    /// Answers a client's identity challenge inside the session whose
    /// channel key is `session_public` (see
    /// [`crate::SessionContext::identity_public_key`]).
    pub fn prove(
        &self,
        session_public: &[u8; PUBLIC_KEY_LEN],
        challenge_public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<IdentityAssertion, IdentityProofError> {
        proof::prove(
            &self.key,
            self.origin,
            self.policy,
            session_public,
            challenge_public,
        )
    }
}

impl fmt::Debug for LongTermIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LongTermIdentity")
            .field("public", &Hex(self.public_key()))
            .field("policy", &self.policy)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::fake::{FAKE_SELF, FakeEnclave};
    use crate::platform::SgxRng;
    use crate::storage::MemoryStorage;
    use sgx_ra_core::identity::IdentityChallenge;

    const MRE: IdentityConfig = IdentityConfig::new(KeyPolicy::MrEnclave);
    const MRS: IdentityConfig = IdentityConfig::new(KeyPolicy::MrSigner);

    fn as_enclave<R>(e: FakeEnclave, f: impl FnOnce() -> R) -> R {
        let old = FAKE_SELF.with(|c| c.replace(e));
        let r = f();
        FAKE_SELF.with(|c| c.set(old));
        r
    }

    fn load(
        config: IdentityConfig,
        storage: &mut MemoryStorage,
    ) -> Result<LongTermIdentity, IdentityError> {
        LongTermIdentity::load_or_create(config, storage, &mut SgxRng)
    }

    fn ns(config: IdentityConfig) -> [u8; 32] {
        namespace(config.policy, &self_report_body().unwrap())
    }

    #[test]
    fn created_once_then_restored() {
        let mut storage = MemoryStorage::new();
        let first = load(MRE, &mut storage).unwrap();
        assert_eq!(first.origin(), IdentityOrigin::Created);
        let second = load(MRE, &mut storage).unwrap();
        assert_eq!(second.origin(), IdentityOrigin::Restored);
        assert_eq!(first.public_key(), second.public_key());
        // Another slot is another identity.
        let other = load(IdentityConfig { slot: 1, ..MRE }, &mut storage).unwrap();
        assert_eq!(other.origin(), IdentityOrigin::Created);
        assert_ne!(other.public_key(), first.public_key());
    }

    #[test]
    fn proof_verifies_on_the_client() {
        let mut storage = MemoryStorage::new();
        let identity = load(MRE, &mut storage).unwrap();
        let challenge = IdentityChallenge::new(&mut SgxRng).unwrap();
        let assertion = identity.prove(&[3; 32], challenge.public_key()).unwrap();
        assert_eq!(&assertion.public_key, identity.public_key());
        assert_eq!(assertion.origin, IdentityOrigin::Created);
        challenge.verify(&[3; 32], &assertion).unwrap();
    }

    #[test]
    fn code_change_loses_an_mrenclave_identity() {
        let mut storage = MemoryStorage::new();
        let old = load(MRE, &mut storage).unwrap();
        let new_code = FakeEnclave {
            mr_enclave: 0x02,
            ..FakeEnclave::DEFAULT
        };
        // The new code looks in its own namespace and starts over; the old
        // blob stays for the old code.
        let new = as_enclave(new_code, || load(MRE, &mut storage).unwrap());
        assert_eq!(new.origin(), IdentityOrigin::Created);
        assert_ne!(new.public_key(), old.public_key());
        assert_eq!(
            load(MRE, &mut storage).unwrap().public_key(),
            old.public_key()
        );
    }

    #[test]
    fn signer_migrates_an_mrsigner_identity() {
        let mut storage = MemoryStorage::new();
        let v1 = load(MRS, &mut storage).unwrap();
        let v2_enclave = FakeEnclave {
            mr_enclave: 0x02,
            isv_svn: 2,
            ..FakeEnclave::DEFAULT
        };
        let v2 = as_enclave(v2_enclave, || load(MRS, &mut storage).unwrap());
        assert_eq!(v2.origin(), IdentityOrigin::Migrated);
        assert_eq!(v2.public_key(), v1.public_key());
        // Re-sealed at ISVSVN 2: v1 can no longer open the stored copy ...
        assert_eq!(
            load(MRS, &mut storage).unwrap_err(),
            IdentityError::Unreadable(SealError::SvnTooHigh)
        );
        // ... while v2 now restores it without migrating again.
        let again = as_enclave(v2_enclave, || load(MRS, &mut storage).unwrap());
        assert_eq!(again.origin(), IdentityOrigin::Restored);
        // A different product of the same signer has its own namespace.
        let other_product = FakeEnclave {
            isv_prod_id: 7,
            ..FakeEnclave::DEFAULT
        };
        let other = as_enclave(other_product, || load(MRS, &mut storage).unwrap());
        assert_eq!(other.origin(), IdentityOrigin::Created);
    }

    #[test]
    fn published_signer_cannot_use_mrsigner() {
        // An own report signed with the published key.
        let mut storage = MemoryStorage::new();
        let mut own = *self_report_body().unwrap().as_bytes();
        own[128..160].copy_from_slice(&PUBLISHED_SIGNERS[0].0);
        let own = ReportBody::from_array(own);
        assert_eq!(
            LongTermIdentity::load_or_create_as(&own, MRS, &mut storage, &mut SgxRng).unwrap_err(),
            IdentityError::PublishedSigner
        );
        // MRENCLAVE sealing does not depend on the signer.
        LongTermIdentity::load_or_create_as(&own, MRE, &mut storage, &mut SgxRng).unwrap();
    }

    #[test]
    fn unreadable_or_foreign_blobs_fail_closed() {
        let mut storage = MemoryStorage::new();
        let original = load(MRE, &mut storage).unwrap();
        let ns = ns(MRE);
        let good = storage.load(&ns, 0).unwrap().unwrap();

        // Tampered blob: refuse, and leave it in place.
        let mut bad = good.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        storage.store(&ns, 0, &bad, StoreMode::Replace).unwrap();
        assert_eq!(
            load(MRE, &mut storage).unwrap_err(),
            IdentityError::Unreadable(SealError::Authentication)
        );
        assert_eq!(storage.load(&ns, 0).unwrap().unwrap(), bad);

        // Same enclave, different CPU.
        storage.store(&ns, 0, &good, StoreMode::Replace).unwrap();
        let other_cpu = FakeEnclave {
            cpu: 9,
            ..FakeEnclave::DEFAULT
        };
        assert_eq!(
            as_enclave(other_cpu, || load(MRE, &mut storage).unwrap_err()),
            IdentityError::Unreadable(SealError::Authentication)
        );

        // A genuine blob of another purpose or slot moved into this slot.
        let foreign = sealing::seal(&[5u8; 32], b"something else").unwrap();
        storage.store(&ns, 0, &foreign, StoreMode::Replace).unwrap();
        assert_eq!(
            load(MRE, &mut storage).unwrap_err(),
            IdentityError::Mismatch
        );
        let slot1 = IdentityConfig { slot: 1, ..MRE };
        load(slot1, &mut storage).unwrap();
        let moved = storage.load(&ns, 1).unwrap().unwrap();
        storage.store(&ns, 0, &moved, StoreMode::Replace).unwrap();
        assert_eq!(
            load(MRE, &mut storage).unwrap_err(),
            IdentityError::Mismatch
        );

        // A blob sealed under the other policy.
        let mrs_blob = sealing::seal_with(KeyPolicy::MrSigner, &[5u8; 32], b"").unwrap();
        storage
            .store(&ns, 0, &mrs_blob, StoreMode::Replace)
            .unwrap();
        assert_eq!(
            load(MRE, &mut storage).unwrap_err(),
            IdentityError::Unreadable(SealError::WrongPolicy)
        );

        // Restoring the genuine blob brings the original key back.
        storage.store(&ns, 0, &good, StoreMode::Replace).unwrap();
        assert_eq!(
            load(MRE, &mut storage).unwrap().public_key(),
            original.public_key()
        );
    }

    /// Storage whose behaviour is scripted per call.
    struct Scripted {
        inner: MemoryStorage,
        unavailable_load: bool,
        unavailable_store: bool,
        /// Before the first store, another instance stores this blob.
        racer: Option<Vec<u8>>,
    }

    impl SealedStorage for Scripted {
        fn load(&mut self, ns: &[u8; 32], slot: u32) -> Result<Option<Vec<u8>>, StorageError> {
            if self.unavailable_load {
                return Err(StorageError::Unavailable);
            }
            self.inner.load(ns, slot)
        }

        fn store(
            &mut self,
            ns: &[u8; 32],
            slot: u32,
            blob: &[u8],
            mode: StoreMode,
        ) -> Result<(), StorageError> {
            if self.unavailable_store {
                return Err(StorageError::Unavailable);
            }
            if let Some(racer) = self.racer.take() {
                self.inner.store(ns, slot, &racer, StoreMode::CreateNew)?;
            }
            self.inner.store(ns, slot, blob, mode)
        }
    }

    fn scripted() -> Scripted {
        Scripted {
            inner: MemoryStorage::new(),
            unavailable_load: false,
            unavailable_store: false,
            racer: None,
        }
    }

    #[test]
    fn no_storage_means_ephemeral() {
        for (load_fails, store_fails) in [(true, false), (false, true)] {
            let mut s = Scripted {
                unavailable_load: load_fails,
                unavailable_store: store_fails,
                ..scripted()
            };
            let a = LongTermIdentity::load_or_create(MRE, &mut s, &mut SgxRng).unwrap();
            let b = LongTermIdentity::load_or_create(MRE, &mut s, &mut SgxRng).unwrap();
            assert_eq!(a.origin(), IdentityOrigin::Ephemeral);
            assert_ne!(a.public_key(), b.public_key());
        }
    }

    #[test]
    fn concurrent_creation_converges_on_the_winner() {
        // The "other instance" creates its identity in a separate store,
        // then its blob lands in ours just before our CreateNew.
        let mut theirs = MemoryStorage::new();
        let winner = load(MRE, &mut theirs).unwrap();
        let blob = theirs.load(&ns(MRE), 0).unwrap().unwrap();
        let mut s = Scripted {
            racer: Some(blob),
            ..scripted()
        };
        let ours = LongTermIdentity::load_or_create(MRE, &mut s, &mut SgxRng).unwrap();
        assert_eq!(ours.origin(), IdentityOrigin::Restored);
        assert_eq!(ours.public_key(), winner.public_key());
    }

    #[test]
    fn debug_hides_the_secret() {
        let identity = load(MRE, &mut MemoryStorage::new()).unwrap();
        let text = alloc::format!("{identity:?}");
        assert!(text.contains("Created"));
        assert!(!text.contains("secret"));
    }
}
