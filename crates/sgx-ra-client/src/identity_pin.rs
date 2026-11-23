//! Pinning an enclave's long-term identity key (`docs/SEALING.md`).
//!
//! An enclave built on `sgx_ra_enclave::identity` asserts its sealed
//! long-term key `lk_pub` inside an attested session, with a proof bound to
//! the session's `ek_pub` and a fresh client challenge
//! ([`sgx_ra_core::identity`]). This module adds the client-side checks:
//!
//! 1. [`verify_assertion`]: the proof is valid for our challenge and for
//!    this channel's attested key;
//! 2. [`IdentityPin`]: trust on first use, then the same `lk_pub` every
//!    time. A pin is checked **in addition to** attestation, never instead
//!    of it: each session still needs a verified quote for the expected
//!    MRENCLAVE.
//!
//! A changed key means the sealed blob is gone or unreadable: the enclave
//! code changed (MRENCLAVE policy), the enclave moved to another CPU, the
//! operator deleted the blob, or the host rolled storage back to an older
//! key. Which one cannot be told apart from the client, so a mismatch is an
//! error the user resolves (by deleting the pin file after checking why).

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use sgx_ra_core::handshake::PUBLIC_KEY_LEN;
use sgx_ra_core::hex::Hex;
use sgx_ra_core::identity::{IdentityAssertion, IdentityChallenge, IdentityProofError};
use sgx_ra_core::sgx::Measurement;

/// Checks `assertion` against `challenge` and the channel's attested key
/// (`EnclaveChannel::enclave_public_key`).
pub fn verify_assertion(
    challenge: IdentityChallenge,
    channel_public: &[u8; PUBLIC_KEY_LEN],
    assertion: &IdentityAssertion,
) -> Result<(), IdentityProofError> {
    challenge.verify(channel_public, assertion)
}

/// Result of [`IdentityPin::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// No pin existed; `lk_pub` is now pinned (trust on first use).
    Pinned,
    /// The presented key equals the pinned one.
    Matches,
    /// The enclave's key is not persisted (origin `Ephemeral`): nothing was
    /// pinned, and an existing pin was left alone.
    NotPersistent,
}

/// Pin failures.
#[derive(Debug)]
pub enum PinError {
    /// The presented key differs from the pinned one.
    Mismatch {
        /// The pinned key.
        pinned: [u8; PUBLIC_KEY_LEN],
        /// The key the enclave proved.
        presented: [u8; PUBLIC_KEY_LEN],
    },
    /// The pin file exists but is not a valid pin.
    Corrupt(PathBuf),
    /// Reading or writing the pin file failed.
    Io(io::Error),
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch { pinned, presented } => write!(
                f,
                "long-term identity changed: pinned {}, enclave proved {}",
                Hex(pinned),
                Hex(presented)
            ),
            Self::Corrupt(path) => write!(f, "{} is not a valid identity pin", path.display()),
            Self::Io(e) => write!(f, "identity pin: {e}"),
        }
    }
}

impl std::error::Error for PinError {}

/// A pinned long-term identity key in a file: one line of 64 hex digits.
#[derive(Debug, Clone)]
pub struct IdentityPin {
    path: PathBuf,
}

impl IdentityPin {
    /// The pin kept at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The pin file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The pinned key, if there is one.
    pub fn load(&self) -> Result<Option<[u8; PUBLIC_KEY_LEN]>, PinError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(PinError::Io(e)),
        };
        // Same 64-hex-digit format as a measurement.
        Measurement::from_hex(text.trim())
            .map(|m| Some(m.0))
            .map_err(|_| PinError::Corrupt(self.path.clone()))
    }

    /// Checks a **verified** assertion against the pin, pinning it on first
    /// use. Call [`verify_assertion`] first.
    pub fn check(&self, assertion: &IdentityAssertion) -> Result<PinOutcome, PinError> {
        let pinned = self.load()?;
        if !assertion.origin.is_persistent() {
            return Ok(PinOutcome::NotPersistent);
        }
        match pinned {
            Some(pinned) if pinned == assertion.public_key => Ok(PinOutcome::Matches),
            Some(pinned) => Err(PinError::Mismatch {
                pinned,
                presented: assertion.public_key,
            }),
            None => {
                self.store(&assertion.public_key)?;
                Ok(PinOutcome::Pinned)
            }
        }
    }

    /// Writes the pin (mode 0600, never overwriting an existing file).
    fn store(&self, key: &[u8; PUBLIC_KEY_LEN]) -> Result<(), PinError> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(PinError::Io)?;
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(PinError::Io)?;
        writeln!(f, "{}", Hex(key)).map_err(PinError::Io)?;
        f.sync_all().map_err(PinError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sgx_ra_core::identity::IdentityOrigin;
    use sgx_ra_core::storage::KeyPolicy;

    fn assertion(key: u8, origin: IdentityOrigin) -> IdentityAssertion {
        IdentityAssertion {
            origin,
            policy: KeyPolicy::MrEnclave,
            public_key: [key; 32],
            proof: [0; 32],
        }
    }

    #[test]
    fn trust_on_first_use_then_strict() {
        let dir = std::env::temp_dir().join(format!("sgx-ra-pin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let pin = IdentityPin::new(dir.join("nested/enclave.pin"));
        assert_eq!(pin.load().unwrap(), None);

        // Ephemeral keys are never pinned.
        assert_eq!(
            pin.check(&assertion(1, IdentityOrigin::Ephemeral)).unwrap(),
            PinOutcome::NotPersistent
        );
        assert_eq!(pin.load().unwrap(), None);

        assert_eq!(
            pin.check(&assertion(1, IdentityOrigin::Created)).unwrap(),
            PinOutcome::Pinned
        );
        assert_eq!(pin.load().unwrap(), Some([1; 32]));
        assert_eq!(
            pin.check(&assertion(1, IdentityOrigin::Restored)).unwrap(),
            PinOutcome::Matches
        );
        assert!(matches!(
            pin.check(&assertion(2, IdentityOrigin::Created)),
            Err(PinError::Mismatch { pinned, presented }) if pinned == [1; 32] && presented == [2; 32]
        ));
        // A mismatch never rewrites the pin.
        assert_eq!(pin.load().unwrap(), Some([1; 32]));
        // An ephemeral key next to a pin is reported, not an error.
        assert_eq!(
            pin.check(&assertion(3, IdentityOrigin::Ephemeral)).unwrap(),
            PinOutcome::NotPersistent
        );

        fs::write(pin.path(), "zz\n").unwrap();
        assert!(matches!(pin.load(), Err(PinError::Corrupt(_))));
        let _ = fs::remove_dir_all(&dir);
    }
}
