//! Long-term enclave identity, proven inside an attested session
//! (`docs/SEALING.md`).
//!
//! The channel identity key `EK` (report_data, [`crate::binding`]) is fresh
//! per enclave instance. An enclave may additionally hold a **long-term
//! identity key** `LK` (X25519) that it seals and persists, so clients can
//! pin `lk_pub` across restarts. `LK` is never put into report_data: every
//! session is still authenticated by a quote over a fresh `EK`, and `LK` is
//! only asserted *inside* that session:
//!
//! ```text
//! client → enclave   chal_pub                       (fresh X25519 key per request)
//! enclave → client   ver=01 ‖ origin ‖ policy ‖ lk_pub[32] ‖ proof[32]
//!
//! k     = HMAC-SHA256("SGXRA-v1/long-term-identity", X25519(lk_sk, chal_pub))
//!           (HKDF-Extract with the label as salt)
//! proof = HMAC-SHA256(k, "SGXRA-v1/long-term-identity/key" ‖ "SGXRA-v1/long-term-identity"
//!                        ‖ ver ‖ origin ‖ policy ‖ ek_pub ‖ lk_pub ‖ chal_pub)
//! ```
//!
//! A valid proof shows that the peer holds `lk_sk` *now* (the challenge is
//! fresh) and binds the assertion to this session's attested `ek_pub`, so
//! it cannot be relayed into another session. The attested channel already
//! authenticates the enclave code; the proof additionally rules out a code
//! path that merely claims a key it does not hold.
//!
//! Why not seal `EK` itself? With a stable `EK`, report_data is the same in
//! every instance, so *any* old quote of the genuine enclave vouches for the
//! key. Whoever ever extracts `ek_sk` (a side channel, a malicious signer
//! under the MRSIGNER policy) could then impersonate the enclave
//! indefinitely by replaying such a quote. Keeping `EK` per instance limits
//! that to the compromised instance; a leaked `LK` lets an attacker decrypt
//! data encrypted to `lk_pub`, but never makes a client accept a channel.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::handshake::{IdentityKey, PUBLIC_KEY_LEN};
use crate::hex::Hex;
use crate::rng::{Rng, RngError};
use crate::storage::KeyPolicy;

/// Domain separator of the identity proof.
pub const IDENTITY_PROOF_LABEL: &[u8] = b"SGXRA-v1/long-term-identity";
/// Prefix of the proof MAC input (separates it from other uses of `k`).
pub const IDENTITY_KEY_LABEL: &[u8] = b"SGXRA-v1/long-term-identity/key";
/// Version byte of [`IdentityAssertion`].
pub const IDENTITY_ASSERTION_VERSION: u8 = 1;
/// Encoded length of [`IdentityAssertion`].
pub const IDENTITY_ASSERTION_LEN: usize = 3 + PUBLIC_KEY_LEN + 32;

type HmacSha256 = Hmac<Sha256>;

/// Where the enclave's long-term key came from in this instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityOrigin {
    /// Generated in this instance and **not** persisted (the host offers no
    /// sealed storage). The key dies with the instance; do not pin it.
    Ephemeral,
    /// Generated in this instance and persisted as a sealed blob.
    Created,
    /// Unsealed from a blob sealed at this enclave's ISVSVN.
    Restored,
    /// Unsealed from a blob sealed by an enclave with a lower ISVSVN
    /// (possible under the MRSIGNER policy, or after re-signing the same
    /// image with a higher ISVSVN) and re-sealed at this ISVSVN.
    Migrated,
}

impl IdentityOrigin {
    /// Single-byte encoding.
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Ephemeral => 0,
            Self::Created => 1,
            Self::Restored => 2,
            Self::Migrated => 3,
        }
    }

    /// Inverse of [`IdentityOrigin::to_byte`].
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Ephemeral,
            1 => Self::Created,
            2 => Self::Restored,
            3 => Self::Migrated,
            _ => return None,
        })
    }

    /// Whether the key is persisted, i.e. worth pinning.
    pub fn is_persistent(self) -> bool {
        self != Self::Ephemeral
    }
}

impl fmt::Display for IdentityOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ephemeral => "ephemeral (not persisted)",
            Self::Created => "created and sealed",
            Self::Restored => "restored from sealed storage",
            Self::Migrated => "migrated from a lower ISVSVN and re-sealed",
        })
    }
}

/// Errors of decoding or verifying an [`IdentityAssertion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProofError {
    /// Wrong length, version, origin or policy byte.
    Malformed,
    /// `lk_pub` is a low-order point.
    NonContributory,
    /// The proof does not verify.
    InvalidProof,
    /// The RNG failed.
    Rng(RngError),
}

impl fmt::Display for IdentityProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed long-term identity assertion"),
            Self::NonContributory => f.write_str("long-term identity key is a low-order point"),
            Self::InvalidProof => f.write_str("long-term identity proof is invalid"),
            Self::Rng(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for IdentityProofError {}

/// The enclave's statement about its long-term identity key, with a proof
/// of possession bound to one session and one challenge.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityAssertion {
    /// How this instance obtained the key.
    pub origin: IdentityOrigin,
    /// The policy the key is (or would be) sealed under.
    pub policy: KeyPolicy,
    /// `lk_pub`.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// The proof of possession.
    pub proof: [u8; 32],
}

impl IdentityAssertion {
    /// `ver ‖ origin ‖ policy ‖ lk_pub ‖ proof`.
    pub fn encode(&self) -> [u8; IDENTITY_ASSERTION_LEN] {
        let mut out = [0u8; IDENTITY_ASSERTION_LEN];
        out[0] = IDENTITY_ASSERTION_VERSION;
        out[1] = self.origin.to_byte();
        out[2] = self.policy.to_byte();
        out[3..35].copy_from_slice(&self.public_key);
        out[35..].copy_from_slice(&self.proof);
        out
    }

    /// Strict inverse of [`IdentityAssertion::encode`].
    pub fn decode(buf: &[u8]) -> Result<Self, IdentityProofError> {
        if buf.len() != IDENTITY_ASSERTION_LEN || buf[0] != IDENTITY_ASSERTION_VERSION {
            return Err(IdentityProofError::Malformed);
        }
        let origin = IdentityOrigin::from_byte(buf[1]).ok_or(IdentityProofError::Malformed)?;
        let policy = KeyPolicy::from_byte(buf[2]).ok_or(IdentityProofError::Malformed)?;
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&buf[3..35]);
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&buf[35..]);
        Ok(Self {
            origin,
            policy,
            public_key,
            proof,
        })
    }
}

impl fmt::Debug for IdentityAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityAssertion")
            .field("origin", &self.origin)
            .field("policy", &self.policy)
            .field("public_key", &Hex(&self.public_key))
            .finish_non_exhaustive()
    }
}

fn proof_tag(
    dh: &[u8; 32],
    origin: IdentityOrigin,
    policy: KeyPolicy,
    session_public: &[u8; PUBLIC_KEY_LEN],
    long_term_public: &[u8; PUBLIC_KEY_LEN],
    challenge_public: &[u8; PUBLIC_KEY_LEN],
) -> [u8; 32] {
    // k = HMAC-SHA256(label, dh), i.e. HKDF-Extract with the label as salt;
    // the transcript-style MAC input below takes the role of HKDF-Expand's
    // info. (Plain HMAC rather than the `hkdf` crate keeps this code from
    // perturbing the handshake's codegen in enclaves that never use it.)
    let mut extract = <HmacSha256 as Mac>::new_from_slice(IDENTITY_PROOF_LABEL)
        .expect("HMAC accepts any key length");
    extract.update(dh);
    let key = Zeroizing::new(<[u8; 32]>::from(extract.finalize().into_bytes()));
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&*key).expect("HMAC accepts any key length");
    mac.update(IDENTITY_KEY_LABEL);
    mac.update(IDENTITY_PROOF_LABEL);
    mac.update(&[
        IDENTITY_ASSERTION_VERSION,
        origin.to_byte(),
        policy.to_byte(),
    ]);
    mac.update(session_public);
    mac.update(long_term_public);
    mac.update(challenge_public);
    mac.finalize().into_bytes().into()
}

/// Enclave side: answers `challenge_public` with an assertion about
/// `long_term`, bound to this session's channel key `session_public`
/// (`ek_pub`).
pub fn prove(
    long_term: &IdentityKey,
    origin: IdentityOrigin,
    policy: KeyPolicy,
    session_public: &[u8; PUBLIC_KEY_LEN],
    challenge_public: &[u8; PUBLIC_KEY_LEN],
) -> Result<IdentityAssertion, IdentityProofError> {
    let dh = long_term.agree(challenge_public);
    if !dh.was_contributory() {
        return Err(IdentityProofError::NonContributory);
    }
    let public_key = *long_term.public_key();
    let proof = proof_tag(
        dh.as_bytes(),
        origin,
        policy,
        session_public,
        &public_key,
        challenge_public,
    );
    Ok(IdentityAssertion {
        origin,
        policy,
        public_key,
        proof,
    })
}

/// Client side: a fresh challenge for one identity request.
pub struct IdentityChallenge {
    secret: StaticSecret,
    public: PublicKey,
}

impl IdentityChallenge {
    /// Generates a fresh challenge key.
    pub fn new(rng: &mut impl Rng) -> Result<Self, IdentityProofError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *bytes)
            .map_err(IdentityProofError::Rng)?;
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// `chal_pub`, to send to the enclave.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        self.public.as_bytes()
    }

    /// Checks `assertion` against this challenge and the session's attested
    /// channel key `session_public` (`EnclaveChannel::enclave_public_key`).
    /// Consumes the challenge: each one answers exactly one request.
    pub fn verify(
        self,
        session_public: &[u8; PUBLIC_KEY_LEN],
        assertion: &IdentityAssertion,
    ) -> Result<(), IdentityProofError> {
        let dh = self
            .secret
            .diffie_hellman(&PublicKey::from(assertion.public_key));
        if !dh.was_contributory() {
            return Err(IdentityProofError::NonContributory);
        }
        let expected = proof_tag(
            dh.as_bytes(),
            assertion.origin,
            assertion.policy,
            session_public,
            &assertion.public_key,
            self.public.as_bytes(),
        );
        if bool::from(expected.ct_eq(&assertion.proof)) {
            Ok(())
        } else {
            Err(IdentityProofError::InvalidProof)
        }
    }
}

impl fmt::Debug for IdentityChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityChallenge")
            .field("public", &Hex(self.public.as_bytes()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FailingRng, TestRng};

    const EK: [u8; 32] = [0x11; 32];

    fn setup() -> (IdentityKey, IdentityChallenge) {
        let lk = IdentityKey::generate(&mut TestRng::new(1)).unwrap();
        let challenge = IdentityChallenge::new(&mut TestRng::new(2)).unwrap();
        (lk, challenge)
    }

    #[test]
    fn roundtrip() {
        let (lk, challenge) = setup();
        let assertion = prove(
            &lk,
            IdentityOrigin::Restored,
            KeyPolicy::MrEnclave,
            &EK,
            challenge.public_key(),
        )
        .unwrap();
        assert_eq!(&assertion.public_key, lk.public_key());
        let decoded = IdentityAssertion::decode(&assertion.encode()).unwrap();
        assert_eq!(decoded, assertion);
        challenge.verify(&EK, &decoded).unwrap();
    }

    #[test]
    fn proof_binds_every_field() {
        let (lk, _) = setup();
        let fresh = || IdentityChallenge::new(&mut TestRng::new(2)).unwrap();
        let good = prove(
            &lk,
            IdentityOrigin::Created,
            KeyPolicy::MrSigner,
            &EK,
            fresh().public_key(),
        )
        .unwrap();

        // Another session's channel key.
        assert_eq!(
            fresh().verify(&[0x12; 32], &good),
            Err(IdentityProofError::InvalidProof)
        );
        // Another challenge (a replayed answer).
        let other = IdentityChallenge::new(&mut TestRng::new(3)).unwrap();
        assert_eq!(
            other.verify(&EK, &good),
            Err(IdentityProofError::InvalidProof)
        );
        // Tampered origin, policy, key or proof.
        let mut t = good.clone();
        t.origin = IdentityOrigin::Restored;
        assert_eq!(
            fresh().verify(&EK, &t),
            Err(IdentityProofError::InvalidProof)
        );
        let mut t = good.clone();
        t.policy = KeyPolicy::MrEnclave;
        assert_eq!(
            fresh().verify(&EK, &t),
            Err(IdentityProofError::InvalidProof)
        );
        let mut t = good.clone();
        t.public_key = *IdentityKey::generate(&mut TestRng::new(9))
            .unwrap()
            .public_key();
        assert_eq!(
            fresh().verify(&EK, &t),
            Err(IdentityProofError::InvalidProof)
        );
        let mut t = good.clone();
        t.proof[0] ^= 1;
        assert_eq!(
            fresh().verify(&EK, &t),
            Err(IdentityProofError::InvalidProof)
        );

        fresh().verify(&EK, &good).unwrap();
    }

    #[test]
    fn low_order_points_are_rejected() {
        let (lk, challenge) = setup();
        assert_eq!(
            prove(
                &lk,
                IdentityOrigin::Created,
                KeyPolicy::MrEnclave,
                &EK,
                &[0u8; 32]
            ),
            Err(IdentityProofError::NonContributory)
        );
        let assertion = IdentityAssertion {
            origin: IdentityOrigin::Created,
            policy: KeyPolicy::MrEnclave,
            public_key: [0u8; 32],
            proof: [0u8; 32],
        };
        assert_eq!(
            challenge.verify(&EK, &assertion),
            Err(IdentityProofError::NonContributory)
        );
    }

    #[test]
    fn strict_decoding() {
        let (lk, challenge) = setup();
        let good = prove(
            &lk,
            IdentityOrigin::Ephemeral,
            KeyPolicy::MrEnclave,
            &EK,
            challenge.public_key(),
        )
        .unwrap()
        .encode();
        assert!(IdentityAssertion::decode(&good).is_ok());
        assert!(IdentityAssertion::decode(&good[1..]).is_err());
        let mut long = good.to_vec();
        long.push(0);
        assert!(IdentityAssertion::decode(&long).is_err());
        for (index, value) in [(0, 2), (1, 4), (2, 0), (2, 3)] {
            let mut bad = good;
            bad[index] = value;
            assert_eq!(
                IdentityAssertion::decode(&bad),
                Err(IdentityProofError::Malformed)
            );
        }
        assert!(matches!(
            IdentityChallenge::new(&mut FailingRng),
            Err(IdentityProofError::Rng(_))
        ));
        assert!(!IdentityOrigin::Ephemeral.is_persistent());
        assert!(IdentityOrigin::Migrated.is_persistent());
    }
}
