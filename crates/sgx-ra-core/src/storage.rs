//! Contract of the sealed-blob storage OCALLs, shared by the enclave
//! (`sgx-ra-enclave`, feature `sealed-storage`) and the untrusted host
//! (`sgx-ra-host`).
//!
//! The OCALLs are declared in `enclave-sys/sealed-storage/Enclave.edl`:
//!
//! ```c
//! uint32_t sgx_ra_ocall_load_sealed(const uint8_t ns[32], uint32_t slot,
//!                                   uint8_t* blob /* [out, capacity] */,
//!                                   size_t capacity, size_t* blob_len /* [out] */);
//! uint32_t sgx_ra_ocall_store_sealed(const uint8_t ns[32], uint32_t slot,
//!                                    const uint8_t* blob /* [in, blob_len] */,
//!                                    size_t blob_len, uint32_t replace);
//! ```
//!
//! Both return a [`StorageStatus`] code. The host only stores opaque bytes:
//! confidentiality and integrity come from sealing, never from the host.
//! The host can still withhold, delete or **roll back** blobs; see
//! `docs/SEALING.md`.
//!
//! A blob is addressed by a namespace and a slot number. The enclave
//! derives the namespace from the identity its blobs are sealed to
//! ([`namespace`]), so an enclave whose MRENCLAVE changed looks in a fresh
//! namespace instead of tripping over blobs it can no longer open. Both are
//! hints for the host's bookkeeping; a lying host gains nothing because
//! the enclave authenticates every blob it loads.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::sgx::ReportBody;

/// Largest sealed blob the storage OCALLs move (the `capacity` the enclave
/// passes to `sgx_ra_ocall_load_sealed`).
pub const MAX_SEALED_BLOB_LEN: usize = 16 * 1024;

/// Length of a storage namespace.
pub const NAMESPACE_LEN: usize = 32;

/// Domain separator of [`namespace`].
pub const NAMESPACE_LABEL: &[u8] = b"SGXRA-v1/sealed-storage";

/// Which enclave identity a sealing key is derived from
/// (`sgx_key_request_t::key_policy`).
///
/// See `docs/SEALING.md` for the trade-offs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPolicy {
    /// `SGX_KEYPOLICY_MRENCLAVE`: only the identical enclave code (same
    /// MRENCLAVE) on the same CPU can unseal. Any code change loses access.
    MrEnclave,
    /// `SGX_KEYPOLICY_MRSIGNER`: every enclave signed with the same key and
    /// the same ISVPRODID, with an ISVSVN at least as high as the sealer's,
    /// can unseal on the same CPU. The signer can migrate data to new code,
    /// and can also sign code that exfiltrates it.
    MrSigner,
}

impl KeyPolicy {
    /// The `key_policy` bits of `sgx_key_request_t`.
    pub const fn bits(self) -> u16 {
        match self {
            Self::MrEnclave => 0x0001,
            Self::MrSigner => 0x0002,
        }
    }

    /// The policy whose `key_policy` bits are exactly `bits`.
    pub fn from_bits(bits: u16) -> Option<Self> {
        match bits {
            0x0001 => Some(Self::MrEnclave),
            0x0002 => Some(Self::MrSigner),
            _ => None,
        }
    }

    /// Single-byte encoding used in framework messages.
    pub const fn to_byte(self) -> u8 {
        self.bits() as u8
    }

    /// Inverse of [`KeyPolicy::to_byte`].
    pub fn from_byte(byte: u8) -> Option<Self> {
        Self::from_bits(u16::from(byte))
    }
}

impl fmt::Display for KeyPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MrEnclave => "MRENCLAVE",
            Self::MrSigner => "MRSIGNER",
        })
    }
}

/// The storage namespace of blobs sealed under `policy` by the enclave
/// whose report body is `own`:
///
/// ```text
/// MRENCLAVE: SHA-256("SGXRA-v1/sealed-storage" ‖ 00 ‖ 01 00 ‖ mr_enclave)
/// MRSIGNER:  SHA-256("SGXRA-v1/sealed-storage" ‖ 00 ‖ 02 00 ‖ mr_signer ‖ isv_prod_id LE)
/// ```
///
/// That is exactly the set of enclaves that may derive the same sealing key
/// (up to SVNs), so every enclave able to open a blob looks for it in the
/// same place.
pub fn namespace(policy: KeyPolicy, own: &ReportBody) -> [u8; NAMESPACE_LEN] {
    let hash = Sha256::new()
        .chain_update(NAMESPACE_LABEL)
        .chain_update([0x00])
        .chain_update(policy.bits().to_le_bytes());
    match policy {
        KeyPolicy::MrEnclave => hash.chain_update(own.mr_enclave().as_bytes()),
        KeyPolicy::MrSigner => hash
            .chain_update(own.mr_signer().as_bytes())
            .chain_update(own.isv_prod_id().to_le_bytes()),
    }
    .finalize()
    .into()
}

/// Result codes of the storage OCALLs (the `uint32_t` return value).
///
/// Codes the enclave does not know are treated like [`StorageStatus::Io`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum StorageStatus {
    /// Done (load: `blob_len` bytes of the buffer are the blob).
    Ok = 0,
    /// Load: no blob in this slot.
    NotFound = 1,
    /// Store without `replace`: the slot is already taken.
    AlreadyExists = 2,
    /// The blob exceeds [`MAX_SEALED_BLOB_LEN`] or the given capacity.
    TooLarge = 3,
    /// The host has no sealed storage configured.
    Unavailable = 4,
    /// The host failed to read or write the blob.
    Io = 5,
    /// Null pointers or other malformed arguments.
    InvalidArgument = 6,
}

impl StorageStatus {
    /// The wire code.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Decodes a wire code; unknown codes are `None`.
    pub fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            0 => Self::Ok,
            1 => Self::NotFound,
            2 => Self::AlreadyExists,
            3 => Self::TooLarge,
            4 => Self::Unavailable,
            5 => Self::Io,
            6 => Self::InvalidArgument,
            _ => return None,
        })
    }
}

impl fmt::Display for StorageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ok => "ok",
            Self::NotFound => "no such blob",
            Self::AlreadyExists => "slot already taken",
            Self::TooLarge => "blob too large",
            Self::Unavailable => "no sealed storage on this host",
            Self::Io => "host storage I/O error",
            Self::InvalidArgument => "invalid storage arguments",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(mr_enclave: u8, mr_signer: u8, prod_id: u16) -> ReportBody {
        let mut raw = [0u8; crate::sgx::report::REPORT_BODY_LEN];
        raw[64..96].fill(mr_enclave);
        raw[128..160].fill(mr_signer);
        raw[256..258].copy_from_slice(&prod_id.to_le_bytes());
        ReportBody::from_array(raw)
    }

    #[test]
    fn policy_codes() {
        for p in [KeyPolicy::MrEnclave, KeyPolicy::MrSigner] {
            assert_eq!(KeyPolicy::from_bits(p.bits()), Some(p));
            assert_eq!(KeyPolicy::from_byte(p.to_byte()), Some(p));
        }
        assert_eq!(KeyPolicy::from_bits(0x0003), None);
        assert_eq!(KeyPolicy::from_bits(0), None);
        for code in 0..=6 {
            assert_eq!(StorageStatus::from_code(code).unwrap().code(), code);
        }
        assert_eq!(StorageStatus::from_code(7), None);
    }

    #[test]
    fn namespaces_follow_the_key_derivation_inputs() {
        let a = body(1, 9, 1);
        // Same code, other signer: same MRENCLAVE namespace.
        assert_eq!(
            namespace(KeyPolicy::MrEnclave, &a),
            namespace(KeyPolicy::MrEnclave, &body(1, 8, 1))
        );
        // New code, same signer and product: same MRSIGNER namespace,
        // different MRENCLAVE namespace.
        let b = body(2, 9, 1);
        assert_eq!(
            namespace(KeyPolicy::MrSigner, &a),
            namespace(KeyPolicy::MrSigner, &b)
        );
        assert_ne!(
            namespace(KeyPolicy::MrEnclave, &a),
            namespace(KeyPolicy::MrEnclave, &b)
        );
        // Another product of the same signer is separate.
        assert_ne!(
            namespace(KeyPolicy::MrSigner, &a),
            namespace(KeyPolicy::MrSigner, &body(1, 9, 2))
        );
        // The policies never share a namespace.
        assert_ne!(
            namespace(KeyPolicy::MrSigner, &a),
            namespace(KeyPolicy::MrEnclave, &a)
        );
    }
}
