//! Sealing: encryption under a key only this CPU derives, and only for a
//! given enclave identity (`sgx_seal_data_ex` / `sgx_unseal_data`).
//!
//! Two key policies ([`KeyPolicy`], trade-offs in `docs/SEALING.md`):
//!
//! * [`KeyPolicy::MrEnclave`] ([`seal`] / [`unseal`]): only an enclave with
//!   the same MRENCLAVE on the same CPU can unseal. Any change to the code,
//!   the toolchain or `Enclave.config.xml` loses access for good.
//! * [`KeyPolicy::MrSigner`] ([`seal_with`] / [`unseal_with`]): any enclave
//!   signed with the same key, with the same ISVPRODID and an ISVSVN at
//!   least as high, can unseal on the same CPU. The signer can migrate data
//!   to new code, and can equally sign code that leaks it.
//!
//! In both cases the CPU's TCB (CPUSVN) must be at least the sealer's.
//!
//! Blobs are stored outside the enclave, so they are confidential and
//! integrity-protected but **not** fresh: the host can replay an older blob
//! or delete it. Applications that need rollback protection must add it
//! themselves.
//!
//! The key policy recorded in a blob is chosen by whoever sealed it, so
//! [`unseal_with`] insists on the policy the caller expects. Otherwise an
//! MRENCLAVE-only secret could be substituted with a blob that a *different*
//! enclave of the same signer sealed under MRSIGNER, which this enclave
//! would happily open. Use the additional data to bind a blob to its purpose
//! (a label, a slot, a version) and check it after unsealing.
//!
//! The attribute mask follows the SDK default (`TSEAL_DEFAULT_FLAGSMASK`):
//! it includes the DEBUG bit, so a debug launch of the same image derives a
//! different key and cannot unseal production data.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

pub use sgx_ra_core::storage::KeyPolicy;

use crate::ffi;
use crate::platform::SgxStatus;

/// `TSEAL_DEFAULT_FLAGSMASK`: INITTED, DEBUG, bit 3 and the reserved top byte.
const FLAGS_MASK: u64 = 0xFF00_0000_0000_000B;
/// `TSEAL_DEFAULT_MISCMASK`.
const MISC_MASK: u32 = 0xF000_0000;
/// `sizeof(sgx_sealed_data_t)`: the fixed blob header.
pub const SEALED_HEADER_LEN: usize = 560;
/// Alignment of `sgx_sealed_data_t`.
const SEALED_ALIGN: usize = 8;
/// Offset of `key_request.key_policy` in the blob.
const KEY_POLICY_OFFSET: usize = 2;
/// Offset of `key_request.isv_svn` in the blob.
const ISV_SVN_OFFSET: usize = 4;

/// `SGX_ERROR_INVALID_CPUSVN`.
const INVALID_CPUSVN: SgxStatus = SgxStatus(0x4001);
/// `SGX_ERROR_INVALID_ISVSVN`.
const INVALID_ISVSVN: SgxStatus = SgxStatus(0x4002);

/// Errors of sealing and unsealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The input is too large to be sealed.
    TooLarge,
    /// The blob is not a well-formed sealed-data structure.
    Malformed,
    /// The blob was sealed under another key policy than expected.
    WrongPolicy,
    /// The blob failed authentication: wrong enclave, wrong CPU, or
    /// tampered data.
    Authentication,
    /// The blob was sealed by an enclave with a higher ISVSVN or on a CPU
    /// with a newer TCB; this enclave cannot derive its key.
    SvnTooHigh,
    /// Another SDK failure.
    Sdk(SgxStatus),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("data too large to seal"),
            Self::Malformed => f.write_str("malformed sealed blob"),
            Self::WrongPolicy => f.write_str("sealed blob uses an unexpected key policy"),
            Self::Authentication => f.write_str("sealed blob failed authentication"),
            Self::SvnTooHigh => f.write_str("sealed blob comes from a newer enclave or TCB"),
            Self::Sdk(status) => write!(f, "sealing failed: {status}"),
        }
    }
}

impl core::error::Error for SealError {}

/// The unauthenticated header fields of a sealed blob, readable without
/// the key. Use them for routing only; [`unseal_with`] authenticates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedHeader {
    /// The key policy, if it is one of the two supported ones.
    pub policy: Option<KeyPolicy>,
    /// The ISVSVN of the enclave that sealed the blob.
    pub isv_svn: u16,
}

/// The contents of an unsealed blob.
pub struct Unsealed {
    /// The decrypted data, wiped on drop.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// The authenticated, unencrypted associated data.
    pub additional_data: Vec<u8>,
    /// The key policy the blob was sealed under (authenticated: it selects
    /// the key that verified the blob).
    pub policy: KeyPolicy,
    /// The sealer's ISVSVN (authenticated likewise). Lower than this
    /// enclave's ISVSVN means the blob comes from an older version: re-seal
    /// it so that older versions cannot read the next copy.
    pub isv_svn: u16,
}

impl fmt::Debug for Unsealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unsealed")
            .field("plaintext_len", &self.plaintext.len())
            .field("additional_data_len", &self.additional_data.len())
            .field("policy", &self.policy)
            .field("isv_svn", &self.isv_svn)
            .finish()
    }
}

/// An 8-byte aligned, zero-initialised scratch buffer for
/// `sgx_sealed_data_t`, wiped on drop.
struct AlignedBuf {
    words: Zeroizing<Vec<u64>>,
    len: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        Self {
            words: Zeroizing::new(vec![0u64; len.div_ceil(SEALED_ALIGN)]),
            len,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = Self::new(bytes.len());
        buf.as_mut_bytes().copy_from_slice(bytes);
        buf
    }

    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the u64 storage covers at least `len` initialised bytes,
        // and u8 has no alignment or validity requirements.
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len) }
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_bytes`, with exclusive access through `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.len) }
    }
}

fn len_u32(len: usize) -> Result<u32, SealError> {
    u32::try_from(len).map_err(|_| SealError::TooLarge)
}

/// Size of the blob produced by sealing the given lengths.
fn sealed_size(additional_len: u32, plaintext_len: u32) -> Result<u32, SealError> {
    // SAFETY: pure arithmetic in the SDK.
    match unsafe { ffi::sgx_calc_sealed_data_size(additional_len, plaintext_len) } {
        u32::MAX => Err(SealError::TooLarge),
        n => Ok(n),
    }
}

/// Size of the blob [`seal_with`] produces for these lengths.
pub fn sealed_len(plaintext_len: usize, additional_len: usize) -> Result<usize, SealError> {
    Ok(sealed_size(len_u32(additional_len)?, len_u32(plaintext_len)?)? as usize)
}

/// Seals `plaintext` (encrypted and authenticated) together with
/// `additional_data` (authenticated only) to this enclave's MRENCLAVE.
pub fn seal(plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, SealError> {
    seal_with(KeyPolicy::MrEnclave, plaintext, additional_data)
}

/// Seals under the given key policy. The blob records the policy and this
/// enclave's ISVSVN.
pub fn seal_with(
    policy: KeyPolicy,
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>, SealError> {
    let plaintext_len = len_u32(plaintext.len())?;
    let additional_len = len_u32(additional_data.len())?;
    if plaintext_len == 0 {
        // The SDK requires a non-empty text to encrypt.
        return Err(SealError::Sdk(SgxStatus::INVALID_PARAMETER));
    }
    let size = sealed_size(additional_len, plaintext_len)?;
    let mut buf = AlignedBuf::new(size as usize);
    let additional_ptr = if additional_data.is_empty() {
        core::ptr::null()
    } else {
        additional_data.as_ptr()
    };
    // SAFETY: input pointers and lengths come from live slices (or null with
    // length 0); `buf` is an aligned, writable buffer of exactly `size`.
    let status = unsafe {
        ffi::sgx_seal_data_ex(
            policy.bits(),
            ffi::Attributes {
                flags: FLAGS_MASK,
                xfrm: 0,
            },
            MISC_MASK,
            additional_len,
            additional_ptr,
            plaintext_len,
            plaintext.as_ptr(),
            size,
            buf.words.as_mut_ptr().cast(),
        )
    };
    SgxStatus::check(status).map_err(SealError::Sdk)?;
    Ok(buf.as_bytes().to_vec())
}

/// Reads the unauthenticated header of `blob`.
pub fn sealed_header(blob: &[u8]) -> Result<SealedHeader, SealError> {
    if blob.len() < SEALED_HEADER_LEN {
        return Err(SealError::Malformed);
    }
    let policy = u16::from_le_bytes([blob[KEY_POLICY_OFFSET], blob[KEY_POLICY_OFFSET + 1]]);
    Ok(SealedHeader {
        policy: KeyPolicy::from_bits(policy),
        isv_svn: u16::from_le_bytes([blob[ISV_SVN_OFFSET], blob[ISV_SVN_OFFSET + 1]]),
    })
}

/// Opens a blob produced by [`seal`]: it must be sealed to MRENCLAVE.
pub fn unseal(blob: &[u8]) -> Result<Unsealed, SealError> {
    unseal_with(KeyPolicy::MrEnclave, blob)
}

/// Opens a blob that must have been sealed under `policy`.
///
/// The blob is untrusted input: its policy and length fields are checked
/// before the SDK parses it.
pub fn unseal_with(policy: KeyPolicy, blob: &[u8]) -> Result<Unsealed, SealError> {
    let header = sealed_header(blob)?;
    if header.policy != Some(policy) {
        return Err(SealError::WrongPolicy);
    }
    let buf = AlignedBuf::from_bytes(blob);
    // SAFETY: `buf` holds at least the full fixed header, which is all these
    // accessors read.
    let (additional_len, plaintext_len) = unsafe {
        (
            ffi::sgx_get_add_mac_txt_len(buf.as_ptr()),
            ffi::sgx_get_encrypt_txt_len(buf.as_ptr()),
        )
    };
    if additional_len == u32::MAX || plaintext_len == u32::MAX || plaintext_len == 0 {
        return Err(SealError::Malformed);
    }
    // The SDK trusts the header's lengths; make sure they describe exactly
    // the bytes we hold, so it never reads past the buffer.
    let expected = sealed_size(additional_len, plaintext_len).map_err(|_| SealError::Malformed)?;
    if expected as usize != blob.len() {
        return Err(SealError::Malformed);
    }

    let mut plaintext = Zeroizing::new(vec![0u8; plaintext_len as usize]);
    let mut additional_data = vec![0u8; additional_len as usize];
    let mut plaintext_out = plaintext_len;
    let mut additional_out = additional_len;
    let additional_ptr = if additional_data.is_empty() {
        core::ptr::null_mut()
    } else {
        additional_data.as_mut_ptr()
    };
    // SAFETY: `buf` is a size-checked sealed blob; output buffers have the
    // capacities passed in the length arguments.
    let status = unsafe {
        ffi::sgx_unseal_data(
            buf.as_ptr(),
            additional_ptr,
            &mut additional_out,
            plaintext.as_mut_ptr(),
            &mut plaintext_out,
        )
    };
    match SgxStatus::check(status) {
        Ok(()) => {}
        Err(SgxStatus::MAC_MISMATCH) => return Err(SealError::Authentication),
        Err(INVALID_CPUSVN | INVALID_ISVSVN) => return Err(SealError::SvnTooHigh),
        Err(status) => return Err(SealError::Sdk(status)),
    }
    if plaintext_out != plaintext_len || additional_out != additional_len {
        return Err(SealError::Malformed);
    }
    Ok(Unsealed {
        plaintext,
        additional_data,
        policy,
        isv_svn: header.isv_svn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::fake::{FAKE_SELF, FakeEnclave};

    fn as_enclave<R>(e: FakeEnclave, f: impl FnOnce() -> R) -> R {
        let old = FAKE_SELF.with(|c| c.replace(e));
        let r = f();
        FAKE_SELF.with(|c| c.set(old));
        r
    }

    #[test]
    fn rejects_short_or_inconsistent_blobs() {
        assert_eq!(unseal(&[0u8; 10]).unwrap_err(), SealError::Malformed);
        let mut blob = seal(b"secret", b"ad").unwrap();
        // Truncated or extended blobs never reach the SDK.
        assert_eq!(
            unseal(&blob[..blob.len() - 1]).unwrap_err(),
            SealError::Malformed
        );
        blob.push(0);
        assert_eq!(unseal(&blob).unwrap_err(), SealError::Malformed);
        blob.pop();
        // plain_text_offset beyond payload_size.
        let mut bad = blob.clone();
        bad[512..516].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(unseal(&bad).unwrap_err(), SealError::Malformed);
        // A header that claims more payload than the blob holds.
        let mut bad = blob.clone();
        bad[528..532].copy_from_slice(&1000u32.to_le_bytes());
        assert_eq!(unseal(&bad).unwrap_err(), SealError::Malformed);
    }

    #[test]
    fn rejects_empty_plaintext() {
        assert_eq!(
            seal(&[], b"ad").unwrap_err(),
            SealError::Sdk(SgxStatus::INVALID_PARAMETER)
        );
    }

    #[test]
    fn aligned_buffer_roundtrip() {
        let buf = AlignedBuf::from_bytes(&[1, 2, 3, 4, 5]);
        assert_eq!(buf.as_bytes(), &[1, 2, 3, 4, 5]);
        assert_eq!(buf.as_ptr() as usize % SEALED_ALIGN, 0);
    }

    #[test]
    fn roundtrip_both_policies() {
        for policy in [KeyPolicy::MrEnclave, KeyPolicy::MrSigner] {
            let blob = seal_with(policy, b"secret", b"label").unwrap();
            assert_eq!(blob.len(), sealed_len(6, 5).unwrap());
            assert_eq!(
                sealed_header(&blob).unwrap(),
                SealedHeader {
                    policy: Some(policy),
                    isv_svn: 1
                }
            );
            let u = unseal_with(policy, &blob).unwrap();
            assert_eq!(&u.plaintext[..], b"secret");
            assert_eq!(u.additional_data, b"label");
            assert_eq!((u.policy, u.isv_svn), (policy, 1));
        }
        let blob = seal(b"x", &[]).unwrap();
        assert!(unseal(&blob).unwrap().additional_data.is_empty());
    }

    #[test]
    fn policy_must_match() {
        let signer_blob = seal_with(KeyPolicy::MrSigner, b"secret", b"").unwrap();
        assert_eq!(unseal(&signer_blob).unwrap_err(), SealError::WrongPolicy);
        let enclave_blob = seal(b"secret", b"").unwrap();
        assert_eq!(
            unseal_with(KeyPolicy::MrSigner, &enclave_blob).unwrap_err(),
            SealError::WrongPolicy
        );
        // Rewriting the policy field changes the derived key.
        let mut forged = enclave_blob.clone();
        forged[KEY_POLICY_OFFSET] = 0x02;
        assert_eq!(
            unseal_with(KeyPolicy::MrSigner, &forged).unwrap_err(),
            SealError::Authentication
        );
    }

    #[test]
    fn tampering_is_detected() {
        let blob = seal(b"secret", b"label").unwrap();
        for index in [40, 100, SEALED_HEADER_LEN, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[index] ^= 1;
            assert_eq!(
                unseal(&bad).unwrap_err(),
                SealError::Authentication,
                "byte {index}"
            );
        }
    }

    #[test]
    fn key_derivation_follows_the_policy() {
        let base = FakeEnclave::DEFAULT;
        let by_enclave = seal(b"e", b"").unwrap();
        let by_signer = seal_with(KeyPolicy::MrSigner, b"s", b"").unwrap();

        // New code, same signer: MRENCLAVE data is lost, MRSIGNER migrates.
        let upgraded = FakeEnclave {
            mr_enclave: 0x01,
            isv_svn: 2,
            ..base
        };
        as_enclave(upgraded, || {
            assert_eq!(unseal(&by_enclave).unwrap_err(), SealError::Authentication);
            let u = unseal_with(KeyPolicy::MrSigner, &by_signer).unwrap();
            assert_eq!((&u.plaintext[..], u.isv_svn), (&b"s"[..], 1));
        });
        // An older version cannot read what a newer one sealed.
        let newer = as_enclave(upgraded, || {
            seal_with(KeyPolicy::MrSigner, b"n", b"").unwrap()
        });
        assert_eq!(
            unseal_with(KeyPolicy::MrSigner, &newer).unwrap_err(),
            SealError::SvnTooHigh
        );
        // Another signer, another product, or another CPU: nothing opens.
        for other in [
            FakeEnclave {
                mr_signer: 0x52,
                ..base
            },
            FakeEnclave {
                isv_prod_id: 2,
                ..base
            },
            FakeEnclave { cpu: 1, ..base },
        ] {
            as_enclave(other, || {
                assert_eq!(
                    unseal_with(KeyPolicy::MrSigner, &by_signer).unwrap_err(),
                    SealError::Authentication
                );
            });
        }
        as_enclave(FakeEnclave { cpu: 1, ..base }, || {
            assert_eq!(unseal(&by_enclave).unwrap_err(), SealError::Authentication);
        });
    }
}
