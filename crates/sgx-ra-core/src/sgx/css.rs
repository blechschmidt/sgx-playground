//! Enclave signature structure (`SIGSTRUCT`, SDK name `enclave_css_t`).
//!
//! `sgx_sign gendata` writes the 256 to-be-signed bytes, [`Gendata`] =
//! header ‖ body. The full 1808-byte [`Sigstruct`] (as embedded in
//! `enclave.signed.so`, or dumped with `sgx_sign dump -cssfile`) is
//!
//! ```text
//! header[128] ‖ modulus[384] ‖ exponent:u32 ‖ signature[384]
//!             ‖ body[128] ‖ reserved[12] ‖ q1[384] ‖ q2[384]
//! ```
//!
//! The reproducible-build check compares `body.enclave_hash` (= MRENCLAVE).
//! Never compare gendata bytewise: the header contains the build date.

use core::fmt;

use sha2::{Digest, Sha256};

use super::report::Attributes;
use super::{Measurement, ParseError};
use crate::hex::Hex;
use crate::reader::{array_at, u16_le_at, u32_le_at};

/// Size of the SIGSTRUCT header.
pub const SIGSTRUCT_HEADER_LEN: usize = 128;
/// Size of the SIGSTRUCT body.
pub const SIGSTRUCT_BODY_LEN: usize = 128;
/// Size of the `sgx_sign gendata` output (header ‖ body).
pub const GENDATA_LEN: usize = SIGSTRUCT_HEADER_LEN + SIGSTRUCT_BODY_LEN;
/// Size of the full SIGSTRUCT.
pub const SIGSTRUCT_LEN: usize = 1808;
/// Size of the RSA-3072 modulus, signature, q1 and q2 fields.
pub const RSA_KEY_LEN: usize = 384;

/// Required first 12 bytes of every SIGSTRUCT (`06000000E100000000000100`).
pub const HEADER_MAGIC: [u8; 12] = [
    0x06, 0x00, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];
/// Required `header2` value (`01010000600000006000000001000000`).
pub const HEADER2_MAGIC: [u8; 16] = [
    0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];
/// Bit of [`SigstructHeader::css_type`] marking a debug (pre-release) signature.
pub const CSS_TYPE_DEBUG: u32 = 1 << 31;

// Offsets inside the full SIGSTRUCT.
const MODULUS: usize = SIGSTRUCT_HEADER_LEN;
const EXPONENT: usize = MODULUS + RSA_KEY_LEN;
const SIGNATURE: usize = EXPONENT + 4;
const BODY: usize = SIGNATURE + RSA_KEY_LEN;
const Q1: usize = BODY + SIGSTRUCT_BODY_LEN + 12;
const Q2: usize = Q1 + RSA_KEY_LEN;

/// The 128-byte SIGSTRUCT header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigstructHeader {
    /// Signature type; bit 31 ([`CSS_TYPE_DEBUG`]) marks a debug signature.
    pub css_type: u32,
    /// Module vendor: `0` for ISVs, `0x8086` for Intel.
    pub module_vendor: u32,
    /// Signing date as BCD `0xYYYYMMDD`.
    pub date: u32,
    /// Hardware version (non-zero only for Intel architectural enclaves).
    pub hw_version: u32,
}

impl SigstructHeader {
    /// Parses and validates the header; `bytes` must be 128 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        check_size("SIGSTRUCT header", bytes, SIGSTRUCT_HEADER_LEN)?;
        if bytes[..12] != HEADER_MAGIC {
            return Err(ParseError::BadMagic {
                what: "SIGSTRUCT header",
            });
        }
        if bytes[24..40] != HEADER2_MAGIC {
            return Err(ParseError::BadMagic {
                what: "SIGSTRUCT header2",
            });
        }
        Ok(Self {
            css_type: u32_le_at(bytes, 12),
            module_vendor: u32_le_at(bytes, 16),
            date: u32_le_at(bytes, 20),
            hw_version: u32_le_at(bytes, 40),
        })
    }

    /// Whether the signature type marks a debug signature.
    pub fn is_debug_signature(&self) -> bool {
        self.css_type & CSS_TYPE_DEBUG != 0
    }

    /// The signing date as `(year, month, day)`, or `None` if it is not BCD.
    pub fn date_ymd(&self) -> Option<(u16, u8, u8)> {
        let bcd = |v: u32, digits: u32| -> Option<u32> {
            let mut out = 0;
            for i in (0..digits).rev() {
                let d = (v >> (4 * i)) & 0xf;
                if d > 9 {
                    return None;
                }
                out = out * 10 + d;
            }
            Some(out)
        };
        let year = bcd(self.date >> 16, 4)?;
        let month = bcd((self.date >> 8) & 0xff, 2)?;
        let day = bcd(self.date & 0xff, 2)?;
        Some((year as u16, month as u8, day as u8))
    }
}

impl fmt::Debug for SigstructHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigstructHeader")
            .field("css_type", &format_args!("{:#x}", self.css_type))
            .field("module_vendor", &format_args!("{:#x}", self.module_vendor))
            .field("date", &format_args!("{:#x}", self.date))
            .field("hw_version", &self.hw_version)
            .finish()
    }
}

/// The 128-byte SIGSTRUCT body: the enclave identity the signer vouches for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigstructBody {
    /// Required `MISCSELECT`.
    pub misc_select: u32,
    /// Mask applied to `MISCSELECT` before comparison.
    pub misc_mask: u32,
    /// `ISVFAMILYID` (KSS).
    pub isv_family_id: [u8; 16],
    /// Required attributes.
    pub attributes: Attributes,
    /// Mask applied to the attributes before comparison.
    pub attribute_mask: Attributes,
    /// The enclave measurement, i.e. the expected MRENCLAVE.
    pub enclave_hash: Measurement,
    /// `ISVEXTPRODID` (KSS).
    pub isvext_prod_id: [u8; 16],
    /// `ISVPRODID`.
    pub isv_prod_id: u16,
    /// `ISVSVN`.
    pub isv_svn: u16,
}

impl SigstructBody {
    /// Parses the body; `bytes` must be 128 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        check_size("SIGSTRUCT body", bytes, SIGSTRUCT_BODY_LEN)?;
        Ok(Self {
            misc_select: u32_le_at(bytes, 0),
            misc_mask: u32_le_at(bytes, 4),
            isv_family_id: array_at(bytes, 12),
            attributes: Attributes::from_bytes(&array_at(bytes, 28)),
            attribute_mask: Attributes::from_bytes(&array_at(bytes, 44)),
            enclave_hash: Measurement(array_at(bytes, 60)),
            isvext_prod_id: array_at(bytes, 108),
            isv_prod_id: u16_le_at(bytes, 124),
            isv_svn: u16_le_at(bytes, 126),
        })
    }

    /// Whether the signer allows the enclave to be launched in debug mode,
    /// i.e. the DEBUG attribute is not forced to zero by the mask
    /// (`DisableDebug = 0` in `Enclave.config.xml`).
    pub fn allows_debug_launch(&self) -> bool {
        self.attribute_mask.flags & Attributes::FLAG_DEBUG == 0
            || self.attributes.flags & Attributes::FLAG_DEBUG != 0
    }
}

impl fmt::Debug for SigstructBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigstructBody")
            .field("misc_select", &self.misc_select)
            .field("misc_mask", &format_args!("{:#x}", self.misc_mask))
            .field("attributes", &self.attributes)
            .field("attribute_mask", &self.attribute_mask)
            .field("enclave_hash", &self.enclave_hash)
            .field("isv_prod_id", &self.isv_prod_id)
            .field("isv_svn", &self.isv_svn)
            .finish_non_exhaustive()
    }
}

/// The output of `sgx_sign gendata`: the 256 bytes a signer signs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gendata {
    /// The header (validated magic values).
    pub header: SigstructHeader,
    /// The body.
    pub body: SigstructBody,
}

impl Gendata {
    /// Parses `enclave.so.gendata`; `bytes` must be exactly 256 bytes long.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        check_size("gendata", bytes, GENDATA_LEN)?;
        Ok(Self {
            header: SigstructHeader::from_bytes(&bytes[..SIGSTRUCT_HEADER_LEN])?,
            body: SigstructBody::from_bytes(&bytes[SIGSTRUCT_HEADER_LEN..])?,
        })
    }

    /// The MRENCLAVE this enclave will have when loaded.
    pub fn mr_enclave(&self) -> Measurement {
        self.body.enclave_hash
    }
}

/// A complete SIGSTRUCT (1808 bytes). Signature verification is not
/// performed here; the parsed structure only exposes the fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sigstruct<'a> {
    raw: &'a [u8],
    header: SigstructHeader,
    body: SigstructBody,
}

impl<'a> Sigstruct<'a> {
    /// Parses a SIGSTRUCT; `bytes` must be exactly 1808 bytes long.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        check_size("SIGSTRUCT", bytes, SIGSTRUCT_LEN)?;
        Ok(Self {
            raw: bytes,
            header: SigstructHeader::from_bytes(&bytes[..SIGSTRUCT_HEADER_LEN])?,
            body: SigstructBody::from_bytes(&bytes[BODY..BODY + SIGSTRUCT_BODY_LEN])?,
        })
    }

    /// The raw 1808 bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// The header.
    pub fn header(&self) -> &SigstructHeader {
        &self.header
    }

    /// The body.
    pub fn body(&self) -> &SigstructBody {
        &self.body
    }

    /// The signer's RSA-3072 modulus, little-endian as stored.
    pub fn modulus(&self) -> &'a [u8] {
        &self.raw[MODULUS..MODULUS + RSA_KEY_LEN]
    }

    /// The RSA public exponent (SGX requires 3).
    pub fn exponent(&self) -> u32 {
        u32_le_at(self.raw, EXPONENT)
    }

    /// The RSA signature, little-endian as stored.
    pub fn signature(&self) -> &'a [u8] {
        &self.raw[SIGNATURE..SIGNATURE + RSA_KEY_LEN]
    }

    /// The `q1` helper value used by `EINIT` to verify the signature.
    pub fn q1(&self) -> &'a [u8] {
        &self.raw[Q1..Q1 + RSA_KEY_LEN]
    }

    /// The `q2` helper value used by `EINIT` to verify the signature.
    pub fn q2(&self) -> &'a [u8] {
        &self.raw[Q2..Q2 + RSA_KEY_LEN]
    }

    /// The MRENCLAVE this enclave will have when loaded.
    pub fn mr_enclave(&self) -> Measurement {
        self.body.enclave_hash
    }

    /// The MRSIGNER an enclave signed with this SIGSTRUCT reports:
    /// SHA-256 of the modulus bytes as stored.
    pub fn mr_signer(&self) -> Measurement {
        Measurement(Sha256::digest(self.modulus()).into())
    }

    /// The signed portion as `sgx_sign gendata` would output it, so a
    /// SIGSTRUCT can be compared with a locally generated gendata file.
    pub fn gendata(&self) -> Gendata {
        Gendata {
            header: self.header,
            body: self.body,
        }
    }
}

impl fmt::Debug for Sigstruct<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sigstruct")
            .field("header", &self.header)
            .field("body", &self.body)
            .field("exponent", &self.exponent())
            .field("mr_signer", &self.mr_signer())
            .field("modulus", &Hex(&self.modulus()[..8]))
            .finish_non_exhaustive()
    }
}

fn check_size(what: &'static str, bytes: &[u8], expected: usize) -> Result<(), ParseError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(ParseError::InvalidSize {
            what,
            expected,
            actual: bytes.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `enclave.so.gendata` of the blueprint C++ enclave (sgx-playground
    /// 0532c29, SDK 2.26, built 2026-11-22).
    const GENDATA: &[u8] = include_bytes!("../../../../fixtures/blueprint_enclave.so.gendata");
    /// The full SIGSTRUCT of the same build (`sgx_sign dump -cssfile`).
    const SIGSTRUCT: &[u8] = include_bytes!("../../../../fixtures/blueprint_enclave.sigstruct");

    const BLUEPRINT_MRENCLAVE: &str =
        "ed92b9ba8521bec3c3b2eacdf67846d275dd655965280028e05bf1a5f318434c";
    const BLUEPRINT_MRSIGNER: &str =
        "c5cee5fe4a89d7ef4a3070015f344eee2c72710548a9c76c5e6cf7bb18cddfb2";

    #[test]
    fn gendata_header_magic() {
        // The check the blueprint client performs (with a strippable assert).
        assert_eq!(
            HEADER_MAGIC[..],
            [
                0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
            ]
        );
        assert_eq!(GENDATA[..12], HEADER_MAGIC);
    }

    #[test]
    fn parses_gendata_fixture() {
        let g = Gendata::parse(GENDATA).unwrap();
        assert_eq!(
            g.mr_enclave(),
            Measurement::from_hex(BLUEPRINT_MRENCLAVE).unwrap()
        );
        assert_eq!(g.header.css_type, 0);
        assert!(!g.header.is_debug_signature());
        assert_eq!(g.header.module_vendor, 0);
        assert_eq!(g.header.date, 0x2026_1122);
        assert_eq!(g.header.date_ymd(), Some((2026, 11, 22)));
        assert_eq!(g.header.hw_version, 0);
        assert_eq!(g.body.misc_select, 0);
        assert_eq!(g.body.misc_mask, 0xffff_ffff);
        assert_eq!(g.body.attributes.flags, Attributes::FLAG_MODE64BIT);
        assert_eq!(g.body.attributes.xfrm, 0x3);
        assert_eq!(g.body.attribute_mask.flags, 0xff00_ffff_ffff_fffd);
        assert_eq!(g.body.attribute_mask.xfrm, 0xffff_ffff_ffff_ff1b);
        assert_eq!((g.body.isv_prod_id, g.body.isv_svn), (0, 0));
        // The blueprint config has DisableDebug = 0 (docs/PROTOCOL.md Q9).
        assert!(g.body.allows_debug_launch());
    }

    #[test]
    fn parses_sigstruct_fixture() {
        let s = Sigstruct::parse(SIGSTRUCT).unwrap();
        assert_eq!(s.exponent(), 3);
        assert_eq!(
            s.mr_enclave(),
            Measurement::from_hex(BLUEPRINT_MRENCLAVE).unwrap()
        );
        assert_eq!(
            s.mr_signer(),
            Measurement::from_hex(BLUEPRINT_MRSIGNER).unwrap()
        );
        // The SIGSTRUCT signs exactly what gendata contains.
        assert_eq!(s.gendata(), Gendata::parse(GENDATA).unwrap());
        assert_eq!(
            s.as_bytes()[..SIGSTRUCT_HEADER_LEN],
            GENDATA[..SIGSTRUCT_HEADER_LEN]
        );
        assert_eq!(
            s.as_bytes()[BODY..BODY + SIGSTRUCT_BODY_LEN],
            GENDATA[SIGSTRUCT_HEADER_LEN..]
        );
        assert_eq!(s.q2().len(), RSA_KEY_LEN);
        assert_eq!(s.signature().len(), RSA_KEY_LEN);
    }

    #[test]
    fn rejects_bad_magic_and_sizes() {
        let mut g = GENDATA.to_vec();
        g[4] = 0xe2;
        assert_eq!(
            Gendata::parse(&g),
            Err(ParseError::BadMagic {
                what: "SIGSTRUCT header"
            })
        );
        let mut g = GENDATA.to_vec();
        g[30] ^= 1;
        assert_eq!(
            Gendata::parse(&g),
            Err(ParseError::BadMagic {
                what: "SIGSTRUCT header2"
            })
        );
        assert!(matches!(
            Gendata::parse(&GENDATA[..255]),
            Err(ParseError::InvalidSize { .. })
        ));
        assert!(matches!(
            Sigstruct::parse(GENDATA),
            Err(ParseError::InvalidSize { .. })
        ));
    }

    #[test]
    fn debug_launch_detection() {
        let mut body = Gendata::parse(GENDATA).unwrap().body;
        body.attribute_mask.flags |= Attributes::FLAG_DEBUG; // DisableDebug = 1
        assert!(!body.allows_debug_launch());
    }
}
