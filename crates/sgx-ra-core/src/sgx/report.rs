//! `sgx_report_body_t`, `sgx_report_t` and `sgx_target_info_t`.

use core::fmt;

use super::{Measurement, ParseError, ReportData};
use crate::hex::Hex;
use crate::reader::{array_at, u16_le_at, u32_le_at, u64_le_at};

/// Size of `sgx_report_body_t`.
pub const REPORT_BODY_LEN: usize = 384;
/// Size of `sgx_report_t` (body ‖ key_id ‖ mac).
pub const REPORT_LEN: usize = 432;
/// Size of `sgx_target_info_t`.
pub const TARGET_INFO_LEN: usize = 512;

// Offsets inside sgx_report_body_t (docs/PROTOCOL.md §3.2).
const CPU_SVN: usize = 0;
const MISC_SELECT: usize = 16;
const ISV_EXT_PROD_ID: usize = 32;
const ATTRIBUTES: usize = 48;
const MR_ENCLAVE: usize = 64;
const MR_SIGNER: usize = 128;
const CONFIG_ID: usize = 192;
const ISV_PROD_ID: usize = 256;
const ISV_SVN: usize = 258;
const CONFIG_SVN: usize = 260;
const ISV_FAMILY_ID: usize = 304;
const REPORT_DATA: usize = 320;

/// The SGX enclave attributes (`sgx_attributes_t`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Attributes {
    /// `SECS.ATTRIBUTES.FLAGS`.
    pub flags: u64,
    /// `SECS.ATTRIBUTES.XFRM`.
    pub xfrm: u64,
}

impl Attributes {
    /// The enclave has been initialised (`EINIT`).
    pub const FLAG_INIT: u64 = 1 << 0;
    /// The enclave runs in debug mode: its memory is readable by the host.
    pub const FLAG_DEBUG: u64 = 1 << 1;
    /// The enclave runs in 64-bit mode.
    pub const FLAG_MODE64BIT: u64 = 1 << 2;
    /// The enclave may use the provisioning key.
    pub const FLAG_PROVISION_KEY: u64 = 1 << 4;
    /// The enclave may use the launch (EINITTOKEN) key.
    pub const FLAG_EINITTOKEN_KEY: u64 = 1 << 5;
    /// Key separation and sharing is enabled.
    pub const FLAG_KSS: u64 = 1 << 7;

    /// Parses the 16-byte little-endian encoding.
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self {
            flags: u64_le_at(bytes, 0),
            xfrm: u64_le_at(bytes, 8),
        }
    }

    /// The 16-byte little-endian encoding.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..].copy_from_slice(&self.xfrm.to_le_bytes());
        out
    }

    /// Whether the DEBUG flag is set.
    pub fn is_debug(&self) -> bool {
        self.flags & Self::FLAG_DEBUG != 0
    }

    /// Whether the MODE64BIT flag is set.
    pub fn is_mode64bit(&self) -> bool {
        self.flags & Self::FLAG_MODE64BIT != 0
    }

    /// Whether the PROVISION_KEY flag is set.
    pub fn has_provision_key(&self) -> bool {
        self.flags & Self::FLAG_PROVISION_KEY != 0
    }

    /// Whether the KSS flag is set.
    pub fn has_kss(&self) -> bool {
        self.flags & Self::FLAG_KSS != 0
    }
}

impl fmt::Debug for Attributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Attributes {{ flags: {:#x}, xfrm: {:#x} }}",
            self.flags, self.xfrm
        )
    }
}

/// An SGX report body (`sgx_report_body_t`, 384 bytes).
///
/// The raw bytes are kept as-is so the exact attested body can be hashed
/// (the handshake binds the channel to `SHA-256(report_body)`); the fields are
/// exposed through accessors.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReportBody([u8; REPORT_BODY_LEN]);

impl ReportBody {
    /// Wraps a raw 384-byte report body.
    pub const fn from_array(raw: [u8; REPORT_BODY_LEN]) -> Self {
        Self(raw)
    }

    /// Parses a report body; `bytes` must be exactly 384 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let raw: [u8; REPORT_BODY_LEN] = bytes.try_into().map_err(|_| ParseError::InvalidSize {
            what: "report body",
            expected: REPORT_BODY_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(raw))
    }

    /// The raw 384 bytes.
    pub fn as_bytes(&self) -> &[u8; REPORT_BODY_LEN] {
        &self.0
    }

    /// `CPUSVN` of the platform at report time.
    pub fn cpu_svn(&self) -> [u8; 16] {
        array_at(&self.0, CPU_SVN)
    }

    /// `MISCSELECT`.
    pub fn misc_select(&self) -> u32 {
        u32_le_at(&self.0, MISC_SELECT)
    }

    /// `ISVEXTPRODID` (KSS).
    pub fn isv_ext_prod_id(&self) -> [u8; 16] {
        array_at(&self.0, ISV_EXT_PROD_ID)
    }

    /// Enclave attributes (DEBUG, MODE64BIT, …).
    pub fn attributes(&self) -> Attributes {
        Attributes::from_bytes(&array_at(&self.0, ATTRIBUTES))
    }

    /// `MRENCLAVE`: the measurement of the enclave's code and initial data.
    pub fn mr_enclave(&self) -> Measurement {
        Measurement(array_at(&self.0, MR_ENCLAVE))
    }

    /// `MRSIGNER`: SHA-256 of the enclave signer's RSA modulus.
    pub fn mr_signer(&self) -> Measurement {
        Measurement(array_at(&self.0, MR_SIGNER))
    }

    /// `CONFIGID` (KSS).
    pub fn config_id(&self) -> [u8; 64] {
        array_at(&self.0, CONFIG_ID)
    }

    /// `ISVPRODID`.
    pub fn isv_prod_id(&self) -> u16 {
        u16_le_at(&self.0, ISV_PROD_ID)
    }

    /// `ISVSVN`.
    pub fn isv_svn(&self) -> u16 {
        u16_le_at(&self.0, ISV_SVN)
    }

    /// `CONFIGSVN` (KSS).
    pub fn config_svn(&self) -> u16 {
        u16_le_at(&self.0, CONFIG_SVN)
    }

    /// `ISVFAMILYID` (KSS).
    pub fn isv_family_id(&self) -> [u8; 16] {
        array_at(&self.0, ISV_FAMILY_ID)
    }

    /// The 64 bytes of user data bound into the report.
    pub fn report_data(&self) -> ReportData {
        ReportData(array_at(&self.0, REPORT_DATA))
    }
}

impl fmt::Debug for ReportBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReportBody")
            .field("cpu_svn", &Hex(&self.cpu_svn()))
            .field("misc_select", &self.misc_select())
            .field("attributes", &self.attributes())
            .field("mr_enclave", &self.mr_enclave())
            .field("mr_signer", &self.mr_signer())
            .field("isv_prod_id", &self.isv_prod_id())
            .field("isv_svn", &self.isv_svn())
            .field("config_svn", &self.config_svn())
            .field("report_data", &self.report_data())
            .finish_non_exhaustive()
    }
}

/// A local SGX report (`sgx_report_t`): body ‖ key_id ‖ MAC.
///
/// Produced by `EREPORT` inside the application enclave and consumed by the
/// quoting enclave. The MAC can only be checked by the target enclave.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Report([u8; REPORT_LEN]);

impl Report {
    /// Parses a report; `bytes` must be exactly 432 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let raw: [u8; REPORT_LEN] = bytes.try_into().map_err(|_| ParseError::InvalidSize {
            what: "report",
            expected: REPORT_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(raw))
    }

    /// The raw 432 bytes.
    pub fn as_bytes(&self) -> &[u8; REPORT_LEN] {
        &self.0
    }

    /// The report body.
    pub fn body(&self) -> ReportBody {
        ReportBody(array_at(&self.0, 0))
    }

    /// The key id used to derive the report key.
    pub fn key_id(&self) -> [u8; 32] {
        array_at(&self.0, REPORT_BODY_LEN)
    }

    /// The CMAC over the body.
    pub fn mac(&self) -> [u8; 16] {
        array_at(&self.0, REPORT_BODY_LEN + 32)
    }
}

impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Report")
            .field("body", &self.body())
            .field("key_id", &Hex(&self.key_id()))
            .field("mac", &Hex(&self.mac()))
            .finish()
    }
}

/// Target information (`sgx_target_info_t`) of the enclave a report is
/// addressed to, normally the quoting enclave.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TargetInfo([u8; TARGET_INFO_LEN]);

impl TargetInfo {
    /// Parses target info; `bytes` must be exactly 512 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let raw: [u8; TARGET_INFO_LEN] = bytes.try_into().map_err(|_| ParseError::InvalidSize {
            what: "target info",
            expected: TARGET_INFO_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(raw))
    }

    /// The raw 512 bytes.
    pub fn as_bytes(&self) -> &[u8; TARGET_INFO_LEN] {
        &self.0
    }

    /// MRENCLAVE of the target enclave.
    pub fn mr_enclave(&self) -> Measurement {
        Measurement(array_at(&self.0, 0))
    }

    /// Attributes of the target enclave.
    pub fn attributes(&self) -> Attributes {
        Attributes::from_bytes(&array_at(&self.0, 32))
    }
}

impl fmt::Debug for TargetInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetInfo")
            .field("mr_enclave", &self.mr_enclave())
            .field("attributes", &self.attributes())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_body_field_offsets() {
        let mut raw = [0u8; REPORT_BODY_LEN];
        raw[MISC_SELECT..MISC_SELECT + 4].copy_from_slice(&7u32.to_le_bytes());
        raw[ATTRIBUTES] = 0x07; // INIT | DEBUG | MODE64BIT
        raw[ATTRIBUTES + 8] = 0xe7;
        raw[MR_ENCLAVE] = 0xaa;
        raw[MR_SIGNER + 31] = 0xbb;
        raw[ISV_PROD_ID..ISV_PROD_ID + 2].copy_from_slice(&0x1234u16.to_le_bytes());
        raw[ISV_SVN..ISV_SVN + 2].copy_from_slice(&0x0102u16.to_le_bytes());
        raw[REPORT_DATA + 63] = 0xcc;

        let body = ReportBody::from_array(raw);
        assert_eq!(body.misc_select(), 7);
        let attrs = body.attributes();
        assert!(attrs.is_debug() && attrs.is_mode64bit() && !attrs.has_kss());
        assert_eq!(attrs.xfrm, 0xe7);
        assert_eq!(attrs.to_bytes(), raw[ATTRIBUTES..ATTRIBUTES + 16]);
        assert_eq!(body.mr_enclave().0[0], 0xaa);
        assert_eq!(body.mr_signer().0[31], 0xbb);
        assert_eq!(body.isv_prod_id(), 0x1234);
        assert_eq!(body.isv_svn(), 0x0102);
        assert_eq!(body.report_data().0[63], 0xcc);
    }

    #[test]
    fn fixed_sizes_are_enforced() {
        assert!(ReportBody::from_bytes(&[0u8; 383]).is_err());
        assert!(Report::from_bytes(&[0u8; 433]).is_err());
        assert!(TargetInfo::from_bytes(&[0u8; 511]).is_err());

        let mut raw = [0u8; REPORT_LEN];
        raw[REPORT_BODY_LEN] = 1;
        raw[REPORT_LEN - 1] = 2;
        let report = Report::from_bytes(&raw).unwrap();
        assert_eq!(report.key_id()[0], 1);
        assert_eq!(report.mac()[15], 2);
    }
}
