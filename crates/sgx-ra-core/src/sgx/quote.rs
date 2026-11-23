//! DCAP ECDSA quotes, versions 3 and 4 (SGX TEE type only).
//!
//! Layout references: `docs/PROTOCOL.md` §3.1–3.3 and the Intel SGX ECDSA
//! Quote Library API (`sgx_quote_3.h`, `sgx_quote_4.h`).
//!
//! ```text
//! v3: header[48] ‖ report_body[384] ‖ sig_len:u32 ‖ sig[64] ‖ att_key[64]
//!     ‖ qe_report[384] ‖ qe_report_sig[64] ‖ auth_len:u16 ‖ auth
//!     ‖ cert_type:u16 ‖ cert_len:u32 ‖ cert
//! v4: header[48] ‖ report_body[384] ‖ sig_len:u32 ‖ sig[64] ‖ att_key[64]
//!     ‖ 6:u16 ‖ len:u32 ‖ ( qe_report[384] ‖ qe_report_sig[64]
//!                          ‖ auth_len:u16 ‖ auth ‖ cert_type:u16 ‖ cert_len:u32 ‖ cert )
//! ```
//!
//! Both versions are normalised into the same [`QuoteSignature`].

use core::fmt;

use super::ParseError;
use super::report::{REPORT_BODY_LEN, ReportBody};
use crate::hex::Hex;
use crate::reader::Reader;

/// Size of the quote header.
pub const QUOTE_HEADER_LEN: usize = 48;
/// Number of leading quote bytes covered by the attestation-key signature
/// (header ‖ report body).
pub const QUOTE_SIGNED_LEN: usize = QUOTE_HEADER_LEN + REPORT_BODY_LEN;
/// Offset of the report body inside the quote.
pub const REPORT_BODY_OFFSET: usize = QUOTE_HEADER_LEN;
/// Attestation key type ECDSA-256-with-P-256.
pub const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;
/// TEE type of SGX quotes (v4 header; reserved and zero in v3).
pub const TEE_TYPE_SGX: u32 = 0;
/// Vendor id of Intel's quoting enclave.
pub const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];
/// Certification data type: PEM-encoded PCK leaf ‖ intermediate ‖ root.
pub const CERT_DATA_PCK_CERT_CHAIN: u16 = 5;
/// Certification data type: QE report certification data (v4 outer layer).
pub const CERT_DATA_QE_REPORT: u16 = 6;

/// The 48-byte quote header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QuoteHeader {
    /// Quote format version (3 or 4).
    pub version: u16,
    /// Attestation key type (always [`ATT_KEY_TYPE_ECDSA_P256`] after parsing).
    pub att_key_type: u16,
    /// TEE type in v4; reserved in v3. Always [`TEE_TYPE_SGX`] after parsing.
    pub tee_type: u32,
    /// Security version of the quoting enclave.
    pub qe_svn: u16,
    /// Security version of the provisioning certification enclave.
    pub pce_svn: u16,
    /// Vendor of the quoting enclave.
    pub qe_vendor_id: [u8; 16],
    /// Custom data; for Intel's QE the first 16 bytes are the QE platform id.
    pub user_data: [u8; 20],
}

impl fmt::Debug for QuoteHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuoteHeader")
            .field("version", &self.version)
            .field("att_key_type", &self.att_key_type)
            .field("tee_type", &self.tee_type)
            .field("qe_svn", &self.qe_svn)
            .field("pce_svn", &self.pce_svn)
            .field("qe_vendor_id", &Hex(&self.qe_vendor_id))
            .field("user_data", &Hex(&self.user_data))
            .finish()
    }
}

/// Typed certification data (`sgx_ql_certification_data_t`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CertificationData<'a> {
    /// Certification data type (see [`CERT_DATA_PCK_CERT_CHAIN`]).
    pub cert_type: u16,
    /// The raw certification data.
    pub data: &'a [u8],
}

impl fmt::Debug for CertificationData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificationData")
            .field("cert_type", &self.cert_type)
            .field("len", &self.data.len())
            .finish()
    }
}

/// The ECDSA signature section of a quote, normalised across v3 and v4.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QuoteSignature<'a> {
    /// ECDSA P-256 signature (r ‖ s, big-endian) over the first
    /// [`QUOTE_SIGNED_LEN`] quote bytes, by the attestation key.
    pub signature: [u8; 64],
    /// The attestation public key (x ‖ y, big-endian).
    pub attestation_key: [u8; 64],
    /// The quoting enclave's report; its report_data binds the attestation key.
    pub qe_report: ReportBody,
    /// ECDSA P-256 signature over `qe_report` by the PCK key.
    pub qe_report_signature: [u8; 64],
    /// QE authentication data, hashed into the QE report's report_data.
    pub qe_auth_data: &'a [u8],
    /// Certification data for the PCK key (normally the PEM chain, type 5).
    pub certification: CertificationData<'a>,
}

impl fmt::Debug for QuoteSignature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuoteSignature")
            .field("attestation_key", &Hex(&self.attestation_key))
            .field("qe_report", &self.qe_report)
            .field("qe_auth_data", &Hex(self.qe_auth_data))
            .field("certification", &self.certification)
            .finish_non_exhaustive()
    }
}

/// A structurally valid DCAP quote borrowing its input.
///
/// Parsing is strict: version 3 or 4, ECDSA-P256 attestation key, SGX TEE
/// type, every length field consistent and no trailing bytes. Nothing is
/// verified cryptographically.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Quote<'a> {
    raw: &'a [u8],
    header: QuoteHeader,
    report_body: ReportBody,
    signature: QuoteSignature<'a>,
}

impl<'a> Quote<'a> {
    /// Parses a complete quote.
    pub fn parse(raw: &'a [u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(raw, "quote");
        let header = QuoteHeader {
            version: r.u16_le()?,
            att_key_type: r.u16_le()?,
            tee_type: r.u32_le()?,
            qe_svn: r.u16_le()?,
            pce_svn: r.u16_le()?,
            qe_vendor_id: r.array()?,
            user_data: r.array()?,
        };
        if header.version != 3 && header.version != 4 {
            return Err(ParseError::UnsupportedQuoteVersion(header.version));
        }
        if header.att_key_type != ATT_KEY_TYPE_ECDSA_P256 {
            return Err(ParseError::UnsupportedAttestationKeyType(
                header.att_key_type,
            ));
        }
        if header.tee_type != TEE_TYPE_SGX {
            return Err(ParseError::UnsupportedTeeType(header.tee_type));
        }
        let report_body = ReportBody::from_bytes(r.take(REPORT_BODY_LEN)?)?;
        debug_assert_eq!(r.position(), QUOTE_SIGNED_LEN);

        let sig_len = r.u32_le()? as usize;
        if sig_len != r.remaining() {
            return Err(if sig_len > r.remaining() {
                ParseError::Truncated {
                    what: "quote signature data",
                    needed: r.position().saturating_add(sig_len),
                    available: raw.len(),
                }
            } else {
                ParseError::TrailingBytes {
                    what: "quote signature data",
                    extra: r.remaining() - sig_len,
                }
            });
        }
        let sig_data = r.take(sig_len)?;
        r.finish()?;

        let signature = match header.version {
            3 => parse_signature_v3(sig_data)?,
            _ => parse_signature_v4(sig_data)?,
        };
        Ok(Self {
            raw,
            header,
            report_body,
            signature,
        })
    }

    /// The complete raw quote.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// The quote header.
    pub fn header(&self) -> &QuoteHeader {
        &self.header
    }

    /// The application enclave's report body.
    pub fn report_body(&self) -> &ReportBody {
        &self.report_body
    }

    /// The signature section.
    pub fn signature(&self) -> &QuoteSignature<'a> {
        &self.signature
    }

    /// The bytes covered by the attestation-key signature (header ‖ body).
    pub fn signed_bytes(&self) -> &'a [u8] {
        &self.raw[..QUOTE_SIGNED_LEN]
    }
}

impl fmt::Debug for Quote<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Quote")
            .field("header", &self.header)
            .field("report_body", &self.report_body)
            .field("signature", &self.signature)
            .finish()
    }
}

/// Signature, attestation key, then the QE report certification data
/// fields inline (v3 layout).
fn parse_signature_v3(sig_data: &[u8]) -> Result<QuoteSignature<'_>, ParseError> {
    let mut r = Reader::new(sig_data, "quote signature data");
    let signature = r.array()?;
    let attestation_key = r.array()?;
    let (qe_report, qe_report_signature, qe_auth_data, certification) =
        parse_qe_report_cert_data(&mut r)?;
    r.finish()?;
    Ok(QuoteSignature {
        signature,
        attestation_key,
        qe_report,
        qe_report_signature,
        qe_auth_data,
        certification,
    })
}

/// Signature, attestation key, then type-6 certification data wrapping the
/// QE report certification data (v4 layout).
fn parse_signature_v4(sig_data: &[u8]) -> Result<QuoteSignature<'_>, ParseError> {
    let mut r = Reader::new(sig_data, "quote signature data");
    let signature = r.array()?;
    let attestation_key = r.array()?;
    let outer = parse_certification_data(&mut r)?;
    r.finish()?;
    if outer.cert_type != CERT_DATA_QE_REPORT {
        return Err(ParseError::UnexpectedCertificationDataType {
            expected: CERT_DATA_QE_REPORT,
            actual: outer.cert_type,
        });
    }
    let mut inner = Reader::new(outer.data, "QE report certification data");
    let (qe_report, qe_report_signature, qe_auth_data, certification) =
        parse_qe_report_cert_data(&mut inner)?;
    inner.finish()?;
    Ok(QuoteSignature {
        signature,
        attestation_key,
        qe_report,
        qe_report_signature,
        qe_auth_data,
        certification,
    })
}

type QeReportCertData<'a> = (ReportBody, [u8; 64], &'a [u8], CertificationData<'a>);

fn parse_qe_report_cert_data<'a>(r: &mut Reader<'a>) -> Result<QeReportCertData<'a>, ParseError> {
    let qe_report = ReportBody::from_bytes(r.take(REPORT_BODY_LEN)?)?;
    let qe_report_signature = r.array()?;
    let auth_len = r.u16_le()? as usize;
    let qe_auth_data = r.take(auth_len)?;
    let certification = parse_certification_data(r)?;
    Ok((qe_report, qe_report_signature, qe_auth_data, certification))
}

fn parse_certification_data<'a>(r: &mut Reader<'a>) -> Result<CertificationData<'a>, ParseError> {
    let cert_type = r.u16_le()?;
    let len = r.u32_le()? as usize;
    let data = r.take(len)?;
    Ok(CertificationData { cert_type, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sgx::Measurement;
    use alloc::vec::Vec;
    use sha2::{Digest, Sha256};

    /// DCAP v3 quote from `blechschmidt/intel-sgx-ra` (`tests/data/quote.dat`).
    const QUOTE_V3: &[u8] = include_bytes!("../../../../fixtures/quote_v3.dat");

    fn hex32(s: &str) -> Measurement {
        Measurement::from_hex(s).unwrap()
    }

    #[test]
    fn parses_v3_fixture() {
        assert_eq!(QUOTE_V3.len(), 4734);
        let quote = Quote::parse(QUOTE_V3).unwrap();
        let h = quote.header();
        assert_eq!(h.version, 3);
        assert_eq!(h.att_key_type, ATT_KEY_TYPE_ECDSA_P256);
        assert_eq!(h.tee_type, TEE_TYPE_SGX);
        assert_eq!((h.qe_svn, h.pce_svn), (9, 14));
        assert_eq!(h.qe_vendor_id, INTEL_QE_VENDOR_ID);

        let body = quote.report_body();
        assert_eq!(
            body.mr_enclave(),
            hex32("e413a4ed616c7a79634d5ca05a2fda746a1f0c71349a80b25a02828846fab90e")
        );
        // Same assertion as intel-sgx-ra's own test_quote_parsing.
        assert_eq!(
            body.mr_signer(),
            hex32("ac2c9fa87e4c91768b1d0c47169466c50d5a98c790639fbaefe7352a59919980")
        );
        assert_eq!(body.isv_prod_id(), 1);
        assert_eq!(body.isv_svn(), 10);
        assert_eq!(body.misc_select(), 0);
        let attrs = body.attributes();
        assert_eq!(attrs.flags, 0x5); // INIT | MODE64BIT
        assert!(!attrs.is_debug());
        assert!(attrs.is_mode64bit());
        assert_eq!(attrs.xfrm, 0xe7);
        assert_eq!(body.report_data().0, [0u8; 64]);
        assert_eq!(body.as_bytes()[..], QUOTE_V3[48..432]);
        assert_eq!(quote.signed_bytes(), &QUOTE_V3[..432]);
    }

    #[test]
    fn v3_fixture_signature_section() {
        let quote = Quote::parse(QUOTE_V3).unwrap();
        let sig = quote.signature();
        assert_eq!(sig.qe_auth_data.len(), 32);
        assert_eq!(sig.certification.cert_type, CERT_DATA_PCK_CERT_CHAIN);
        assert_eq!(sig.certification.data.len(), 3682);
        let pem = core::str::from_utf8(sig.certification.data)
            .unwrap()
            .trim_end_matches('\0');
        assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 3);

        // The QE report binds the attestation key:
        // qe_report.report_data[..32] == SHA-256(att_key ‖ qe_auth_data).
        let mut h = Sha256::new();
        h.update(sig.attestation_key);
        h.update(sig.qe_auth_data);
        let digest: [u8; 32] = h.finalize().into();
        let qe_rd = sig.qe_report.report_data();
        assert_eq!(qe_rd.0[..32], digest);
        assert_eq!(qe_rd.0[32..], [0u8; 32]);
        assert_eq!(
            sig.qe_report.mr_enclave(),
            hex32("192aa50ce1c0cef03ccf89e7b5b16b0d7978f5c2b1edcf774d87702e8154d8bf")
        );
    }

    /// Re-encodes the v3 fixture in the v4 layout (outer type-6 certification
    /// data wrapping the QE report certification data).
    fn v3_to_v4(v3: &[u8]) -> Vec<u8> {
        let sig = &v3[QUOTE_SIGNED_LEN + 4..];
        let inner = &sig[128..];
        let mut v4_sig = Vec::new();
        v4_sig.extend_from_slice(&sig[..128]);
        v4_sig.extend_from_slice(&CERT_DATA_QE_REPORT.to_le_bytes());
        v4_sig.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        v4_sig.extend_from_slice(inner);

        let mut out = Vec::new();
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&v3[2..QUOTE_SIGNED_LEN]);
        out.extend_from_slice(&(v4_sig.len() as u32).to_le_bytes());
        out.extend_from_slice(&v4_sig);
        out
    }

    #[test]
    fn parses_v4_layout() {
        let v4 = v3_to_v4(QUOTE_V3);
        let q4 = Quote::parse(&v4).unwrap();
        let q3 = Quote::parse(QUOTE_V3).unwrap();
        assert_eq!(q4.header().version, 4);
        assert_eq!(q4.report_body(), q3.report_body());
        assert_eq!(q4.signature().qe_report, q3.signature().qe_report);
        assert_eq!(q4.signature().qe_auth_data, q3.signature().qe_auth_data);
        assert_eq!(q4.signature().certification, q3.signature().certification);
        assert_eq!(
            q4.signature().attestation_key,
            q3.signature().attestation_key
        );
    }

    #[test]
    fn v4_requires_qe_report_certification_data() {
        let mut v4 = v3_to_v4(QUOTE_V3);
        let type_off = QUOTE_SIGNED_LEN + 4 + 128;
        v4[type_off..type_off + 2].copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(
            Quote::parse(&v4),
            Err(ParseError::UnexpectedCertificationDataType {
                expected: CERT_DATA_QE_REPORT,
                actual: 5
            })
        );
    }

    #[test]
    fn rejects_unsupported_header_values() {
        let mut q = QUOTE_V3.to_vec();
        q[0] = 2;
        assert_eq!(
            Quote::parse(&q),
            Err(ParseError::UnsupportedQuoteVersion(2))
        );

        let mut q = QUOTE_V3.to_vec();
        q[2] = 3;
        assert_eq!(
            Quote::parse(&q),
            Err(ParseError::UnsupportedAttestationKeyType(3))
        );

        let mut q = v3_to_v4(QUOTE_V3);
        q[4] = 0x81; // TDX
        assert_eq!(Quote::parse(&q), Err(ParseError::UnsupportedTeeType(0x81)));
    }

    #[test]
    fn rejects_length_inconsistencies() {
        // Every strict prefix fails.
        for len in [0, 47, 431, 435, 436, 1000, QUOTE_V3.len() - 1] {
            assert!(Quote::parse(&QUOTE_V3[..len]).is_err(), "prefix {len}");
        }
        // Trailing garbage fails.
        let mut q = QUOTE_V3.to_vec();
        q.push(0);
        assert!(matches!(
            Quote::parse(&q),
            Err(ParseError::TrailingBytes { extra: 1, .. })
        ));
        // A signature length that disagrees with the actual data fails even
        // if the remaining bytes would otherwise parse.
        let mut q = QUOTE_V3.to_vec();
        q.push(0);
        let sig_len = (q.len() - QUOTE_SIGNED_LEN - 4) as u32;
        q[QUOTE_SIGNED_LEN..QUOTE_SIGNED_LEN + 4].copy_from_slice(&sig_len.to_le_bytes());
        assert!(matches!(
            Quote::parse(&q),
            Err(ParseError::TrailingBytes {
                what: "quote signature data",
                extra: 1
            })
        ));
        // An inflated certification data length fails.
        let mut q = QUOTE_V3.to_vec();
        let cert_len_off = QUOTE_V3.len() - 3682 - 4;
        q[cert_len_off..cert_len_off + 4].copy_from_slice(&3683u32.to_le_bytes());
        assert!(matches!(
            Quote::parse(&q),
            Err(ParseError::Truncated { .. })
        ));
    }
}
