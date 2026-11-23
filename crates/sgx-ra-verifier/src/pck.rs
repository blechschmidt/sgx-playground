//! The Intel SGX extension of PCK certificates
//! (OID `1.2.840.113741.1.13.1`, "SGX PCK Certificate and Certificate
//! Revocation List Profile Specification").
//!
//! It names the platform (FMSPC, PCE-ID) and its TCB (16 CPU SVN
//! components and the PCE SVN). The TCB Info lookup and evaluation depend
//! on these values, so the parser is strict: every required field exactly
//! once, exact sizes, DER integers in range.

use sgx_ra_core::hex::Hex;

use crate::error::{VerifyError, cert_err};
use crate::pki::Cert;

/// DER content of OID 1.2.840.113741.1.13.1.
const SGX_EXT_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01];

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_ENUMERATED: u8 = 0x0a;
const TAG_SEQUENCE: u8 = 0x30;

const WHAT: &str = "PCK certificate SGX extension";

/// The PCK certificate's TCB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PckTcb {
    /// SGX TCB components 1–16 (the CPU SVN, component by component).
    pub comp_svn: [u8; 16],
    /// PCE SVN.
    pub pce_svn: u16,
    /// The raw CPU SVN.
    pub cpu_svn: [u8; 16],
}

/// The fields of the SGX extension the verifier uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PckExtensions {
    /// Platform provisioning id (encrypted PPID is not part of the cert).
    pub ppid: [u8; 16],
    /// Family-Model-Stepping-Platform-CustomSKU: selects the TCB Info.
    pub fmspc: [u8; 6],
    /// PCE identifier.
    pub pce_id: [u8; 2],
    /// The platform TCB this PCK key was certified for.
    pub tcb: PckTcb,
    /// SGX type (0 = Standard, 1 = Scalable, 2 = Scalable with integrity).
    pub sgx_type: u8,
}

impl PckExtensions {
    /// Extracts and parses the SGX extension of a PCK certificate.
    pub(crate) fn from_cert(cert: &Cert<'_>) -> Result<Self, VerifyError> {
        let mut found = None;
        for ext in cert.x509.extensions() {
            if ext.oid.as_bytes() == SGX_EXT_OID {
                if found.is_some() {
                    return Err(cert_err(WHAT, "duplicate SGX extension"));
                }
                found = Some(ext.value);
            }
        }
        Self::parse(found.ok_or_else(|| cert_err(WHAT, "missing"))?)
    }

    /// Parses the DER value of the extension (`SEQUENCE OF SEQUENCE { OID,
    /// ANY }`).
    pub fn parse(der: &[u8]) -> Result<Self, VerifyError> {
        let (body, rest) = read(der, TAG_SEQUENCE)?;
        if !rest.is_empty() {
            return Err(cert_err(WHAT, "trailing bytes"));
        }
        let mut ppid = None;
        let mut tcb = None;
        let mut pce_id = None;
        let mut fmspc = None;
        let mut sgx_type = None;

        for (oid, value) in entries(body)? {
            let Some(sub) = oid.strip_prefix(SGX_EXT_OID) else {
                return Err(cert_err(WHAT, format!("foreign OID {}", Hex(oid))));
            };
            match sub {
                [1] => set_once(&mut ppid, octets::<16>(value)?)?,
                [2] => set_once(&mut tcb, parse_tcb(value)?)?,
                [3] => set_once(&mut pce_id, octets::<2>(value)?)?,
                [4] => set_once(&mut fmspc, octets::<6>(value)?)?,
                [5] => {
                    let (v, rest) = read(value, TAG_ENUMERATED)?;
                    if !rest.is_empty() {
                        return Err(cert_err(WHAT, "trailing bytes after SGX type"));
                    }
                    let t = u8::try_from(uint(v)?)
                        .map_err(|_| cert_err(WHAT, "SGX type out of range"))?;
                    set_once(&mut sgx_type, t)?;
                }
                // platformInstanceID and configuration (multi-package
                // platforms) are not used by the verification.
                [6] | [7] => {}
                _ => return Err(cert_err(WHAT, format!("unknown field {}", Hex(sub)))),
            }
        }

        let missing = |f: &str| cert_err(WHAT, format!("missing {f}"));
        Ok(Self {
            ppid: ppid.ok_or_else(|| missing("PPID"))?,
            fmspc: fmspc.ok_or_else(|| missing("FMSPC"))?,
            pce_id: pce_id.ok_or_else(|| missing("PCE-ID"))?,
            tcb: tcb.ok_or_else(|| missing("TCB"))?,
            sgx_type: sgx_type.ok_or_else(|| missing("SGX type"))?,
        })
    }
}

fn parse_tcb(value: &[u8]) -> Result<PckTcb, VerifyError> {
    let (body, rest) = read(value, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(cert_err(WHAT, "trailing bytes after TCB"));
    }
    let mut comps: [Option<u8>; 16] = [None; 16];
    let mut pce_svn = None;
    let mut cpu_svn = None;
    for (oid, value) in entries(body)? {
        let sub = oid
            .strip_prefix(SGX_EXT_OID)
            .and_then(|s| s.strip_prefix(&[2]))
            .ok_or_else(|| cert_err(WHAT, format!("foreign TCB OID {}", Hex(oid))))?;
        match *sub {
            [n @ 1..=16] => {
                let svn = u8::try_from(integer(value)?)
                    .map_err(|_| cert_err(WHAT, "TCB component SVN out of range"))?;
                set_once(&mut comps[usize::from(n - 1)], svn)?;
            }
            [17] => {
                let svn = u16::try_from(integer(value)?)
                    .map_err(|_| cert_err(WHAT, "PCE SVN out of range"))?;
                set_once(&mut pce_svn, svn)?;
            }
            [18] => set_once(&mut cpu_svn, octets::<16>(value)?)?,
            _ => return Err(cert_err(WHAT, format!("unknown TCB field {}", Hex(sub)))),
        }
    }
    let mut comp_svn = [0u8; 16];
    for (dst, src) in comp_svn.iter_mut().zip(comps) {
        *dst = src.ok_or_else(|| cert_err(WHAT, "missing TCB component"))?;
    }
    Ok(PckTcb {
        comp_svn,
        pce_svn: pce_svn.ok_or_else(|| cert_err(WHAT, "missing PCE SVN"))?,
        cpu_svn: cpu_svn.ok_or_else(|| cert_err(WHAT, "missing CPU SVN"))?,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), VerifyError> {
    if slot.is_some() {
        return Err(cert_err(WHAT, "duplicate field"));
    }
    *slot = Some(value);
    Ok(())
}

/// Iterates the `SEQUENCE { OID, value }` entries of a sequence body.
/// `(OID content, value TLV)` pairs.
type Entries<'a> = Vec<(&'a [u8], &'a [u8])>;

fn entries(mut body: &[u8]) -> Result<Entries<'_>, VerifyError> {
    let mut out = Vec::new();
    while !body.is_empty() {
        let (entry, rest) = read(body, TAG_SEQUENCE)?;
        body = rest;
        let (oid, value) = read(entry, TAG_OID)?;
        out.push((oid, value));
    }
    Ok(out)
}

fn octets<const N: usize>(value: &[u8]) -> Result<[u8; N], VerifyError> {
    let (v, rest) = read(value, TAG_OCTET_STRING)?;
    if !rest.is_empty() {
        return Err(cert_err(WHAT, "trailing bytes after OCTET STRING"));
    }
    v.try_into()
        .map_err(|_| cert_err(WHAT, format!("expected {N} bytes, got {}", v.len())))
}

fn integer(value: &[u8]) -> Result<u32, VerifyError> {
    let (v, rest) = read(value, TAG_INTEGER)?;
    if !rest.is_empty() {
        return Err(cert_err(WHAT, "trailing bytes after INTEGER"));
    }
    uint(v)
}

/// A non-negative, minimally encoded DER integer of at most 4 value bytes.
fn uint(v: &[u8]) -> Result<u32, VerifyError> {
    let bad = || cert_err(WHAT, "invalid INTEGER");
    match v {
        [] => Err(bad()),
        [b, ..] if b & 0x80 != 0 => Err(bad()),
        [0, b, ..] if b & 0x80 == 0 => Err(bad()),
        _ => {
            let v = v.strip_prefix(&[0]).unwrap_or(v);
            if v.len() > 4 {
                return Err(bad());
            }
            Ok(v.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
        }
    }
}

/// Reads one TLV with the expected single-byte `tag`; returns the value and
/// the remaining input.
fn read(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), VerifyError> {
    let bad = |m: &str| cert_err(WHAT, m.to_owned());
    let (&t, rest) = input.split_first().ok_or_else(|| bad("truncated"))?;
    if t != tag {
        return Err(cert_err(
            WHAT,
            format!("expected tag {tag:#04x}, got {t:#04x}"),
        ));
    }
    let (&l0, mut rest) = rest.split_first().ok_or_else(|| bad("truncated"))?;
    let len = if l0 < 0x80 {
        usize::from(l0)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 3 || rest.len() < n {
            return Err(bad("invalid length"));
        }
        let (bytes, r) = rest.split_at(n);
        rest = r;
        let len = bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        if bytes[0] == 0 || len < 0x80 {
            return Err(bad("non-minimal length"));
        }
        len
    };
    if rest.len() < len {
        return Err(bad("truncated"));
    }
    Ok(rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::pem_certificates;
    use sgx_ra_core::sgx::Quote;

    const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");

    pub(crate) fn fixture_extension() -> Vec<u8> {
        let quote = Quote::parse(QUOTE_V3).unwrap();
        let chain = pem_certificates(quote.signature().certification.data, "t").unwrap();
        let leaf = Cert::parse(&chain[0], "t").unwrap();
        leaf.x509
            .extensions()
            .iter()
            .find(|e| e.oid.as_bytes() == SGX_EXT_OID)
            .unwrap()
            .value
            .to_vec()
    }

    #[test]
    fn parses_fixture_pck() {
        let ext = PckExtensions::parse(&fixture_extension()).unwrap();
        assert_eq!(Hex(&ext.fmspc).to_string(), "30606a000000");
        assert_eq!(ext.pce_id, [0, 0]);
        assert_eq!(
            ext.tcb.comp_svn,
            [7, 9, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(ext.tcb.pce_svn, 13);
        assert_eq!(
            Hex(&ext.tcb.cpu_svn).to_string(),
            "07090303ffff01000000000000000000"
        );
        assert_eq!(
            Hex(&ext.ppid).to_string(),
            "e6851d73b9e49350db917577b38d9b9d"
        );
        assert_eq!(ext.sgx_type, 1); // Scalable (Xeon SP)
    }

    #[test]
    fn rejects_malformed_extensions() {
        let good = fixture_extension();
        // Every truncation fails.
        for n in 0..good.len() {
            assert!(PckExtensions::parse(&good[..n]).is_err(), "prefix {n}");
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(PckExtensions::parse(&trailing).is_err());

        // FMSPC with 7 bytes: change the OCTET STRING length 06 → 07 is a
        // structural error; locate it via its OID suffix.
        let fmspc_oid = [SGX_EXT_OID, &[4]].concat();
        let pos = good
            .windows(fmspc_oid.len())
            .position(|w| w == fmspc_oid.as_slice())
            .unwrap();
        let mut bad = good.clone();
        bad[pos + fmspc_oid.len() + 1] = 5; // OCTET STRING length 6 → 5
        assert!(PckExtensions::parse(&bad).is_err());
    }

    #[test]
    fn der_integers() {
        assert_eq!(uint(&[0]).unwrap(), 0);
        assert_eq!(uint(&[0x7f]).unwrap(), 127);
        assert_eq!(uint(&[0, 0xff]).unwrap(), 255);
        assert!(uint(&[]).is_err());
        assert!(uint(&[0xff]).is_err()); // negative
        assert!(uint(&[0, 0x7f]).is_err()); // non-minimal
        assert!(uint(&[1, 2, 3, 4, 5]).is_err());
    }
}
