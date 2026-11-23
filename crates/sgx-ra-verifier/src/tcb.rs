//! Signed TCB Info (v3, SGX) and QE Identity (v2) documents, and TCB
//! level evaluation.
//!
//! Both documents have the shape `{"<body>": {...}, "signature": "<hex>"}`
//! where the signature is ECDSA P-256 / SHA-256 (`r ‖ s`) over the exact
//! bytes of the body as served. The body is therefore taken verbatim from
//! the input and the signature is checked before any field is interpreted.

use p256::ecdsa::VerifyingKey;
use serde::Deserialize;
use serde_json::value::RawValue;
use sgx_ra_core::TcbStatus;
use sgx_ra_core::hex::{self, Hex};
use sgx_ra_core::sgx::{Measurement, ReportBody};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::{VerifyError, collateral_err};
use crate::pki::{self, Cert, RevokedSerials, Role, TrustAnchor};

/// Common name of the certificate that signs TCB Info and QE Identity.
pub const TCB_SIGNING_CN: &str = "Intel SGX TCB Signing";

/// Upper bound on the number of TCB levels accepted in a document.
const MAX_TCB_LEVELS: usize = 512;

/// One TCB level of the platform TCB Info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbLevel {
    /// Minimum SGX TCB component SVNs.
    pub comp_svn: [u8; 16],
    /// Minimum PCE SVN.
    pub pce_svn: u16,
    /// Date of the TCB recovery this level corresponds to (RFC 3339).
    pub tcb_date: String,
    /// Status of platforms at this level.
    pub status: TcbStatus,
    /// Applicable Intel security advisories.
    pub advisory_ids: Vec<String>,
}

/// A verified TCB Info document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbInfo {
    /// FMSPC the document applies to.
    pub fmspc: [u8; 6],
    /// PCE id the document applies to.
    pub pce_id: [u8; 2],
    /// Issue date (Unix seconds).
    pub issue_date: i64,
    /// Next update (Unix seconds): the document is stale afterwards.
    pub next_update: i64,
    /// Intel's TCB evaluation data number (monotonic per TCB recovery).
    pub tcb_evaluation_data_number: u32,
    /// TCB levels, in document order (highest first).
    pub levels: Vec<TcbLevel>,
    /// Intel's labels for the 16 SGX TCB components (`category` and
    /// `type`, e.g. "BIOS, Early Microcode Update"), taken from the highest
    /// level; empty where Intel gives none.
    pub component_labels: [String; 16],
}

/// What the platform's TCB lacks compared to the best level of a TCB Info
/// document; see [`TcbInfo::gap_to_best`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbGap {
    /// The highest level Intel defines for this FMSPC: the best status any
    /// platform of this kind can reach. It need not be `UpToDate`.
    pub best: TcbLevel,
    /// The SVNs below that level's minimum, in component order.
    pub shortfalls: Vec<TcbShortfall>,
}

/// One TCB component (or the PCE SVN) below the value a TCB level requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbShortfall {
    /// SGX TCB component index (0–15), or `None` for the PCE SVN.
    pub component: Option<usize>,
    /// Intel's label for the component; empty if Intel gives none.
    pub label: String,
    /// The platform's SVN.
    pub have: u16,
    /// The SVN the level requires.
    pub need: u16,
}

impl TcbShortfall {
    /// Who can raise this SVN. It is always the platform owner (BIOS and
    /// microcode, or the host OS / VMM for late microcode), never the
    /// enclave, its host app or a guest VM. Components without an Intel
    /// label are platform configuration reflected in CPUSVN (for example
    /// x2APIC locking or disabled SGX error injection on 3rd-gen Xeon SP),
    /// which only the BIOS setup changes.
    pub fn remedy(&self) -> &'static str {
        if self.component.is_none() {
            return "update the platform software (PCE)";
        }
        let label = self.label.as_str();
        if label.starts_with("BIOS") {
            "update the BIOS / microcode of the physical host"
        } else if label.starts_with("OS/VMM") {
            "load newer microcode in the host OS / VMM, or update the BIOS"
        } else {
            "update or reconfigure the BIOS of the physical host"
        }
    }
}

impl std::fmt::Display for TcbShortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.component {
            Some(i) => write!(f, "component {i}")?,
            None => f.write_str("PCE SVN")?,
        }
        if !self.label.is_empty() {
            write!(f, " ({})", self.label)?;
        }
        write!(f, " is {} < {}", self.have, self.need)
    }
}

/// One TCB level of the QE Identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QeTcbLevel {
    /// Minimum QE ISVSVN.
    pub isv_svn: u16,
    /// Date of the TCB recovery (RFC 3339).
    pub tcb_date: String,
    /// Status of QEs at this level.
    pub status: TcbStatus,
    /// Applicable Intel security advisories.
    pub advisory_ids: Vec<String>,
}

/// A verified QE Identity document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QeIdentity {
    /// Issue date (Unix seconds).
    pub issue_date: i64,
    /// Next update (Unix seconds).
    pub next_update: i64,
    /// Intel's TCB evaluation data number.
    pub tcb_evaluation_data_number: u32,
    /// Expected `MISCSELECT` (after masking).
    pub misc_select: u32,
    /// Mask applied to `MISCSELECT`.
    pub misc_select_mask: u32,
    /// Expected attributes (after masking).
    pub attributes: [u8; 16],
    /// Mask applied to the attributes.
    pub attributes_mask: [u8; 16],
    /// Expected QE MRSIGNER.
    pub mr_signer: Measurement,
    /// Expected QE ISVPRODID.
    pub isv_prod_id: u16,
    /// QE TCB levels, highest first.
    pub levels: Vec<QeTcbLevel>,
}

// --- JSON shapes -----------------------------------------------------------

#[derive(Deserialize)]
struct TcbInfoEnvelope<'a> {
    #[serde(borrow, rename = "tcbInfo")]
    body: &'a RawValue,
    signature: &'a str,
}

#[derive(Deserialize)]
struct QeIdentityEnvelope<'a> {
    #[serde(borrow, rename = "enclaveIdentity")]
    body: &'a RawValue,
    signature: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoJson {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    fmspc: String,
    pce_id: String,
    tcb_type: u32,
    tcb_evaluation_data_number: u32,
    tcb_levels: Vec<TcbLevelJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevelJson {
    tcb: TcbJson,
    tcb_date: String,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

#[derive(Deserialize)]
struct TcbJson {
    sgxtcbcomponents: Vec<TcbComponentJson>,
    pcesvn: u16,
}

#[derive(Deserialize)]
struct TcbComponentJson {
    svn: u8,
    #[serde(default)]
    category: String,
    #[serde(default, rename = "type")]
    kind: String,
}

impl TcbComponentJson {
    fn label(&self) -> String {
        match (self.category.is_empty(), self.kind.is_empty()) {
            (false, false) => format!("{}, {}", self.category, self.kind),
            (false, true) => self.category.clone(),
            (true, false) => self.kind.clone(),
            (true, true) => String::new(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentityJson {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    tcb_evaluation_data_number: u32,
    miscselect: String,
    miscselect_mask: String,
    attributes: String,
    attributes_mask: String,
    mrsigner: String,
    isvprodid: u16,
    tcb_levels: Vec<QeTcbLevelJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeTcbLevelJson {
    tcb: QeTcbJson,
    tcb_date: String,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

#[derive(Deserialize)]
struct QeTcbJson {
    isvsvn: u16,
}

// --- Signer chain ----------------------------------------------------------

/// Verifies a `[TCB signing cert, Intel root]` issuer chain and returns the
/// signing key.
pub(crate) fn verify_tcb_signer(
    chain_pem: &[u8],
    anchor: &TrustAnchor,
    root: &Cert<'_>,
    root_crl: &RevokedSerials,
    now: i64,
    what: &'static str,
) -> Result<VerifyingKey, VerifyError> {
    let ders = pki::pem_certificates(chain_pem, what)?;
    let [signer_der, root_der] = ders.as_slice() else {
        return Err(pki_err(
            what,
            format!("expected 2 certificates, got {}", ders.len()),
        ));
    };
    anchor.require_pinned(root_der, what)?;
    let signer = Cert::parse(signer_der, what)?;
    if signer.common_name() != Some(TCB_SIGNING_CN) {
        return Err(pki_err(
            what,
            "signer is not the Intel SGX TCB Signing certificate",
        ));
    }
    signer.check_issued_by(root, what)?;
    signer.check_validity(now, what)?;
    signer.check_role(Role::EndEntity, what)?;
    root_crl.check(&signer, what)?;
    signer.p256_key(what)
}

fn pki_err(what: &'static str, reason: impl Into<String>) -> VerifyError {
    VerifyError::Certificate {
        what,
        reason: reason.into(),
    }
}

// --- Parsing ---------------------------------------------------------------

fn signature_bytes(hex_sig: &str, what: &'static str) -> Result<[u8; 64], VerifyError> {
    let mut sig = [0u8; 64];
    hex::decode_into(hex_sig, &mut sig).map_err(|_| VerifyError::BadSignature { what })?;
    Ok(sig)
}

fn timestamp(s: &str, what: &'static str) -> Result<i64, VerifyError> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|_| collateral_err(what, format!("invalid date {s:?}")))
}

fn hex_field<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N], VerifyError> {
    let mut out = [0u8; N];
    hex::decode_into(s, &mut out)
        .map_err(|_| collateral_err(what, format!("invalid hex field {s:?}")))?;
    Ok(out)
}

fn status(s: &str, what: &'static str) -> Result<TcbStatus, VerifyError> {
    TcbStatus::from_name(s).ok_or_else(|| collateral_err(what, format!("unknown TCB status {s:?}")))
}

impl TcbInfo {
    /// Verifies the signature of a TCB Info document under `signer` and
    /// parses it. Only SGX TCB Info version 3 (`tcbType` 0) is accepted.
    pub(crate) fn verify_and_parse(
        json: &[u8],
        signer: &VerifyingKey,
    ) -> Result<Self, VerifyError> {
        const WHAT: &str = "TCB Info";
        let env: TcbInfoEnvelope<'_> = serde_json::from_slice(json)
            .map_err(|e| collateral_err(WHAT, format!("malformed JSON: {e}")))?;
        let sig = signature_bytes(env.signature, WHAT)?;
        pki::verify_raw_signature(signer, env.body.get().as_bytes(), &sig, WHAT)?;

        let body: TcbInfoJson = serde_json::from_str(env.body.get())
            .map_err(|e| collateral_err(WHAT, format!("malformed body: {e}")))?;
        if body.id != "SGX" || body.version != 3 || body.tcb_type != 0 {
            return Err(collateral_err(
                WHAT,
                format!(
                    "unsupported document (id {:?}, version {}, tcbType {})",
                    body.id, body.version, body.tcb_type
                ),
            ));
        }
        if body.tcb_levels.is_empty() || body.tcb_levels.len() > MAX_TCB_LEVELS {
            return Err(collateral_err(WHAT, "invalid number of TCB levels"));
        }
        let component_labels: [String; 16] = core::array::from_fn(|i| {
            body.tcb_levels[0]
                .tcb
                .sgxtcbcomponents
                .get(i)
                .map(TcbComponentJson::label)
                .unwrap_or_default()
        });
        let levels = body
            .tcb_levels
            .into_iter()
            .map(|l| {
                let comps: [TcbComponentJson; 16] =
                    l.tcb.sgxtcbcomponents.try_into().map_err(|_| {
                        collateral_err(WHAT, "TCB level does not have 16 components")
                    })?;
                Ok(TcbLevel {
                    comp_svn: comps.map(|c| c.svn),
                    pce_svn: l.tcb.pcesvn,
                    status: status(&l.tcb_status, WHAT)?,
                    tcb_date: l.tcb_date,
                    advisory_ids: l.advisory_ids,
                })
            })
            .collect::<Result<_, VerifyError>>()?;
        Ok(Self {
            fmspc: hex_field(&body.fmspc, WHAT)?,
            pce_id: hex_field(&body.pce_id, WHAT)?,
            issue_date: timestamp(&body.issue_date, WHAT)?,
            next_update: timestamp(&body.next_update, WHAT)?,
            tcb_evaluation_data_number: body.tcb_evaluation_data_number,
            levels,
            component_labels,
        })
    }

    /// The first (highest) level the platform's TCB satisfies: every SVN
    /// component and the PCE SVN at least the level's value.
    pub fn level_for(&self, comp_svn: &[u8; 16], pce_svn: u16) -> Option<&TcbLevel> {
        self.levels.iter().find(|l| {
            pce_svn >= l.pce_svn
                && comp_svn
                    .iter()
                    .zip(&l.comp_svn)
                    .all(|(have, min)| have >= min)
        })
    }

    /// Compares the platform's TCB with the highest level of the document
    /// and lists every SVN below it. This explains a status worse than the
    /// best one: which components the platform owner has to raise. Returns
    /// `None` if the platform already satisfies the highest level.
    pub fn gap_to_best(&self, comp_svn: &[u8; 16], pce_svn: u16) -> Option<TcbGap> {
        let best = self.levels.first()?;
        let mut shortfalls: Vec<TcbShortfall> = comp_svn
            .iter()
            .zip(&best.comp_svn)
            .enumerate()
            .filter(|(_, (have, need))| have < need)
            .map(|(i, (&have, &need))| TcbShortfall {
                component: Some(i),
                label: self.component_labels[i].clone(),
                have: have.into(),
                need: need.into(),
            })
            .collect();
        if pce_svn < best.pce_svn {
            shortfalls.push(TcbShortfall {
                component: None,
                label: String::new(),
                have: pce_svn,
                need: best.pce_svn,
            });
        }
        (!shortfalls.is_empty()).then(|| TcbGap {
            best: best.clone(),
            shortfalls,
        })
    }
}

impl QeIdentity {
    /// Verifies the signature of a QE Identity document under `signer` and
    /// parses it. Only version 2 documents for the ECDSA QE (`id` "QE") are
    /// accepted.
    pub(crate) fn verify_and_parse(
        json: &[u8],
        signer: &VerifyingKey,
    ) -> Result<Self, VerifyError> {
        const WHAT: &str = "QE Identity";
        let env: QeIdentityEnvelope<'_> = serde_json::from_slice(json)
            .map_err(|e| collateral_err(WHAT, format!("malformed JSON: {e}")))?;
        let sig = signature_bytes(env.signature, WHAT)?;
        pki::verify_raw_signature(signer, env.body.get().as_bytes(), &sig, WHAT)?;

        let body: QeIdentityJson = serde_json::from_str(env.body.get())
            .map_err(|e| collateral_err(WHAT, format!("malformed body: {e}")))?;
        if body.id != "QE" || body.version != 2 {
            return Err(collateral_err(
                WHAT,
                format!(
                    "unsupported document (id {:?}, version {})",
                    body.id, body.version
                ),
            ));
        }
        if body.tcb_levels.is_empty() || body.tcb_levels.len() > MAX_TCB_LEVELS {
            return Err(collateral_err(WHAT, "invalid number of TCB levels"));
        }
        let levels = body
            .tcb_levels
            .into_iter()
            .map(|l| {
                Ok(QeTcbLevel {
                    isv_svn: l.tcb.isvsvn,
                    status: status(&l.tcb_status, WHAT)?,
                    tcb_date: l.tcb_date,
                    advisory_ids: l.advisory_ids,
                })
            })
            .collect::<Result<_, VerifyError>>()?;
        // MISCSELECT is a little-endian u32 in the report but written as
        // big-endian hex in the document.
        Ok(Self {
            issue_date: timestamp(&body.issue_date, WHAT)?,
            next_update: timestamp(&body.next_update, WHAT)?,
            tcb_evaluation_data_number: body.tcb_evaluation_data_number,
            misc_select: u32::from_be_bytes(hex_field(&body.miscselect, WHAT)?),
            misc_select_mask: u32::from_be_bytes(hex_field(&body.miscselect_mask, WHAT)?),
            attributes: hex_field(&body.attributes, WHAT)?,
            attributes_mask: hex_field(&body.attributes_mask, WHAT)?,
            mr_signer: Measurement(hex_field(&body.mrsigner, WHAT)?),
            isv_prod_id: body.isvprodid,
            levels,
        })
    }

    /// Checks the QE report against the identity (MRSIGNER, ISVPRODID,
    /// masked MISCSELECT and attributes) and returns the QE's TCB level.
    pub(crate) fn match_report(&self, qe: &ReportBody) -> Result<&QeTcbLevel, VerifyError> {
        let mismatch = |field| VerifyError::QeIdentityMismatch { field };
        if qe.mr_signer() != self.mr_signer {
            return Err(mismatch("MRSIGNER"));
        }
        if qe.isv_prod_id() != self.isv_prod_id {
            return Err(mismatch("ISVPRODID"));
        }
        if qe.misc_select() & self.misc_select_mask != self.misc_select & self.misc_select_mask {
            return Err(mismatch("MISCSELECT"));
        }
        let attrs = qe.attributes().to_bytes();
        let masked_eq = attrs
            .iter()
            .zip(&self.attributes)
            .zip(&self.attributes_mask)
            .all(|((a, e), m)| a & m == e & m);
        if !masked_eq {
            return Err(mismatch("attributes"));
        }
        self.levels
            .iter()
            .find(|l| qe.isv_svn() >= l.isv_svn)
            .ok_or(VerifyError::TcbLevelNotFound {
                what: "quoting enclave",
            })
    }
}

/// Combines the platform TCB status with the QE's TCB status the way
/// Intel's QVL does: an out-of-date QE makes the whole TCB out of date, a
/// revoked one revokes it.
pub fn converge_tcb_status(platform: TcbStatus, qe: TcbStatus) -> TcbStatus {
    use TcbStatus::*;
    match (qe, platform) {
        (Revoked, _) | (_, Revoked) => Revoked,
        (OutOfDate | OutOfDateConfigurationNeeded, UpToDate | SwHardeningNeeded) => OutOfDate,
        (
            OutOfDate | OutOfDateConfigurationNeeded,
            ConfigurationNeeded | ConfigurationAndSwHardeningNeeded,
        ) => OutOfDateConfigurationNeeded,
        (_, p) => p,
    }
}

impl std::fmt::Display for TcbLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (components {}, PCE SVN {}, {})",
            self.status,
            Hex(&self.comp_svn),
            self.pce_svn,
            self.tcb_date
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TcbStatus::*;

    #[test]
    fn convergence() {
        assert_eq!(converge_tcb_status(UpToDate, UpToDate), UpToDate);
        assert_eq!(
            converge_tcb_status(SwHardeningNeeded, UpToDate),
            SwHardeningNeeded
        );
        assert_eq!(converge_tcb_status(UpToDate, OutOfDate), OutOfDate);
        assert_eq!(converge_tcb_status(SwHardeningNeeded, OutOfDate), OutOfDate);
        assert_eq!(
            converge_tcb_status(ConfigurationNeeded, OutOfDate),
            OutOfDateConfigurationNeeded
        );
        assert_eq!(
            converge_tcb_status(ConfigurationAndSwHardeningNeeded, OutOfDate),
            OutOfDateConfigurationNeeded
        );
        assert_eq!(converge_tcb_status(OutOfDate, UpToDate), OutOfDate);
        assert_eq!(converge_tcb_status(UpToDate, Revoked), Revoked);
        assert_eq!(converge_tcb_status(Revoked, UpToDate), Revoked);
    }
}
