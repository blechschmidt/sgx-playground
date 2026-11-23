//! Sources of the expected enclave measurement.
//!
//! The expected MRENCLAVE is the client's trust anchor for *which code* runs
//! in the remote enclave. It must come from somewhere the client trusts:
//! ideally its own reproducible build of the enclave source.

use std::fs;
use std::path::{Path, PathBuf};

use sgx_ra_core::Measurement;
use sgx_ra_core::sgx::Gendata;

use crate::error::ClientError;

/// Provides the MRENCLAVE the client expects the remote enclave to have.
pub trait MeasurementSource {
    /// Returns the expected MRENCLAVE.
    fn mr_enclave(&self) -> Result<Measurement, ClientError>;
}

/// Reads the MRENCLAVE from an `enclave.so.gendata` file produced by
/// `sgx_sign gendata` (e.g. the output of the reproducible build).
#[derive(Debug, Clone)]
pub struct GendataFile {
    path: PathBuf,
}

impl GendataFile {
    /// Uses the gendata file at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads and parses the whole gendata file.
    pub fn read(&self) -> Result<Gendata, ClientError> {
        let bytes = fs::read(&self.path).map_err(|source| ClientError::ReadFile {
            path: self.path.clone(),
            source,
        })?;
        Ok(Gendata::parse(&bytes)?)
    }
}

impl MeasurementSource for GendataFile {
    fn mr_enclave(&self) -> Result<Measurement, ClientError> {
        Ok(self.read()?.mr_enclave())
    }
}

/// A fixed, externally supplied MRENCLAVE (e.g. from a release manifest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedMeasurement(pub Measurement);

impl FixedMeasurement {
    /// Parses 64 hex digits.
    pub fn from_hex(hex: &str) -> Result<Self, ClientError> {
        Ok(Self(Measurement::from_hex(hex)?))
    }
}

impl MeasurementSource for FixedMeasurement {
    fn mr_enclave(&self) -> Result<Measurement, ClientError> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name)
    }

    const BLUEPRINT_MRENCLAVE: &str =
        "ed92b9ba8521bec3c3b2eacdf67846d275dd655965280028e05bf1a5f318434c";

    #[test]
    fn gendata_file_source() {
        let src = GendataFile::new(fixture("blueprint_enclave.so.gendata"));
        assert_eq!(
            src.mr_enclave().unwrap(),
            Measurement::from_hex(BLUEPRINT_MRENCLAVE).unwrap()
        );
    }

    #[test]
    fn gendata_file_errors() {
        let missing = GendataFile::new(fixture("does-not-exist"));
        assert!(matches!(
            missing.mr_enclave(),
            Err(ClientError::ReadFile { .. })
        ));
        // A quote is not a gendata file.
        let wrong = GendataFile::new(fixture("quote_v3.dat"));
        assert!(matches!(wrong.mr_enclave(), Err(ClientError::Parse(_))));
    }

    #[test]
    fn fixed_source() {
        let src = FixedMeasurement::from_hex(BLUEPRINT_MRENCLAVE).unwrap();
        assert_eq!(src.mr_enclave().unwrap().to_string(), BLUEPRINT_MRENCLAVE);
        assert!(matches!(
            FixedMeasurement::from_hex("xyz"),
            Err(ClientError::Hex(_))
        ));
    }
}
