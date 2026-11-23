//! Client error type.

use std::fmt;
use std::io;
use std::path::PathBuf;

use sgx_ra_core::hex::HexError;
use sgx_ra_core::sgx::ParseError;

/// Client-side failures.
#[derive(Debug)]
pub enum ClientError {
    /// Reading a local file failed.
    ReadFile {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// A local SGX artefact (gendata, SIGSTRUCT) is malformed.
    Parse(ParseError),
    /// A hex-encoded measurement is malformed.
    Hex(HexError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFile { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Self::Parse(e) => write!(f, "malformed SGX structure: {e}"),
            Self::Hex(e) => write!(f, "malformed measurement: {e}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } => Some(source),
            Self::Parse(e) => Some(e),
            Self::Hex(e) => Some(e),
        }
    }
}

impl From<ParseError> for ClientError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<HexError> for ClientError {
    fn from(e: HexError) -> Self {
        Self::Hex(e)
    }
}
