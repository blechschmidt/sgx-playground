//! Byte-stream transports to the untrusted host.
//!
//! The transport (TCP, or TLS to the remote executor's stunnel) carries
//! layer-1 frames. It is **not** a trust anchor: confidentiality and
//! authenticity come from the attested channel running inside it. TLS
//! terminates outside the enclave (`docs/PROTOCOL.md` §1), so even a fully
//! verified TLS session only authenticates the operator's front end.
//! Verifying it by default still keeps casual network attackers out of
//! the metadata; [`TlsVerification::Insecure`] exists because the remote
//! executor's certificate has been observed expired (§5).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, StreamOwned};

/// Read timeout while waiting for the quote announcement. The remote host
/// may spend about 60 s in DCAP collateral retrieval before it answers
/// (`docs/PROTOCOL.md` §2.4 Q7).
pub const QUOTE_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Read timeout for each response after the quote.
pub const RESPONSE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout of the TCP connect and of writes.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A bidirectional byte stream with configurable read timeout.
pub trait Transport: Read + Write {
    /// Sets the read timeout; `None` blocks indefinitely.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Transport for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(timeout)
    }
}

/// A TLS client stream over TCP.
pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

impl Transport for TlsStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }
}

/// How the outer TLS server certificate is checked.
#[derive(Clone, PartialEq, Eq)]
pub enum TlsVerification {
    /// Mozilla's root store (`webpki-roots`) and the host name.
    WebPki,
    /// Only these PEM CA certificates, and the host name.
    CustomCa(Vec<u8>),
    /// Accept any certificate (handshake signatures are still checked).
    /// Acceptable only because TLS is not part of the trust chain.
    Insecure,
}

impl fmt::Debug for TlsVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WebPki => "WebPki",
            Self::CustomCa(_) => "CustomCa",
            Self::Insecure => "Insecure",
        })
    }
}

/// Transport-level failures (connect, TLS setup).
#[derive(Debug)]
pub enum TransportError {
    /// Name resolution or TCP connect failed.
    Connect {
        /// `host:port`.
        addr: String,
        /// The underlying error.
        source: io::Error,
    },
    /// The host name is not a valid TLS server name.
    ServerName(String),
    /// The TLS configuration is invalid (e.g. a bad CA PEM).
    Config(String),
    /// The TLS handshake failed.
    Handshake(io::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect { addr, source } => write!(f, "cannot connect to {addr}: {source}"),
            Self::ServerName(name) => write!(f, "{name:?} is not a valid TLS server name"),
            Self::Config(e) => write!(f, "invalid TLS configuration: {e}"),
            Self::Handshake(e) => write!(f, "TLS handshake failed: {e}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect { source, .. } => Some(source),
            Self::Handshake(e) => Some(e),
            _ => None,
        }
    }
}

/// Opens a TCP connection to `host:port` (trying every resolved address).
pub fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, TransportError> {
    let addr = format!("{host}:{port}");
    let err = |source| TransportError::Connect {
        addr: addr.clone(),
        source,
    };
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no addresses resolved");
    for sa in (host, port).to_socket_addrs().map_err(err)? {
        match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_write_timeout(Some(CONNECT_TIMEOUT))
                    .map_err(err)?;
                stream.set_nodelay(true).map_err(err)?;
                return Ok(stream);
            }
            Err(e) => last = e,
        }
    }
    Err(err(last))
}

/// Builds the rustls client configuration for `verification`.
pub fn tls_config(verification: &TlsVerification) -> Result<ClientConfig, TransportError> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Config(e.to_string()))?;
    let config = match verification {
        TlsVerification::WebPki => {
            let roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        TlsVerification::CustomCa(pem) => {
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(pem) {
                let cert =
                    cert.map_err(|e| TransportError::Config(format!("invalid CA PEM: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| TransportError::Config(format!("unusable CA certificate: {e}")))?;
            }
            if roots.is_empty() {
                return Err(TransportError::Config(
                    "CA PEM contains no certificates".into(),
                ));
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        TlsVerification::Insecure => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(
                provider.signature_verification_algorithms,
            )))
            .with_no_client_auth(),
    };
    Ok(config)
}

/// Connects to `host:port` and completes a TLS handshake with SNI `host`.
pub fn connect_tls(
    host: &str,
    port: u16,
    verification: &TlsVerification,
) -> Result<TlsStream, TransportError> {
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| TransportError::ServerName(host.to_owned()))?;
    let config = Arc::new(tls_config(verification)?);
    let mut tcp = connect_tcp(host, port)?;
    tcp.set_read_timeout(Some(CONNECT_TIMEOUT))
        .map_err(TransportError::Handshake)?;
    let mut conn = ClientConnection::new(config, server_name)
        .map_err(|e| TransportError::Config(e.to_string()))?;
    // Drive the handshake now so certificate errors surface here and not
    // as a confusing read error while waiting for the quote.
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)
            .map_err(TransportError::Handshake)?;
    }
    Ok(StreamOwned::new(conn, tcp))
}

/// Describes the negotiated TLS session (for logging).
pub fn describe_tls(stream: &TlsStream) -> String {
    let version = stream
        .conn
        .protocol_version()
        .map_or_else(|| "?".to_owned(), |v| format!("{v:?}"));
    let suite = stream
        .conn
        .negotiated_cipher_suite()
        .map_or_else(|| "?".to_owned(), |s| format!("{:?}", s.suite()));
    format!("{version}, {suite}")
}

/// Accepts any server certificate but still verifies that the server owns
/// the key in it (handshake signatures).
#[derive(Debug)]
struct AcceptAnyCertificate(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_configs_build() {
        assert!(tls_config(&TlsVerification::WebPki).is_ok());
        assert!(tls_config(&TlsVerification::Insecure).is_ok());
        let pem = include_bytes!("../../../fixtures/dcap/tcb_info_issuer_chain.pem").to_vec();
        assert!(tls_config(&TlsVerification::CustomCa(pem)).is_ok());
        assert!(matches!(
            tls_config(&TlsVerification::CustomCa(b"nothing".to_vec())),
            Err(TransportError::Config(_))
        ));
    }

    #[test]
    fn bad_server_name() {
        assert!(matches!(
            connect_tls("not a host", 443, &TlsVerification::WebPki),
            Err(TransportError::ServerName(_))
        ));
    }
}
