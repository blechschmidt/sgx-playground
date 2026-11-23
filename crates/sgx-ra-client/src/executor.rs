//! Client side of the remote executor's layer-1 protocol
//! (`docs/PROTOCOL.md` §2): read the quote announcement once, then
//! exchange length-prefixed requests and status-prefixed responses in
//! strict lockstep.
//!
//! [`ExecutorConnection`] implements [`MessageTransport`], so it plugs
//! directly into [`sgx_ra_core::ClientChannel`]. Nothing here is trusted:
//! the framing only has to be robust against a hostile host (bounded
//! lengths, timeouts, no plaintext fallback).

use std::fmt;
use std::io;
use std::time::Duration;

use sgx_ra_core::session::MessageTransport;
use sgx_ra_core::wire::{self, Decoded, Response, Status, WireError};

use crate::transport::{QUOTE_READ_TIMEOUT, RESPONSE_READ_TIMEOUT, Transport};

/// Upper bound on the diagnostic text collected after a
/// [`WireError::RemoteDiagnostic`].
const MAX_DIAGNOSTIC: usize = 64 << 10;
/// How long to keep collecting diagnostic text once it started.
const DIAGNOSTIC_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Layer-1 failures. All are fatal for the connection.
#[derive(Debug)]
pub enum ExecutorError {
    /// Reading or writing the transport failed.
    Io(io::Error),
    /// No data arrived within the read timeout.
    Timeout {
        /// What the client was waiting for.
        waiting_for: &'static str,
        /// The timeout that expired.
        after: Duration,
    },
    /// The host closed the connection.
    Closed {
        /// What the client was waiting for.
        waiting_for: &'static str,
        /// Bytes of the incomplete frame received before EOF.
        partial: Vec<u8>,
    },
    /// A frame violated the framing rules.
    Wire(WireError),
    /// The host sent diagnostic text instead of a quote (quirk Q5): the
    /// remote attestation infrastructure is not working.
    RemoteDiagnostic(String),
    /// The host answered a request with a failure status, i.e. the enclave
    /// rejected the message or the ECALL failed.
    Status(Status),
    /// The API was used out of order (e.g. a request before the quote).
    Protocol(&'static str),
}

impl ExecutorError {
    /// Whether the failure means the remote side cannot attest at all
    /// (as opposed to a verification or protocol failure).
    pub fn is_infrastructure_unavailable(&self) -> bool {
        matches!(self, Self::RemoteDiagnostic(_))
    }
}

impl fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Timeout { waiting_for, after } => {
                write!(f, "timed out after {after:?} waiting for {waiting_for}")
            }
            Self::Closed {
                waiting_for,
                partial,
            } => {
                write!(f, "connection closed while waiting for {waiting_for}")?;
                if !partial.is_empty() {
                    write!(
                        f,
                        " ({} bytes of an incomplete frame received)",
                        partial.len()
                    )?;
                }
                Ok(())
            }
            Self::Wire(e) => write!(f, "framing error: {e}"),
            Self::RemoteDiagnostic(text) => write!(
                f,
                "remote attestation infrastructure unavailable; the host sent:\n{}",
                text.trim_end()
            ),
            Self::Status(s) => write!(
                f,
                "host answered with failure status {:#04x} ({s:?})",
                *s as u8
            ),
            Self::Protocol(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for ExecutorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Wire(e) => Some(e),
            _ => None,
        }
    }
}

impl From<WireError> for ExecutorError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

/// A connection to the remote executor (or the example host app).
#[derive(Debug)]
pub struct ExecutorConnection<T> {
    transport: T,
    quote_received: bool,
    failed: bool,
}

impl<T: Transport> ExecutorConnection<T> {
    /// Wraps a freshly opened transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            quote_received: false,
            failed: false,
        }
    }

    /// The underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Reads the quote announcement. Must be called exactly once, first.
    ///
    /// Waits up to [`QUOTE_READ_TIMEOUT`]. If the host writes text instead
    /// of a quote, the text (up to 64 KiB) is returned as
    /// [`ExecutorError::RemoteDiagnostic`].
    pub fn read_quote(&mut self) -> Result<Vec<u8>, ExecutorError> {
        if self.quote_received {
            return Err(ExecutorError::Protocol("the quote was already read"));
        }
        self.guard()?;
        let result = self.read_quote_inner();
        self.failed = result.is_err();
        self.quote_received = result.is_ok();
        result
    }

    fn read_quote_inner(&mut self) -> Result<Vec<u8>, ExecutorError> {
        const WHAT: &str = "the quote announcement";
        self.transport
            .set_read_timeout(Some(QUOTE_READ_TIMEOUT))
            .map_err(ExecutorError::Io)?;
        let mut buf = Vec::new();
        loop {
            match wire::decode_quote(&buf) {
                Ok(Decoded::Complete { value, .. }) => {
                    self.transport
                        .set_read_timeout(Some(RESPONSE_READ_TIMEOUT))
                        .map_err(ExecutorError::Io)?;
                    return Ok(value);
                }
                Ok(Decoded::Incomplete { needed }) => {
                    self.read_more(&mut buf, needed, WHAT, QUOTE_READ_TIMEOUT)?;
                }
                Err(WireError::RemoteDiagnostic { .. }) => {
                    return Err(ExecutorError::RemoteDiagnostic(
                        self.collect_diagnostic(buf),
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Reads what follows a diagnostic prefix until EOF, a pause or the
    /// size limit; never fails (the diagnostic is informational).
    fn collect_diagnostic(&mut self, mut text: Vec<u8>) -> String {
        let _ = self
            .transport
            .set_read_timeout(Some(DIAGNOSTIC_READ_TIMEOUT));
        let mut chunk = [0u8; 4096];
        while text.len() < MAX_DIAGNOSTIC {
            match self.transport.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => text.extend_from_slice(&chunk[..n]),
            }
        }
        text.truncate(MAX_DIAGNOSTIC);
        String::from_utf8_lossy(&text).into_owned()
    }

    fn read_more(
        &mut self,
        buf: &mut Vec<u8>,
        needed: usize,
        waiting_for: &'static str,
        timeout: Duration,
    ) -> Result<(), ExecutorError> {
        let start = buf.len();
        buf.resize(start + needed, 0);
        let mut filled = start;
        while filled < buf.len() {
            match self.transport.read(&mut buf[filled..]) {
                Ok(0) => {
                    buf.truncate(filled);
                    return Err(ExecutorError::Closed {
                        waiting_for,
                        partial: std::mem::take(buf),
                    });
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(ExecutorError::Timeout {
                        waiting_for,
                        after: timeout,
                    });
                }
                Err(e) => return Err(ExecutorError::Io(e)),
            }
        }
        Ok(())
    }

    fn guard(&self) -> Result<(), ExecutorError> {
        if self.failed {
            Err(ExecutorError::Protocol(
                "the connection already failed and cannot be reused",
            ))
        } else {
            Ok(())
        }
    }

    fn send_inner(&mut self, message: &[u8]) -> Result<(), ExecutorError> {
        if !self.quote_received {
            return Err(ExecutorError::Protocol(
                "requests are only allowed after the quote was read",
            ));
        }
        let mut frame = Vec::with_capacity(wire::LEN_PREFIX + message.len());
        wire::encode_request(message, &mut frame)?;
        self.transport
            .write_all(&frame)
            .and_then(|()| self.transport.flush())
            .map_err(ExecutorError::Io)?;
        log::trace!("sent request frame of {} bytes", frame.len());
        Ok(())
    }

    fn recv_inner(&mut self) -> Result<Vec<u8>, ExecutorError> {
        if !self.quote_received {
            return Err(ExecutorError::Protocol(
                "responses are only expected after the quote was read",
            ));
        }
        const WHAT: &str = "a response";
        let mut buf = Vec::new();
        loop {
            match wire::decode_response(&buf)? {
                Decoded::Complete {
                    value: Response::Ok(payload),
                    ..
                } => {
                    log::trace!("received response payload of {} bytes", payload.len());
                    return Ok(payload);
                }
                Decoded::Complete {
                    value: Response::Failure(status),
                    ..
                } => return Err(ExecutorError::Status(status)),
                Decoded::Incomplete { needed } => {
                    self.read_more(&mut buf, needed, WHAT, RESPONSE_READ_TIMEOUT)?;
                }
            }
        }
    }
}

impl<T: Transport> MessageTransport for ExecutorConnection<T> {
    type Error = ExecutorError;

    /// Sends one request frame. Empty and oversized payloads are refused
    /// locally (quirks Q2/Q3).
    fn send(&mut self, message: &[u8]) -> Result<(), ExecutorError> {
        self.guard()?;
        let result = self.send_inner(message);
        // A local refusal (nothing was written) leaves the stream usable.
        self.failed = matches!(result, Err(ExecutorError::Io(_)));
        result
    }

    /// Receives one response. Any failure status or framing error makes
    /// the connection unusable (the SGXRA session is gone anyway).
    fn recv(&mut self) -> Result<Vec<u8>, ExecutorError> {
        self.guard()?;
        let result = self.recv_inner();
        self.failed = result.is_err();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    /// A scripted transport: reads from `input`, records writes.
    struct Scripted {
        input: Cursor<Vec<u8>>,
        written: Vec<u8>,
        /// Return `WouldBlock` instead of EOF when the input is exhausted.
        stall: bool,
    }

    impl Scripted {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                written: Vec::new(),
                stall: false,
            }
        }
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // Deliver at most 3 bytes per read to exercise reassembly.
            let n = buf.len().min(3);
            let got = self.input.read(&mut buf[..n])?;
            if got == 0 && self.stall {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(got)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Transport for Scripted {
        fn set_read_timeout(&mut self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    fn quote_frame(quote: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        wire::encode_quote(quote, &mut out).unwrap();
        out
    }

    #[test]
    fn quote_then_lockstep() {
        let mut input = quote_frame(b"QUOTE-BYTES");
        wire::encode_response(&Response::Ok(b"pong".to_vec()), &mut input).unwrap();
        wire::encode_response(&Response::Ok(Vec::new()), &mut input).unwrap();
        let mut conn = ExecutorConnection::new(Scripted::new(input));

        assert!(matches!(conn.send(b"x"), Err(ExecutorError::Protocol(_))));
        assert_eq!(conn.read_quote().unwrap(), b"QUOTE-BYTES");
        assert!(matches!(conn.read_quote(), Err(ExecutorError::Protocol(_))));
        conn.send(b"ping").unwrap();
        assert_eq!(conn.recv().unwrap(), b"pong");
        assert_eq!(conn.recv().unwrap(), b"");
        assert_eq!(
            conn.transport().written,
            [&[0, 0, 0, 4][..], b"ping"].concat()
        );
    }

    #[test]
    fn local_refusals_keep_the_connection() {
        let mut conn = ExecutorConnection::new(Scripted::new(quote_frame(b"Q")));
        conn.read_quote().unwrap();
        assert!(matches!(
            conn.send(b""),
            Err(ExecutorError::Wire(WireError::EmptyPayload))
        ));
        assert!(matches!(
            conn.send(&[0u8; wire::MAX_PAYLOAD + 1]),
            Err(ExecutorError::Wire(WireError::PayloadTooLarge { .. }))
        ));
        conn.send(b"ok").unwrap();
        assert!(conn.transport().written.len() == 6);
    }

    #[test]
    fn failure_status_is_fatal() {
        let mut input = quote_frame(b"Q");
        input.push(0x02);
        wire::encode_response(&Response::Ok(b"late".to_vec()), &mut input).unwrap();
        let mut conn = ExecutorConnection::new(Scripted::new(input));
        conn.read_quote().unwrap();
        conn.send(b"a").unwrap();
        assert!(matches!(
            conn.recv(),
            Err(ExecutorError::Status(Status::EnclaveCommunicationFailure))
        ));
        assert!(matches!(conn.recv(), Err(ExecutorError::Protocol(_))));
        assert!(matches!(conn.send(b"b"), Err(ExecutorError::Protocol(_))));
    }

    #[test]
    fn remote_diagnostic_is_collected() {
        let session = include_bytes!("../../../fixtures/remote_pccs_error_session.bin");
        let mut conn = ExecutorConnection::new(Scripted::new(session.to_vec()));
        let err = conn.read_quote().unwrap_err();
        assert!(err.is_infrastructure_unavailable());
        let ExecutorError::RemoteDiagnostic(text) = &err else {
            panic!("{err:?}");
        };
        assert_eq!(text.len(), session.len());
        assert!(text.starts_with("[QCNL] Error:"));
        assert!(err.to_string().contains("Error in sgx_qe_get_target_info"));
    }

    #[test]
    fn eof_and_timeouts() {
        // EOF inside the quote.
        let mut frame = quote_frame(b"0123456789");
        frame.truncate(8);
        let mut conn = ExecutorConnection::new(Scripted::new(frame));
        match conn.read_quote() {
            Err(ExecutorError::Closed { partial, .. }) => assert_eq!(partial.len(), 8),
            other => panic!("{other:?}"),
        }

        // A stalled response.
        let mut s = Scripted::new([quote_frame(b"Q"), vec![0x00, 0, 0]].concat());
        s.stall = true;
        let mut conn = ExecutorConnection::new(s);
        conn.read_quote().unwrap();
        conn.send(b"a").unwrap();
        assert!(matches!(conn.recv(), Err(ExecutorError::Timeout { .. })));

        // Oversized binary length and unknown status are framing errors.
        let mut conn = ExecutorConnection::new(Scripted::new(vec![0x7f, 0, 0, 0]));
        assert!(matches!(
            conn.read_quote(),
            Err(ExecutorError::Wire(WireError::QuoteTooLarge { .. }))
        ));
        let mut conn =
            ExecutorConnection::new(Scripted::new([quote_frame(b"Q"), vec![9]].concat()));
        conn.read_quote().unwrap();
        conn.send(b"a").unwrap();
        assert!(matches!(
            conn.recv(),
            Err(ExecutorError::Wire(WireError::UnknownStatus(9)))
        ));
    }
}
