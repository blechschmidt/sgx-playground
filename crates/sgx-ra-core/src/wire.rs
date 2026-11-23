//! Layer-1 framing of the remote executor protocol (`docs/PROTOCOL.md` §2).
//!
//! ```text
//! server → client, once:  quote_len:u32 BE ‖ quote
//! client → server:        msg_len:u32 BE  ‖ payload          (1 ..= 4096 bytes)
//! server → client:        0x00 ‖ resp_len:u32 BE ‖ payload   (success)
//!                         0x01 | 0x02                         (failure, no length)
//! ```
//!
//! The codec is sans-I/O: `encode_*` append to a `Vec`, `decode_*` inspect a
//! buffer and either return a complete frame together with the number of
//! bytes it consumed, or report how many more bytes are needed. Callers
//! (blocking or async) own the actual reads and writes.

use alloc::vec::Vec;
use core::fmt;

/// Size of every length prefix.
pub const LEN_PREFIX: usize = 4;
/// Maximum request and response payload (the EDL's fixed 4096-byte buffers;
/// the blueprint host overflows its stack beyond this, quirk Q1/Q2).
pub const MAX_PAYLOAD: usize = 4096;
/// Upper bound accepted for the quote announcement. Real DCAP quotes are
/// about 4.7 KiB; anything larger is treated as garbage.
pub const MAX_QUOTE_LEN: usize = 64 * 1024;

/// Status byte preceding every response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Status {
    /// The enclave processed the request; a length-prefixed payload follows.
    Ok = 0x00,
    /// The host read a short payload (unreachable with the blueprint host).
    MessageTooShort = 0x01,
    /// The ECALL failed or the enclave rejected the request.
    EnclaveCommunicationFailure = 0x02,
}

impl Status {
    /// Maps a status byte to a known status.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Ok),
            0x01 => Some(Self::MessageTooShort),
            0x02 => Some(Self::EnclaveCommunicationFailure),
            _ => None,
        }
    }
}

/// A decoded response frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Status `0x00` with the enclave's payload.
    Ok(Vec<u8>),
    /// A failure status (never [`Status::Ok`]).
    Failure(Status),
}

/// Result of a decode attempt on a possibly incomplete buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded<T> {
    /// A complete frame; `consumed` bytes of the buffer belong to it.
    Complete {
        /// The decoded frame.
        value: T,
        /// Number of buffer bytes the frame occupied.
        consumed: usize,
    },
    /// The buffer holds a valid prefix; at least `needed` more bytes are
    /// required before decoding can make progress.
    Incomplete {
        /// Minimum number of additional bytes required.
        needed: usize,
    },
}

/// Framing errors. Every error is fatal for the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// A zero-length request; the blueprint host ends the session on it (Q3).
    EmptyPayload,
    /// A request or response payload above [`MAX_PAYLOAD`].
    PayloadTooLarge {
        /// Declared or actual length.
        len: usize,
    },
    /// A zero-length quote announcement.
    EmptyQuote,
    /// A quote length above [`MAX_QUOTE_LEN`].
    QuoteTooLarge {
        /// Declared length.
        len: usize,
    },
    /// The quote length prefix is printable text: the remote host wrote a
    /// diagnostic (e.g. `[QCNL] Error: …`) to the wire instead of a quote
    /// (quirk Q5). The caller should read and display the rest of the stream.
    RemoteDiagnostic {
        /// The four bytes that were read as the length prefix.
        prefix: [u8; LEN_PREFIX],
    },
    /// An unknown response status byte.
    UnknownStatus(u8),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => f.write_str("empty payloads are not allowed"),
            Self::PayloadTooLarge { len } => {
                write!(
                    f,
                    "payload of {len} bytes exceeds the {MAX_PAYLOAD}-byte limit"
                )
            }
            Self::EmptyQuote => f.write_str("remote announced an empty quote"),
            Self::QuoteTooLarge { len } => {
                write!(
                    f,
                    "announced quote length {len} exceeds {MAX_QUOTE_LEN} bytes"
                )
            }
            Self::RemoteDiagnostic { prefix } => write!(
                f,
                "remote sent text instead of a quote (starts with {:?})",
                core::str::from_utf8(prefix).unwrap_or("<non-utf8>")
            ),
            Self::UnknownStatus(b) => write!(f, "unknown response status byte {b:#04x}"),
        }
    }
}

impl core::error::Error for WireError {}

/// Whether `bytes` look like diagnostic text (printable ASCII and common
/// whitespace) rather than binary protocol data.
pub fn looks_like_text(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    // Callers bound `len` to at most MAX_QUOTE_LEN, so it fits in u32.
    out.extend_from_slice(&(len as u32).to_be_bytes());
}

fn read_len(buf: &[u8]) -> usize {
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize
}

fn check_payload(len: usize) -> Result<(), WireError> {
    match len {
        0 => Err(WireError::EmptyPayload),
        n if n > MAX_PAYLOAD => Err(WireError::PayloadTooLarge { len: n }),
        _ => Ok(()),
    }
}

/// Appends the quote announcement frame.
pub fn encode_quote(quote: &[u8], out: &mut Vec<u8>) -> Result<(), WireError> {
    match quote.len() {
        0 => return Err(WireError::EmptyQuote),
        n if n > MAX_QUOTE_LEN => return Err(WireError::QuoteTooLarge { len: n }),
        _ => {}
    }
    put_len(out, quote.len());
    out.extend_from_slice(quote);
    Ok(())
}

/// Decodes the quote announcement.
pub fn decode_quote(buf: &[u8]) -> Result<Decoded<Vec<u8>>, WireError> {
    if buf.len() < LEN_PREFIX {
        return Ok(Decoded::Incomplete {
            needed: LEN_PREFIX - buf.len(),
        });
    }
    let prefix = [buf[0], buf[1], buf[2], buf[3]];
    let len = read_len(buf);
    if len == 0 {
        return Err(WireError::EmptyQuote);
    }
    if len > MAX_QUOTE_LEN {
        return Err(if looks_like_text(&prefix) {
            WireError::RemoteDiagnostic { prefix }
        } else {
            WireError::QuoteTooLarge { len }
        });
    }
    decode_body(buf, len, |body| body.to_vec())
}

/// Appends a request frame. Refuses empty and oversized payloads, which the
/// blueprint host would mishandle (quirks Q2/Q3).
pub fn encode_request(payload: &[u8], out: &mut Vec<u8>) -> Result<(), WireError> {
    check_payload(payload.len())?;
    put_len(out, payload.len());
    out.extend_from_slice(payload);
    Ok(())
}

/// Decodes a request frame. The length is validated before any payload is
/// buffered, so an oversized declaration is rejected immediately.
pub fn decode_request(buf: &[u8]) -> Result<Decoded<Vec<u8>>, WireError> {
    if buf.len() < LEN_PREFIX {
        return Ok(Decoded::Incomplete {
            needed: LEN_PREFIX - buf.len(),
        });
    }
    let len = read_len(buf);
    check_payload(len)?;
    decode_body(buf, len, |body| body.to_vec())
}

/// Appends a response frame. A successful response may carry an empty
/// payload; it may not exceed [`MAX_PAYLOAD`].
pub fn encode_response(response: &Response, out: &mut Vec<u8>) -> Result<(), WireError> {
    match response {
        Response::Ok(payload) => {
            if payload.len() > MAX_PAYLOAD {
                return Err(WireError::PayloadTooLarge { len: payload.len() });
            }
            out.push(Status::Ok as u8);
            put_len(out, payload.len());
            out.extend_from_slice(payload);
        }
        Response::Failure(status) => {
            // A failure with status Ok would be indistinguishable from a
            // successful frame; encode it as a generic enclave failure.
            let status = match status {
                Status::Ok => Status::EnclaveCommunicationFailure,
                s => *s,
            };
            out.push(status as u8);
        }
    }
    Ok(())
}

/// Decodes a response frame.
pub fn decode_response(buf: &[u8]) -> Result<Decoded<Response>, WireError> {
    let Some(&status_byte) = buf.first() else {
        return Ok(Decoded::Incomplete { needed: 1 });
    };
    match Status::from_byte(status_byte) {
        None => Err(WireError::UnknownStatus(status_byte)),
        Some(Status::Ok) => {
            let rest = &buf[1..];
            if rest.len() < LEN_PREFIX {
                return Ok(Decoded::Incomplete {
                    needed: LEN_PREFIX - rest.len(),
                });
            }
            let len = read_len(rest);
            if len > MAX_PAYLOAD {
                return Err(WireError::PayloadTooLarge { len });
            }
            Ok(
                match decode_body(rest, len, |b| Response::Ok(b.to_vec()))? {
                    Decoded::Complete { value, consumed } => Decoded::Complete {
                        value,
                        consumed: consumed + 1,
                    },
                    incomplete => incomplete,
                },
            )
        }
        Some(failure) => Ok(Decoded::Complete {
            value: Response::Failure(failure),
            consumed: 1,
        }),
    }
}

/// Shared tail of the length-prefixed decoders; `buf` starts at the prefix.
fn decode_body<T>(
    buf: &[u8],
    len: usize,
    make: impl FnOnce(&[u8]) -> T,
) -> Result<Decoded<T>, WireError> {
    let total = LEN_PREFIX + len;
    if buf.len() < total {
        return Ok(Decoded::Incomplete {
            needed: total - buf.len(),
        });
    }
    Ok(Decoded::Complete {
        value: make(&buf[LEN_PREFIX..total]),
        consumed: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// What the live executor sent on 2026-11-22 instead of a quote.
    const PCCS_ERROR: &[u8] = include_bytes!("../../../fixtures/remote_pccs_error_session.bin");
    const QUOTE_V3: &[u8] = include_bytes!("../../../fixtures/quote_v3.dat");

    #[test]
    fn quote_roundtrip_and_incremental_decode() {
        let mut wire = Vec::new();
        encode_quote(QUOTE_V3, &mut wire).unwrap();
        assert_eq!(wire[..4], (QUOTE_V3.len() as u32).to_be_bytes());
        for cut in [0, 3, 4, 100, wire.len() - 1] {
            assert_eq!(
                decode_quote(&wire[..cut]).unwrap(),
                Decoded::Incomplete {
                    needed: if cut < 4 { 4 - cut } else { wire.len() - cut }
                }
            );
        }
        wire.extend_from_slice(b"next frame");
        assert_eq!(
            decode_quote(&wire).unwrap(),
            Decoded::Complete {
                value: QUOTE_V3.to_vec(),
                consumed: 4 + QUOTE_V3.len()
            }
        );
    }

    #[test]
    fn remote_diagnostic_is_detected() {
        assert!(looks_like_text(PCCS_ERROR));
        assert_eq!(
            decode_quote(PCCS_ERROR),
            Err(WireError::RemoteDiagnostic { prefix: *b"[QCN" })
        );
        assert_eq!(
            decode_quote(&[0x7f, 0, 0, 0]),
            Err(WireError::QuoteTooLarge { len: 0x7f00_0000 })
        );
        assert_eq!(decode_quote(&[0, 0, 0, 0]), Err(WireError::EmptyQuote));
    }

    #[test]
    fn request_limits() {
        let mut out = Vec::new();
        assert_eq!(encode_request(&[], &mut out), Err(WireError::EmptyPayload));
        assert_eq!(
            encode_request(&[0u8; MAX_PAYLOAD + 1], &mut out),
            Err(WireError::PayloadTooLarge {
                len: MAX_PAYLOAD + 1
            })
        );
        assert!(out.is_empty());

        encode_request(&[0xab; MAX_PAYLOAD], &mut out).unwrap();
        assert_eq!(
            decode_request(&out).unwrap(),
            Decoded::Complete {
                value: vec![0xab; MAX_PAYLOAD],
                consumed: 4 + MAX_PAYLOAD
            }
        );
        // An oversized declaration is rejected from the prefix alone.
        assert_eq!(
            decode_request(&4097u32.to_be_bytes()),
            Err(WireError::PayloadTooLarge { len: 4097 })
        );
        assert_eq!(decode_request(&[0, 0, 0, 0]), Err(WireError::EmptyPayload));
    }

    #[test]
    fn blueprint_echo_exchange() {
        // docs/PROTOCOL.md §2.5
        let mut req = Vec::new();
        encode_request(b"Hello, SGX server!", &mut req).unwrap();
        assert_eq!(req[..4], [0, 0, 0, 18]);

        let mut resp = Vec::new();
        encode_response(&Response::Ok(b"Hello, SGX server!".to_vec()), &mut resp).unwrap();
        assert_eq!(resp[..5], [0, 0, 0, 0, 18]);
        assert_eq!(
            decode_response(&resp).unwrap(),
            Decoded::Complete {
                value: Response::Ok(b"Hello, SGX server!".to_vec()),
                consumed: 23
            }
        );
        assert_eq!(
            decode_response(&resp[..3]).unwrap(),
            Decoded::Incomplete { needed: 2 }
        );
        assert_eq!(
            decode_response(&resp[..10]).unwrap(),
            Decoded::Incomplete { needed: 13 }
        );
    }

    #[test]
    fn response_failures() {
        let mut out = Vec::new();
        encode_response(
            &Response::Failure(Status::EnclaveCommunicationFailure),
            &mut out,
        )
        .unwrap();
        encode_response(&Response::Failure(Status::Ok), &mut out).unwrap();
        assert_eq!(out, [0x02, 0x02]);
        assert_eq!(
            decode_response(&[0x01, 0xff]).unwrap(),
            Decoded::Complete {
                value: Response::Failure(Status::MessageTooShort),
                consumed: 1
            }
        );
        assert_eq!(decode_response(&[0x03]), Err(WireError::UnknownStatus(3)));
        assert_eq!(
            decode_response(&[]).unwrap(),
            Decoded::Incomplete { needed: 1 }
        );
        assert_eq!(
            decode_response(&[0, 0, 0, 0x10, 0x01]),
            Err(WireError::PayloadTooLarge { len: 4097 })
        );
        assert!(encode_response(&Response::Ok(vec![0; MAX_PAYLOAD + 1]), &mut out).is_err());
        // Empty successful responses are legal.
        let mut out = Vec::new();
        encode_response(&Response::Ok(Vec::new()), &mut out).unwrap();
        assert_eq!(
            decode_response(&out).unwrap(),
            Decoded::Complete {
                value: Response::Ok(Vec::new()),
                consumed: 5
            }
        );
    }
}
