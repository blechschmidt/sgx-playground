//! One session of the executor protocol (`docs/PROTOCOL.md` §2).
//!
//! ```text
//! S → C   u32 BE len ‖ quote                      once, before any input is read
//! C → S   u32 BE len ‖ payload                    1 ..= 4096 bytes
//! S → C   0x00 ‖ u32 BE len ‖ response            ECALL succeeded
//!         0x02                                    ECALL failed; session continues
//! ```
//!
//! Differences from the blueprint `App.cpp`, all invisible to a conforming
//! client:
//!
//! * A declared length above 4096 bytes ends the session instead of
//!   overflowing a stack buffer (Q2); a zero length ends it explicitly
//!   (the blueprint ends it by accident, Q3).
//! * EOF between frames ends the session normally; EOF inside a frame is
//!   reported as [`HostError::TruncatedRequest`] (Q4).
//! * Every write is checked and flushed (Q7); nothing but frames is written.

use std::io::{self, Read, Write};

use sgx_ra_core::wire::{self, LEN_PREFIX, MAX_PAYLOAD, Status};

use crate::log::{debug, info};
use crate::{EnclaveBackend, HostError, Quoter};

/// What happened during a session that ended normally (client EOF).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionSummary {
    /// Requests passed to the enclave.
    pub requests: u64,
    /// Requests answered with a failure status.
    pub failures: u64,
}

/// Runs the attestation steps of `App.cpp`: QE target info, an enclave
/// report targeted at the QE, and the quote for it. Returns the bytes to
/// announce.
pub fn attest<E, Q>(enclave: &mut E, quoter: &mut Q) -> Result<Vec<u8>, HostError>
where
    E: EnclaveBackend + ?Sized,
    Q: Quoter + ?Sized,
{
    let target = quoter.target_info()?;
    debug!("got the quoting enclave's target info");
    let report = enclave.create_report(&target)?;
    let body = report.body();
    info!(
        "enclave report: MRENCLAVE {}, ISVPRODID {}, ISVSVN {}, debug {}",
        body.mr_enclave(),
        body.isv_prod_id(),
        body.isv_svn(),
        body.attributes().is_debug()
    );
    let quote = quoter.quote(&report)?;
    info!("announcing {} bytes of evidence", quote.len());
    Ok(quote)
}

/// [`attest`] followed by [`serve_session`].
pub fn run_session<E, Q, R, W>(
    enclave: &mut E,
    quoter: &mut Q,
    reader: R,
    writer: W,
) -> Result<SessionSummary, HostError>
where
    E: EnclaveBackend + ?Sized,
    Q: Quoter + ?Sized,
    R: Read,
    W: Write,
{
    let announcement = attest(enclave, quoter)?;
    serve_session(enclave, &announcement, reader, writer)
}

/// Announces `announcement` (normally the quote) and then relays requests
/// to `enclave` until the client closes the connection.
///
/// Enclave failures are answered with status `0x02` and the session goes
/// on, as in the blueprint. Framing violations and I/O errors end the
/// session with an error.
pub fn serve_session<E, R, W>(
    enclave: &mut E,
    announcement: &[u8],
    mut reader: R,
    mut writer: W,
) -> Result<SessionSummary, HostError>
where
    E: EnclaveBackend + ?Sized,
    R: Read,
    W: Write,
{
    let mut frame = Vec::with_capacity(LEN_PREFIX + announcement.len());
    wire::encode_quote(announcement, &mut frame)?;
    send(&mut writer, &frame)?;

    let mut summary = SessionSummary::default();
    let mut input = Box::new([0u8; MAX_PAYLOAD]);
    let mut output = Box::new([0u8; MAX_PAYLOAD]);
    loop {
        let mut prefix = [0u8; LEN_PREFIX];
        if !read_exact_or_eof(&mut reader, &mut prefix)? {
            return Ok(summary);
        }
        let len = u32::from_be_bytes(prefix) as usize;
        match len {
            0 => return Err(wire::WireError::EmptyPayload.into()),
            n if n > MAX_PAYLOAD => return Err(wire::WireError::PayloadTooLarge { len: n }.into()),
            _ => {}
        }
        let request = &mut input[..len];
        reader.read_exact(request).map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => HostError::TruncatedRequest,
            _ => HostError::Io(e),
        })?;
        summary.requests += 1;

        output.fill(0);
        frame.clear();
        match enclave.message(request, &mut output) {
            Ok(n) if n <= MAX_PAYLOAD => {
                debug!(
                    "request {}: {len} bytes in, {n} bytes out",
                    summary.requests
                );
                frame.push(Status::Ok as u8);
                frame.extend_from_slice(&(n as u32).to_be_bytes());
                frame.extend_from_slice(&output[..n]);
            }
            result => {
                let error = match result {
                    Ok(n) => HostError::InvalidResponseLength(n),
                    Err(e) => e,
                };
                info!("request {} ({len} bytes) failed: {error}", summary.requests);
                summary.failures += 1;
                frame.push(Status::EnclaveCommunicationFailure as u8);
            }
        }
        send(&mut writer, &frame)?;
    }
}

fn send<W: Write>(writer: &mut W, frame: &[u8]) -> Result<(), HostError> {
    writer.write_all(frame)?;
    writer.flush()?;
    Ok(())
}

/// Fills `buf` completely. Returns `Ok(false)` on EOF before the first
/// byte and [`HostError::TruncatedRequest`] on EOF after it.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool, HostError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(HostError::TruncatedRequest),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sgx_ra_core::sgx::report::{REPORT_LEN, TARGET_INFO_LEN};
    use sgx_ra_core::sgx::{Report, TargetInfo};
    use sgx_ra_core::wire::{Decoded, Response, WireError};

    /// Echoes requests; a request starting with `!` is rejected.
    #[derive(Debug, Default)]
    pub(crate) struct MockEnclave {
        pub(crate) reports: usize,
        pub(crate) messages: usize,
        pub(crate) last_target: Option<TargetInfo>,
        /// Reported response length override (to test the bounds check).
        pub(crate) bogus_len: Option<usize>,
    }

    impl EnclaveBackend for MockEnclave {
        fn create_report(&mut self, qe_target: &TargetInfo) -> Result<Report, HostError> {
            self.reports += 1;
            self.last_target = Some(*qe_target);
            let mut raw = [0u8; REPORT_LEN];
            raw[64..96].fill(0xAB); // MRENCLAVE
            Ok(Report::from_bytes(&raw).unwrap())
        }

        fn message(
            &mut self,
            input: &[u8],
            output: &mut [u8; MAX_PAYLOAD],
        ) -> Result<usize, HostError> {
            self.messages += 1;
            if input.first() == Some(&b'!') {
                return Err(HostError::EnclaveRejected {
                    call: "enclave_message",
                    status: 1,
                });
            }
            output[..input.len()].copy_from_slice(input);
            Ok(self.bogus_len.unwrap_or(input.len()))
        }
    }

    /// Wraps the report into a fake "quote" (`QUOTE` ‖ report).
    #[derive(Debug, Default)]
    pub(crate) struct MockQuoter;

    impl Quoter for MockQuoter {
        fn target_info(&mut self) -> Result<TargetInfo, HostError> {
            Ok(TargetInfo::from_bytes(&[7u8; TARGET_INFO_LEN]).unwrap())
        }

        fn quote(&mut self, report: &Report) -> Result<Vec<u8>, HostError> {
            let mut q = b"QUOTE".to_vec();
            q.extend_from_slice(report.as_bytes());
            Ok(q)
        }
    }

    fn request(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// Splits the server output into the announcement and the responses.
    pub(crate) fn parse_output(mut out: &[u8]) -> (Vec<u8>, Vec<Response>) {
        let Decoded::Complete {
            value: quote,
            consumed,
        } = wire::decode_quote(out).unwrap()
        else {
            panic!("incomplete announcement");
        };
        out = &out[consumed..];
        let mut responses = Vec::new();
        while !out.is_empty() {
            let Decoded::Complete { value, consumed } = wire::decode_response(out).unwrap() else {
                panic!("incomplete response");
            };
            responses.push(value);
            out = &out[consumed..];
        }
        (quote, responses)
    }

    fn run(input: &[u8]) -> (Result<SessionSummary, HostError>, Vec<u8>, MockEnclave) {
        let mut enclave = MockEnclave::default();
        let mut out = Vec::new();
        let result = run_session(&mut enclave, &mut MockQuoter, input, &mut out);
        (result, out, enclave)
    }

    #[test]
    fn announces_quote_then_echoes() {
        let mut input = request(b"Hello, SGX server!");
        input.extend(request(&[0x55; MAX_PAYLOAD]));
        let (result, out, enclave) = run(&input);
        assert_eq!(
            result.unwrap(),
            SessionSummary {
                requests: 2,
                failures: 0
            }
        );
        assert_eq!(enclave.reports, 1);
        assert_eq!(
            enclave.last_target.unwrap().as_bytes(),
            &[7u8; TARGET_INFO_LEN]
        );
        let (quote, responses) = parse_output(&out);
        assert_eq!(&quote[..5], b"QUOTE");
        assert_eq!(quote.len(), 5 + REPORT_LEN);
        assert_eq!(
            responses,
            vec![
                Response::Ok(b"Hello, SGX server!".to_vec()),
                Response::Ok(vec![0x55; MAX_PAYLOAD])
            ]
        );
    }

    #[test]
    fn byte_exact_blueprint_framing() {
        let (result, out, _) = run(&request(b"hi"));
        result.unwrap();
        let tail = &out[4 + 5 + REPORT_LEN..];
        assert_eq!(tail, &[0x00, 0, 0, 0, 2, b'h', b'i']);
    }

    #[test]
    fn enclave_failure_is_status_2_and_session_continues() {
        let mut input = request(b"!bad");
        input.extend(request(b"ok"));
        let (result, out, enclave) = run(&input);
        assert_eq!(
            result.unwrap(),
            SessionSummary {
                requests: 2,
                failures: 1
            }
        );
        assert_eq!(enclave.messages, 2);
        let (_, responses) = parse_output(&out);
        assert_eq!(
            responses,
            vec![
                Response::Failure(Status::EnclaveCommunicationFailure),
                Response::Ok(b"ok".to_vec())
            ]
        );
    }

    #[test]
    fn oversized_response_length_is_a_failure_not_an_overread() {
        let mut enclave = MockEnclave {
            bogus_len: Some(MAX_PAYLOAD + 1),
            ..Default::default()
        };
        let mut out = Vec::new();
        let summary = serve_session(&mut enclave, b"q", &request(b"x")[..], &mut out).unwrap();
        assert_eq!(summary.failures, 1);
        let (_, responses) = parse_output(&out);
        assert_eq!(
            responses,
            vec![Response::Failure(Status::EnclaveCommunicationFailure)]
        );
    }

    #[test]
    fn oversized_request_closes_without_reaching_the_enclave() {
        let mut input = ((MAX_PAYLOAD + 1) as u32).to_be_bytes().to_vec();
        input.extend(vec![0u8; MAX_PAYLOAD + 1]);
        let (result, out, enclave) = run(&input);
        assert!(matches!(
            result,
            Err(HostError::Wire(WireError::PayloadTooLarge { len })) if len == MAX_PAYLOAD + 1
        ));
        assert_eq!(enclave.messages, 0);
        let (_, responses) = parse_output(&out);
        assert!(responses.is_empty());
    }

    #[test]
    fn empty_request_closes() {
        let (result, _, enclave) = run(&[0, 0, 0, 0]);
        assert!(matches!(
            result,
            Err(HostError::Wire(WireError::EmptyPayload))
        ));
        assert_eq!(enclave.messages, 0);
    }

    #[test]
    fn eof_between_frames_is_normal_and_inside_a_frame_is_truncation() {
        let (result, _, _) = run(&[]);
        assert_eq!(result.unwrap(), SessionSummary::default());

        let (result, _, _) = run(&[0, 0]);
        assert!(matches!(result, Err(HostError::TruncatedRequest)));

        let mut input = request(b"hello");
        input.truncate(6);
        let (result, _, enclave) = run(&input);
        assert!(matches!(result, Err(HostError::TruncatedRequest)));
        assert_eq!(enclave.messages, 0);
    }

    #[test]
    fn quoter_failure_ends_before_anything_is_written() {
        struct Failing;
        impl Quoter for Failing {
            fn target_info(&mut self) -> Result<TargetInfo, HostError> {
                Err(HostError::sgx("sgx_qe_get_target_info", 0xe019))
            }
            fn quote(&mut self, _: &Report) -> Result<Vec<u8>, HostError> {
                unreachable!()
            }
        }
        let mut enclave = MockEnclave::default();
        let mut out = Vec::new();
        let err = run_session(&mut enclave, &mut Failing, &b""[..], &mut out).unwrap_err();
        assert_eq!(
            err.to_string(),
            "sgx_qe_get_target_info failed with status 0xe019"
        );
        assert!(out.is_empty(), "nothing may reach the wire");
        assert_eq!(enclave.reports, 0);
    }

    #[test]
    fn write_errors_are_propagated() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut enclave = MockEnclave::default();
        let err = serve_session(&mut enclave, b"q", &request(b"x")[..], Closed).unwrap_err();
        assert!(matches!(err, HostError::Io(e) if e.kind() == io::ErrorKind::BrokenPipe));
    }

    #[test]
    fn handles_short_reads() {
        /// Returns one byte per read call.
        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                match (self.0.split_first(), buf.first_mut()) {
                    (Some((b, rest)), Some(dst)) => {
                        *dst = *b;
                        self.0 = rest;
                        Ok(1)
                    }
                    _ => Ok(0),
                }
            }
        }
        let input = request(b"slow");
        let mut enclave = MockEnclave::default();
        let mut out = Vec::new();
        let summary = serve_session(&mut enclave, b"q", Trickle(&input), &mut out).unwrap();
        assert_eq!(summary.requests, 1);
        let (_, responses) = parse_output(&out);
        assert_eq!(responses, vec![Response::Ok(b"slow".to_vec())]);
    }
}
