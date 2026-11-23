//! The SGXRA v1 record layer (`docs/PROTOCOL.md` §6.5).
//!
//! ```text
//! RECORD = 0x03 ‖ seq (u64 BE) ‖ ChaCha20-Poly1305(key, nonce, aad, plaintext) ‖ tag[16]
//! nonce  = 0x00000000 ‖ seq (u64 BE)
//! aad    = 0x03 ‖ seq (u64 BE)
//! key    = k_c2e (client → enclave) or k_e2c (enclave → client)
//! ```
//!
//! Each direction has its own key and its own counter starting at 0, so a
//! (key, nonce) pair is never used twice: the sender's counter only moves
//! forward and refuses to wrap, and the two directions never share a key.
//! The receiver accepts only the next expected sequence number, which rejects
//! replayed, reordered, dropped and reflected records.
//!
//! Any receive failure is fatal: the session wipes its keys and refuses all
//! further traffic. There is no way to continue, and no plaintext fallback.

use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

use crate::handshake::{MAX_RECORD_PLAINTEXT, MessageError, RECORD_HEADER_LEN, Record, TAG_LEN};

/// Size of a ChaCha20-Poly1305 key.
pub const KEY_LEN: usize = 32;

/// Highest sequence number a sender may use. The session must be re-keyed
/// (by reconnecting) before the counter would reach `u64::MAX`.
pub const MAX_SEQ: u64 = u64::MAX - 1;

/// Which end of the channel a [`Session`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The relying party: sends with `k_c2e`, receives with `k_e2c`.
    Client,
    /// The enclave: sends with `k_e2c`, receives with `k_c2e`.
    Enclave,
}

/// Errors of the record layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The plaintext exceeds [`MAX_RECORD_PLAINTEXT`]. Nothing was sent and
    /// the session is still usable.
    PlaintextTooLarge(usize),
    /// The received payload is not a well-formed record.
    Malformed(MessageError),
    /// The record's sequence number is not the next expected one (replay,
    /// reordering, a dropped record, or a reflected record).
    UnexpectedSequence {
        /// Sequence number the receiver expected.
        expected: u64,
        /// Sequence number found in the record.
        actual: u64,
    },
    /// Authentication failed: the record was tampered with or was not
    /// produced under this session's key for this direction.
    Decryption,
    /// The send or receive counter is exhausted; the session must be
    /// re-established.
    SequenceExhausted,
    /// The session already failed (or was closed) and holds no keys.
    SessionFailed,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextTooLarge(n) => write!(
                f,
                "plaintext of {n} bytes exceeds the record limit of {MAX_RECORD_PLAINTEXT}"
            ),
            Self::Malformed(e) => write!(f, "malformed record: {e}"),
            Self::UnexpectedSequence { expected, actual } => write!(
                f,
                "record sequence number {actual} received, {expected} expected (replay or reordering)"
            ),
            Self::Decryption => f.write_str("record authentication failed"),
            Self::SequenceExhausted => f.write_str("record sequence numbers exhausted"),
            Self::SessionFailed => f.write_str("secure session has failed and was wiped"),
        }
    }
}

impl core::error::Error for RecordError {}

impl From<MessageError> for RecordError {
    fn from(e: MessageError) -> Self {
        Self::Malformed(e)
    }
}

/// Live key material. The ciphers zeroize their keys on drop.
struct Keys {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
}

/// An established session: per-direction keys and counters.
///
/// Created by the handshake ([`crate::handshake::ClientHandshake`],
/// [`crate::handshake::respond`]); never constructed from raw keys by
/// applications.
pub struct Session {
    role: Role,
    keys: Option<Keys>,
    send_seq: u64,
    recv_seq: u64,
}

impl Session {
    /// Builds a session from the two directional keys derived in the
    /// handshake.
    pub(crate) fn new(role: Role, k_c2e: &[u8; KEY_LEN], k_e2c: &[u8; KEY_LEN]) -> Self {
        let c2e = ChaCha20Poly1305::new(Key::from_slice(k_c2e));
        let e2c = ChaCha20Poly1305::new(Key::from_slice(k_e2c));
        let (send, recv) = match role {
            Role::Client => (c2e, e2c),
            Role::Enclave => (e2c, c2e),
        };
        Self {
            role,
            keys: Some(Keys { send, recv }),
            send_seq: 0,
            recv_seq: 0,
        }
    }

    /// This end's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Whether the session failed or was closed (its keys are gone).
    pub fn is_failed(&self) -> bool {
        self.keys.is_none()
    }

    /// Sequence number the next [`Session::seal`] will use.
    pub fn next_send_seq(&self) -> u64 {
        self.send_seq
    }

    /// Sequence number the next [`Session::open`] will accept.
    pub fn next_recv_seq(&self) -> u64 {
        self.recv_seq
    }

    /// Wipes the keys; every later operation fails with
    /// [`RecordError::SessionFailed`].
    pub fn close(&mut self) {
        self.keys = None;
    }

    /// Encrypts `plaintext` into a complete `RECORD` payload and advances
    /// the send counter.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        if plaintext.len() > MAX_RECORD_PLAINTEXT {
            return Err(RecordError::PlaintextTooLarge(plaintext.len()));
        }
        let keys = self.keys.as_ref().ok_or(RecordError::SessionFailed)?;
        let seq = self.send_seq;
        if seq > MAX_SEQ {
            self.close();
            return Err(RecordError::SequenceExhausted);
        }
        let header = Record::header(seq);
        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + plaintext.len() + TAG_LEN);
        out.extend_from_slice(&header);
        out.extend_from_slice(plaintext);
        let tag = match keys.send.encrypt_in_place_detached(
            &nonce(seq),
            &header,
            &mut out[RECORD_HEADER_LEN..],
        ) {
            Ok(tag) => tag,
            Err(_) => {
                // Unreachable for record-sized inputs; fail closed anyway.
                self.close();
                return Err(RecordError::SessionFailed);
            }
        };
        out.extend_from_slice(&tag);
        // Advance only after the record exists, so a counter value is never
        // handed out twice.
        self.send_seq = seq + 1;
        Ok(out)
    }

    /// Authenticates and decrypts a complete `RECORD` payload.
    ///
    /// Any failure wipes the session.
    pub fn open(&mut self, payload: &[u8]) -> Result<Vec<u8>, RecordError> {
        let result = self.open_inner(payload);
        if result.is_err() {
            self.close();
        }
        result
    }

    fn open_inner(&mut self, payload: &[u8]) -> Result<Vec<u8>, RecordError> {
        let keys = self.keys.as_ref().ok_or(RecordError::SessionFailed)?;
        let record = Record::decode(payload)?;
        if self.recv_seq > MAX_SEQ {
            return Err(RecordError::SequenceExhausted);
        }
        if record.seq != self.recv_seq {
            return Err(RecordError::UnexpectedSequence {
                expected: self.recv_seq,
                actual: record.seq,
            });
        }
        let split = record.plaintext_len();
        let (ciphertext, tag) = record.sealed.split_at(split);
        let mut plaintext = Vec::from(ciphertext);
        keys.recv
            .decrypt_in_place_detached(
                &nonce(record.seq),
                &Record::header(record.seq),
                &mut plaintext,
                Tag::from_slice(tag),
            )
            .map_err(|_| RecordError::Decryption)?;
        self.recv_seq += 1;
        Ok(plaintext)
    }

    #[cfg(test)]
    pub(crate) fn set_send_seq(&mut self, seq: u64) {
        self.send_seq = seq;
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("role", &self.role)
            .field("failed", &self.is_failed())
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .finish_non_exhaustive()
    }
}

fn nonce(seq: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    Nonce::from(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::MAX_PAYLOAD;
    use alloc::vec;

    fn pair() -> (Session, Session) {
        let c2e = [0x11; 32];
        let e2c = [0x22; 32];
        (
            Session::new(Role::Client, &c2e, &e2c),
            Session::new(Role::Enclave, &c2e, &e2c),
        )
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut client, mut enclave) = pair();
        for i in 0..3u8 {
            let rec = client.seal(&[i; 10]).unwrap();
            assert_eq!(rec[..9], Record::header(u64::from(i)));
            assert_eq!(enclave.open(&rec).unwrap(), [i; 10]);
            let reply = enclave.seal(b"ok").unwrap();
            assert_eq!(client.open(&reply).unwrap(), b"ok");
        }
        assert_eq!(client.next_send_seq(), 3);
        assert_eq!(enclave.next_recv_seq(), 3);
    }

    #[test]
    fn known_answer_nonce_and_aad() {
        // Independent RFC 8439 computation: same key/nonce/aad via the raw
        // AEAD must give the same bytes as the record layer.
        let (mut client, _) = pair();
        client.set_send_seq(0x0102);
        let rec = client.seal(b"abc").unwrap();
        let mut buf = *b"abc";
        let mut n = [0u8; 12];
        n[10] = 1;
        n[11] = 2;
        let tag = ChaCha20Poly1305::new(Key::from_slice(&[0x11; 32]))
            .encrypt_in_place_detached(Nonce::from_slice(&n), &rec[..9], &mut buf)
            .unwrap();
        assert_eq!(rec[9..12], buf);
        assert_eq!(rec[12..], tag[..]);
    }

    #[test]
    fn max_size_record_fits_enclave_buffer() {
        let (mut client, mut enclave) = pair();
        let rec = client.seal(&vec![0x5a; MAX_RECORD_PLAINTEXT]).unwrap();
        assert_eq!(rec.len(), MAX_PAYLOAD);
        assert_eq!(enclave.open(&rec).unwrap().len(), MAX_RECORD_PLAINTEXT);

        // One byte more is refused locally and does not hurt the session.
        assert_eq!(
            client.seal(&vec![0; MAX_RECORD_PLAINTEXT + 1]),
            Err(RecordError::PlaintextTooLarge(MAX_RECORD_PLAINTEXT + 1))
        );
        assert!(!client.is_failed());
        assert_eq!(client.next_send_seq(), 1);
    }

    #[test]
    fn tampered_ciphertext_tag_and_header_are_rejected() {
        for pos in [0usize, 5, 9, 12, 20] {
            let (mut client, mut enclave) = pair();
            let mut rec = client.seal(b"attack at dawn").unwrap();
            rec[pos] ^= 0x01;
            let err = enclave.open(&rec).unwrap_err();
            match pos {
                0 => assert!(matches!(err, RecordError::Malformed(_))),
                5 => assert!(matches!(err, RecordError::UnexpectedSequence { .. })),
                _ => assert_eq!(err, RecordError::Decryption),
            }
            // The failure is permanent, even for the original record.
            assert!(enclave.is_failed());
            rec[pos] ^= 0x01;
            assert_eq!(enclave.open(&rec), Err(RecordError::SessionFailed));
            assert_eq!(enclave.seal(b"x"), Err(RecordError::SessionFailed));
        }
    }

    #[test]
    fn truncated_record_is_rejected() {
        let (mut client, mut enclave) = pair();
        let rec = client.seal(b"hello").unwrap();
        assert_eq!(
            enclave.open(&rec[..rec.len() - 1]),
            Err(RecordError::Decryption)
        );
        let (mut client, mut enclave) = pair();
        let rec = client.seal(b"").unwrap();
        assert!(matches!(
            enclave.open(&rec[..rec.len() - 1]),
            Err(RecordError::Malformed(MessageError::RecordTooShort(24)))
        ));
    }

    #[test]
    fn replay_is_rejected() {
        let (mut client, mut enclave) = pair();
        let rec = client.seal(b"pay 10").unwrap();
        assert_eq!(enclave.open(&rec).unwrap(), b"pay 10");
        assert_eq!(
            enclave.open(&rec),
            Err(RecordError::UnexpectedSequence {
                expected: 1,
                actual: 0
            })
        );
        assert!(enclave.is_failed());
    }

    #[test]
    fn reordering_and_drops_are_rejected() {
        let (mut client, mut enclave) = pair();
        let r0 = client.seal(b"0").unwrap();
        let r1 = client.seal(b"1").unwrap();
        assert_eq!(
            enclave.open(&r1),
            Err(RecordError::UnexpectedSequence {
                expected: 0,
                actual: 1
            })
        );
        assert_eq!(enclave.open(&r0), Err(RecordError::SessionFailed));
    }

    #[test]
    fn nonce_reuse_is_impossible_and_detected() {
        let (mut client, mut enclave) = pair();

        // The sender never reuses a nonce: identical plaintexts get distinct
        // sequence numbers and therefore distinct ciphertexts.
        let a = client.seal(b"same").unwrap();
        let b = client.seal(b"same").unwrap();
        assert_ne!(a[1..9], b[1..9]);
        assert_ne!(a[9..], b[9..]);

        // A forged record reusing an already-consumed nonce (seq 0) is
        // rejected before decryption is even attempted.
        assert_eq!(enclave.open(&a).unwrap(), b"same");
        let mut forged = a.clone();
        forged[9] ^= 0xff;
        assert_eq!(
            enclave.open(&forged),
            Err(RecordError::UnexpectedSequence {
                expected: 1,
                actual: 0
            })
        );

        // The two directions use different keys, so the same counter value
        // in both directions is not a nonce reuse: a client record reflected
        // back to the client does not authenticate.
        let (mut client, mut enclave) = pair();
        let req = client.seal(b"ping").unwrap();
        assert_eq!(client.open(&req), Err(RecordError::Decryption));
        let reply = enclave.seal(b"ping").unwrap();
        assert_eq!(req[..9], reply[..9]);
        assert_ne!(req[9..], reply[9..]);
    }

    #[test]
    fn counter_never_wraps() {
        let (mut client, mut enclave) = pair();
        client.set_send_seq(MAX_SEQ);
        let last = client.seal(b"last").unwrap();
        assert_eq!(last[1..9], MAX_SEQ.to_be_bytes());
        assert_eq!(client.next_send_seq(), u64::MAX);
        assert_eq!(client.seal(b"wrap"), Err(RecordError::SequenceExhausted));
        assert!(client.is_failed());

        // A receiver never accepts seq u64::MAX either.
        enclave.recv_seq = u64::MAX;
        let mut fake = last;
        fake[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(enclave.open(&fake), Err(RecordError::SequenceExhausted));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (mut client, _) = pair();
        let mut other = Session::new(Role::Enclave, &[0x33; 32], &[0x22; 32]);
        let rec = client.seal(b"secret").unwrap();
        assert_eq!(other.open(&rec), Err(RecordError::Decryption));
    }
}
