//! Message definitions of the attested channel protocol "SGXRA v1"
//! (`docs/PROTOCOL.md` §6.3).
//!
//! Every message is carried as one layer-1 payload ([`crate::wire`]) and
//! starts with a type byte:
//!
//! | type | message        | layout                                                     | size      |
//! |------|----------------|------------------------------------------------------------|-----------|
//! | 0x01 | [`Hello`]      | `01 ‖ 01 ‖ c_pub[32] ‖ c_nonce[32]`                         | 66        |
//! | 0x02 | [`HelloReply`] | `02 ‖ 01 ‖ ek_pub[32] ‖ se_pub[32] ‖ s_nonce[32] ‖ confirm[32]` | 130   |
//! | 0x03 | [`Record`]     | `03 ‖ seq:u64 BE ‖ ciphertext ‖ tag[16]`                    | 25..=4096 |
//!
//! On top of the codec, this module implements the key exchange (§6.4):
//! [`IdentityKey`] and [`respond`] on the enclave side, [`ClientHandshake`]
//! on the client side. Both produce a [`Session`] for the record layer
//! ([`crate::record`]).
//!
//! The handshake is transport-agnostic: it consumes and produces message
//! values, and the caller moves the bytes. [`crate::session`] packages it
//! with a message transport.

use alloc::vec::Vec;
use core::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::attestation::VerifiedClaims;
use crate::binding::{self, BindingError};
use crate::hex::Hex;
use crate::record::{Role, Session};
use crate::rng::{Rng, RngError};
use crate::sgx::{ReportBody, ReportData};
use crate::wire::MAX_PAYLOAD;

/// Protocol version carried in [`Hello`] and [`HelloReply`].
pub const PROTOCOL_VERSION: u8 = 1;
/// Size of an X25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Size of handshake nonces.
pub const NONCE_LEN: usize = 32;
/// Size of the key-confirmation MAC.
pub const CONFIRM_LEN: usize = 32;
/// Size of the ChaCha20-Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// Size of the record header (type ‖ seq).
pub const RECORD_HEADER_LEN: usize = 1 + 8;
/// Size of an encoded [`Hello`].
pub const HELLO_LEN: usize = 2 + PUBLIC_KEY_LEN + NONCE_LEN;
/// Size of an encoded [`HelloReply`].
pub const HELLO_REPLY_LEN: usize = 2 + 2 * PUBLIC_KEY_LEN + NONCE_LEN + CONFIRM_LEN;
/// Largest plaintext that fits in one record (4096 − 9 − 16 = 4071).
pub const MAX_RECORD_PLAINTEXT: usize = MAX_PAYLOAD - RECORD_HEADER_LEN - TAG_LEN;

/// Message type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Client → enclave key share.
    Hello = 0x01,
    /// Enclave → client key share and key confirmation.
    HelloReply = 0x02,
    /// Encrypted application data, both directions.
    Record = 0x03,
}

impl MessageType {
    /// Maps a type byte to a message type.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::HelloReply),
            0x03 => Some(Self::Record),
            _ => None,
        }
    }
}

/// Errors decoding or encoding a handshake-layer message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// The payload is empty.
    Empty,
    /// The type byte is not a known message type.
    UnknownType(u8),
    /// A known or unknown message type where a specific one was required.
    UnexpectedType {
        /// Required type.
        expected: MessageType,
        /// Type byte found.
        actual: u8,
    },
    /// The version byte is not [`PROTOCOL_VERSION`].
    UnsupportedVersion(u8),
    /// A fixed-size message has the wrong length.
    InvalidLength {
        /// Message type.
        message: MessageType,
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// A record is shorter than header plus tag.
    RecordTooShort(usize),
    /// A record (or its plaintext) does not fit in one layer-1 payload.
    RecordTooLarge(usize),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty message"),
            Self::UnknownType(t) => write!(f, "unknown message type {t:#04x}"),
            Self::UnexpectedType { expected, actual } => {
                write!(f, "expected {expected:?} message, got type {actual:#04x}")
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            Self::InvalidLength {
                message,
                expected,
                actual,
            } => write!(f, "{message:?} must be {expected} bytes, got {actual}"),
            Self::RecordTooShort(n) => write!(f, "record of {n} bytes is too short"),
            Self::RecordTooLarge(n) => write!(f, "record of {n} bytes is too large"),
        }
    }
}

impl core::error::Error for MessageError {}

/// `HELLO`: the client's ephemeral X25519 key and nonce.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// Client ephemeral public key `c_pub`.
    pub client_public: [u8; PUBLIC_KEY_LEN],
    /// Client nonce `c_nonce`.
    pub client_nonce: [u8; NONCE_LEN],
}

impl Hello {
    /// Encodes the message (66 bytes).
    pub fn encode(&self) -> [u8; HELLO_LEN] {
        let mut out = [0u8; HELLO_LEN];
        out[0] = MessageType::Hello as u8;
        out[1] = PROTOCOL_VERSION;
        out[2..34].copy_from_slice(&self.client_public);
        out[34..66].copy_from_slice(&self.client_nonce);
        out
    }

    /// Decodes a complete `HELLO` payload.
    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        check_fixed(buf, MessageType::Hello, HELLO_LEN)?;
        Ok(Self {
            client_public: take(buf, 2),
            client_nonce: take(buf, 34),
        })
    }
}

impl fmt::Debug for Hello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hello")
            .field("client_public", &Hex(&self.client_public))
            .field("client_nonce", &Hex(&self.client_nonce))
            .finish()
    }
}

/// `HELLO_REPLY`: the enclave identity key, a fresh enclave ephemeral key,
/// a nonce and the key confirmation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HelloReply {
    /// Enclave identity public key `ek_pub`, whose hash is in report_data.
    pub identity_public: [u8; PUBLIC_KEY_LEN],
    /// Per-handshake enclave ephemeral public key `se_pub`.
    pub ephemeral_public: [u8; PUBLIC_KEY_LEN],
    /// Enclave nonce `s_nonce`.
    pub server_nonce: [u8; NONCE_LEN],
    /// Key confirmation `HMAC(k_conf, label ‖ transcript_hash)`.
    pub confirm: [u8; CONFIRM_LEN],
}

impl HelloReply {
    /// Encodes the message (130 bytes).
    pub fn encode(&self) -> [u8; HELLO_REPLY_LEN] {
        let mut out = [0u8; HELLO_REPLY_LEN];
        out[0] = MessageType::HelloReply as u8;
        out[1] = PROTOCOL_VERSION;
        out[2..34].copy_from_slice(&self.identity_public);
        out[34..66].copy_from_slice(&self.ephemeral_public);
        out[66..98].copy_from_slice(&self.server_nonce);
        out[98..130].copy_from_slice(&self.confirm);
        out
    }

    /// Decodes a complete `HELLO_REPLY` payload.
    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        check_fixed(buf, MessageType::HelloReply, HELLO_REPLY_LEN)?;
        Ok(Self {
            identity_public: take(buf, 2),
            ephemeral_public: take(buf, 34),
            server_nonce: take(buf, 66),
            confirm: take(buf, 98),
        })
    }
}

impl fmt::Debug for HelloReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloReply")
            .field("identity_public", &Hex(&self.identity_public))
            .field("ephemeral_public", &Hex(&self.ephemeral_public))
            .field("server_nonce", &Hex(&self.server_nonce))
            .finish_non_exhaustive()
    }
}

/// `RECORD`: one AEAD-protected application message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Sequence number; also determines the AEAD nonce.
    pub seq: u64,
    /// Ciphertext followed by the 16-byte tag.
    pub sealed: &'a [u8],
}

impl<'a> Record<'a> {
    /// The record header, which is also the AEAD associated data.
    pub fn header(seq: u64) -> [u8; RECORD_HEADER_LEN] {
        let mut out = [0u8; RECORD_HEADER_LEN];
        out[0] = MessageType::Record as u8;
        out[1..].copy_from_slice(&seq.to_be_bytes());
        out
    }

    /// Encodes the record, checking that it fits one layer-1 payload.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let total = RECORD_HEADER_LEN + self.sealed.len();
        if self.sealed.len() < TAG_LEN {
            return Err(MessageError::RecordTooShort(total));
        }
        if total > MAX_PAYLOAD {
            return Err(MessageError::RecordTooLarge(total));
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&Self::header(self.seq));
        out.extend_from_slice(self.sealed);
        Ok(out)
    }

    /// Decodes a complete `RECORD` payload.
    pub fn decode(buf: &'a [u8]) -> Result<Self, MessageError> {
        check_type(buf, MessageType::Record)?;
        if buf.len() < RECORD_HEADER_LEN + TAG_LEN {
            return Err(MessageError::RecordTooShort(buf.len()));
        }
        if buf.len() > MAX_PAYLOAD {
            return Err(MessageError::RecordTooLarge(buf.len()));
        }
        Ok(Self {
            seq: u64::from_be_bytes(take(buf, 1)),
            sealed: &buf[RECORD_HEADER_LEN..],
        })
    }

    /// Length of the plaintext the record carries.
    pub fn plaintext_len(&self) -> usize {
        self.sealed.len() - TAG_LEN
    }
}

impl fmt::Debug for Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("seq", &self.seq)
            .field("sealed_len", &self.sealed.len())
            .finish()
    }
}

/// Any SGXRA v1 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    /// See [`Hello`].
    Hello(Hello),
    /// See [`HelloReply`].
    HelloReply(HelloReply),
    /// See [`Record`].
    Record(Record<'a>),
}

impl<'a> Message<'a> {
    /// Decodes a layer-1 payload according to its type byte.
    pub fn decode(buf: &'a [u8]) -> Result<Self, MessageError> {
        let &first = buf.first().ok_or(MessageError::Empty)?;
        match MessageType::from_byte(first) {
            Some(MessageType::Hello) => Hello::decode(buf).map(Self::Hello),
            Some(MessageType::HelloReply) => HelloReply::decode(buf).map(Self::HelloReply),
            Some(MessageType::Record) => Record::decode(buf).map(Self::Record),
            None => Err(MessageError::UnknownType(first)),
        }
    }

    /// The message type.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Hello(_) => MessageType::Hello,
            Self::HelloReply(_) => MessageType::HelloReply,
            Self::Record(_) => MessageType::Record,
        }
    }
}

fn check_type(buf: &[u8], expected: MessageType) -> Result<(), MessageError> {
    match buf.first() {
        None => Err(MessageError::Empty),
        Some(&t) if t == expected as u8 => Ok(()),
        Some(&actual) => Err(MessageError::UnexpectedType { expected, actual }),
    }
}

fn check_fixed(buf: &[u8], message: MessageType, expected: usize) -> Result<(), MessageError> {
    check_type(buf, message)?;
    if buf.len() != expected {
        return Err(MessageError::InvalidLength {
            message,
            expected,
            actual: buf.len(),
        });
    }
    if buf[1] != PROTOCOL_VERSION {
        return Err(MessageError::UnsupportedVersion(buf[1]));
    }
    Ok(())
}

fn take<const N: usize>(buf: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[offset..offset + N]);
    out
}

// ---------------------------------------------------------------------------
// Key agreement and key derivation (`docs/PROTOCOL.md` §6.4)
// ---------------------------------------------------------------------------

/// Label of the transcript hash.
pub const TRANSCRIPT_LABEL: &[u8] = b"SGXRA-v1/transcript";
/// HKDF info for the client → enclave record key.
pub const C2E_LABEL: &[u8] = b"SGXRA-v1/c2e";
/// HKDF info for the enclave → client record key.
pub const E2C_LABEL: &[u8] = b"SGXRA-v1/e2c";
/// HKDF info for the key-confirmation key.
pub const CONFIRM_KEY_LABEL: &[u8] = b"SGXRA-v1/confirm";
/// Prefix of the HMAC input of the enclave's key confirmation.
pub const ENCLAVE_CONFIRM_LABEL: &[u8] = b"SGXRA-v1/enclave-confirm";

type HmacSha256 = Hmac<Sha256>;

/// Errors of the key exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The random number generator failed.
    Rng(RngError),
    /// A handshake message could not be decoded.
    Message(MessageError),
    /// The enclave key in `HELLO_REPLY` is not the one committed to in the
    /// attested report_data.
    Binding(BindingError),
    /// A peer public key is a low-order point (the X25519 output would be
    /// independent of our secret).
    NonContributory,
    /// The enclave's key confirmation is wrong: it does not hold the secret
    /// of the attested key, or the transcript was tampered with.
    ConfirmationFailed,
    /// Enclave side: the report the enclave is about to answer for does not
    /// commit to its identity key (a framework bug; fail closed).
    IdentityNotAttested,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rng(e) => write!(f, "handshake: {e}"),
            Self::Message(e) => write!(f, "handshake: {e}"),
            Self::Binding(e) => write!(f, "handshake: {e}"),
            Self::NonContributory => f.write_str("handshake: peer sent a low-order public key"),
            Self::ConfirmationFailed => f.write_str("handshake: enclave key confirmation failed"),
            Self::IdentityNotAttested => {
                f.write_str("handshake: report does not commit to the enclave identity key")
            }
        }
    }
}

impl core::error::Error for HandshakeError {}

impl From<RngError> for HandshakeError {
    fn from(e: RngError) -> Self {
        Self::Rng(e)
    }
}

impl From<MessageError> for HandshakeError {
    fn from(e: MessageError) -> Self {
        Self::Message(e)
    }
}

impl From<BindingError> for HandshakeError {
    fn from(e: BindingError) -> Self {
        Self::Binding(e)
    }
}

fn random_secret(rng: &mut impl Rng) -> Result<StaticSecret, RngError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *bytes)?;
    Ok(StaticSecret::from(*bytes))
}

/// The enclave identity key `EK` (X25519), whose public half is committed to
/// in report_data ([`crate::binding`]).
///
/// Generated once per enclave instance with [`IdentityKey::generate`] and
/// kept in enclave memory only. The same type serves as the optional sealed
/// long-term identity `LK` ([`crate::identity`], via
/// [`IdentityKey::secret_bytes`] / [`IdentityKey::from_secret_bytes`]); `EK`
/// itself is never sealed, so report_data differs in every instance and an
/// old quote never vouches for a key that outlived its instance.
pub struct IdentityKey {
    secret: StaticSecret,
    public: PublicKey,
}

impl IdentityKey {
    /// Generates a fresh key from `rng` (inside the enclave: `sgx_read_rand`).
    pub fn generate(rng: &mut impl Rng) -> Result<Self, RngError> {
        Ok(Self::from_secret(random_secret(rng)?))
    }

    /// Restores a key from its 32 secret bytes (e.g. after unsealing).
    pub fn from_secret_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self::from_secret(StaticSecret::from(*bytes))
    }

    fn from_secret(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The secret bytes, for sealing only. They must never leave the enclave
    /// unencrypted.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// The public key `ek_pub`.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        self.public.as_bytes()
    }

    /// The report_data the enclave must put into its report.
    pub fn report_data(&self) -> ReportData {
        binding::report_data_for(self.public_key())
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKey")
            .field("public", &Hex(self.public_key()))
            .finish_non_exhaustive()
    }
}

/// `rb_hash = SHA-256(report_body)`: binds the transcript to the exact
/// attested report (MRENCLAVE, attributes, SVNs and report_data).
pub fn report_body_hash(report_body: &ReportBody) -> [u8; 32] {
    Sha256::digest(report_body.as_bytes()).into()
}

/// Inputs of the transcript hash, in transcript order.
struct Transcript<'a> {
    rb_hash: &'a [u8; 32],
    hello: &'a Hello,
    identity_public: &'a [u8; PUBLIC_KEY_LEN],
    ephemeral_public: &'a [u8; PUBLIC_KEY_LEN],
    server_nonce: &'a [u8; NONCE_LEN],
}

impl Transcript<'_> {
    /// `th = SHA-256(label ‖ rb_hash ‖ c_pub ‖ c_nonce ‖ ek_pub ‖ se_pub ‖ s_nonce)`.
    /// All fields have fixed length, so the encoding is unambiguous.
    fn hash(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(TRANSCRIPT_LABEL)
            .chain_update(self.rb_hash)
            .chain_update(self.hello.client_public)
            .chain_update(self.hello.client_nonce)
            .chain_update(self.identity_public)
            .chain_update(self.ephemeral_public)
            .chain_update(self.server_nonce)
            .finalize()
            .into()
    }
}

/// Keys derived from one handshake.
struct DerivedKeys {
    c2e: Zeroizing<[u8; 32]>,
    e2c: Zeroizing<[u8; 32]>,
    confirm: [u8; CONFIRM_LEN],
}

/// HKDF over `dh_static ‖ dh_ephemeral` with the transcript hash as salt,
/// then the enclave's key confirmation.
fn derive(
    th: &[u8; 32],
    dh_static: &SharedSecret,
    dh_ephemeral: &SharedSecret,
) -> Result<DerivedKeys, HandshakeError> {
    if !dh_static.was_contributory() || !dh_ephemeral.was_contributory() {
        return Err(HandshakeError::NonContributory);
    }
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(dh_static.as_bytes());
    ikm[32..].copy_from_slice(dh_ephemeral.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(th), &*ikm);

    let mut c2e = Zeroizing::new([0u8; 32]);
    let mut e2c = Zeroizing::new([0u8; 32]);
    let mut k_conf = Zeroizing::new([0u8; 32]);
    // 32-byte outputs are far below HKDF's 255·32 limit, so these cannot fail.
    hk.expand(C2E_LABEL, &mut *c2e).expect("HKDF output length");
    hk.expand(E2C_LABEL, &mut *e2c).expect("HKDF output length");
    hk.expand(CONFIRM_KEY_LABEL, &mut *k_conf)
        .expect("HKDF output length");

    let confirm = enclave_confirm(&k_conf, th);
    Ok(DerivedKeys { c2e, e2c, confirm })
}

/// `confirm = HMAC-SHA256(k_conf, "SGXRA-v1/enclave-confirm" ‖ th)`.
fn enclave_confirm(k_conf: &[u8; 32], th: &[u8; 32]) -> [u8; CONFIRM_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k_conf).expect("HMAC accepts any key length");
    mac.update(ENCLAVE_CONFIRM_LABEL);
    mac.update(th);
    mac.finalize().into_bytes().into()
}

/// Client side of the handshake.
///
/// It can only be started from [`VerifiedClaims`], i.e. after the quote was
/// verified and accepted by policy, and it only yields a [`Session`] once
/// the enclave proved possession of the key committed to in the attested
/// report_data.
pub struct ClientHandshake {
    secret: StaticSecret,
    hello: Hello,
    report_data: ReportData,
    rb_hash: [u8; 32],
}

impl ClientHandshake {
    /// Generates the client ephemeral key and nonce and returns the `HELLO`
    /// to send.
    pub fn start(
        claims: &VerifiedClaims,
        rng: &mut impl Rng,
    ) -> Result<(Self, Hello), HandshakeError> {
        let secret = random_secret(rng)?;
        let mut client_nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut client_nonce)?;
        let hello = Hello {
            client_public: PublicKey::from(&secret).to_bytes(),
            client_nonce,
        };
        let state = Self {
            secret,
            hello,
            report_data: claims.report_data(),
            rb_hash: report_body_hash(claims.report_body()),
        };
        Ok((state, hello))
    }

    /// The `HELLO` this handshake sent.
    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    /// Processes the enclave's `HELLO_REPLY`.
    ///
    /// Checks, in order: `ek_pub` is exactly the key committed to in the
    /// attested report_data; both X25519 results are contributory; the key
    /// confirmation matches (constant-time). Only then is a session returned.
    pub fn finish(self, reply: &HelloReply) -> Result<Session, HandshakeError> {
        binding::check_report_data(&self.report_data, &reply.identity_public)?;

        let th = Transcript {
            rb_hash: &self.rb_hash,
            hello: &self.hello,
            identity_public: &reply.identity_public,
            ephemeral_public: &reply.ephemeral_public,
            server_nonce: &reply.server_nonce,
        }
        .hash();
        let keys = derive(
            &th,
            &self
                .secret
                .diffie_hellman(&PublicKey::from(reply.identity_public)),
            &self
                .secret
                .diffie_hellman(&PublicKey::from(reply.ephemeral_public)),
        )?;
        if !bool::from(keys.confirm.ct_eq(&reply.confirm)) {
            return Err(HandshakeError::ConfirmationFailed);
        }
        Ok(Session::new(Role::Client, &keys.c2e, &keys.e2c))
    }

    /// Decodes a `HELLO_REPLY` payload and calls [`ClientHandshake::finish`].
    pub fn finish_payload(self, payload: &[u8]) -> Result<Session, HandshakeError> {
        let reply = HelloReply::decode(payload)?;
        self.finish(&reply)
    }
}

impl fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("hello", &self.hello)
            .finish_non_exhaustive()
    }
}

/// Enclave side of the handshake: answers a `HELLO`.
///
/// `report_body` is the body of the report the enclave created for its
/// quote. It must commit to `identity` (checked, failing closed); its hash
/// enters the transcript, so a client that verified a different report
/// derives different keys.
pub fn respond(
    identity: &IdentityKey,
    report_body: &ReportBody,
    hello: &Hello,
    rng: &mut impl Rng,
) -> Result<(HelloReply, Session), HandshakeError> {
    binding::check_report_data(&report_body.report_data(), identity.public_key())
        .map_err(|_| HandshakeError::IdentityNotAttested)?;

    let ephemeral = random_secret(rng)?;
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let mut server_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut server_nonce)?;

    let rb_hash = report_body_hash(report_body);
    let th = Transcript {
        rb_hash: &rb_hash,
        hello,
        identity_public: identity.public_key(),
        ephemeral_public: &ephemeral_public,
        server_nonce: &server_nonce,
    }
    .hash();
    let c_pub = PublicKey::from(hello.client_public);
    let keys = derive(
        &th,
        &identity.secret.diffie_hellman(&c_pub),
        &ephemeral.diffie_hellman(&c_pub),
    )?;
    let reply = HelloReply {
        identity_public: *identity.public_key(),
        ephemeral_public,
        server_nonce,
        confirm: keys.confirm,
    };
    Ok((reply, Session::new(Role::Enclave, &keys.c2e, &keys.e2c)))
}

impl IdentityKey {
    /// `X25519(sk, peer)`, for the long-term identity proof
    /// ([`crate::identity`]). Callers must check `was_contributory`.
    pub(crate) fn agree(&self, peer: &[u8; PUBLIC_KEY_LEN]) -> SharedSecret {
        self.secret.diffie_hellman(&PublicKey::from(*peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::TcbStatus;
    use crate::testutil::{FailingRng, TestRng, attested_body};
    use alloc::vec;

    #[test]
    fn sizes_match_protocol() {
        assert_eq!(HELLO_LEN, 66);
        assert_eq!(HELLO_REPLY_LEN, 130);
        assert_eq!(MAX_RECORD_PLAINTEXT, 4071);
    }

    #[test]
    fn hello_roundtrip() {
        let hello = Hello {
            client_public: [1; 32],
            client_nonce: [2; 32],
        };
        let enc = hello.encode();
        assert_eq!(enc[..2], [0x01, 0x01]);
        assert_eq!(Hello::decode(&enc), Ok(hello));
        assert_eq!(Message::decode(&enc), Ok(Message::Hello(hello)));

        let mut bad = enc;
        bad[1] = 2;
        assert_eq!(
            Hello::decode(&bad),
            Err(MessageError::UnsupportedVersion(2))
        );
        assert!(matches!(
            Hello::decode(&enc[..65]),
            Err(MessageError::InvalidLength {
                expected: 66,
                actual: 65,
                ..
            })
        ));
    }

    #[test]
    fn hello_reply_roundtrip() {
        let reply = HelloReply {
            identity_public: [3; 32],
            ephemeral_public: [4; 32],
            server_nonce: [5; 32],
            confirm: [6; 32],
        };
        let enc = reply.encode();
        assert_eq!(enc[0], 0x02);
        assert_eq!(enc[129], 6);
        assert_eq!(Message::decode(&enc), Ok(Message::HelloReply(reply)));
        // A HELLO_REPLY is never accepted where a HELLO is expected.
        assert_eq!(
            Hello::decode(&enc),
            Err(MessageError::UnexpectedType {
                expected: MessageType::Hello,
                actual: 0x02
            })
        );
    }

    #[test]
    fn record_bounds() {
        let sealed = vec![0xee; MAX_RECORD_PLAINTEXT + TAG_LEN];
        let rec = Record {
            seq: 0x0102_0304_0506_0708,
            sealed: &sealed,
        };
        let enc = rec.encode().unwrap();
        assert_eq!(enc.len(), MAX_PAYLOAD);
        assert_eq!(enc[..9], [3, 1, 2, 3, 4, 5, 6, 7, 8]);
        let dec = Record::decode(&enc).unwrap();
        assert_eq!(dec, rec);
        assert_eq!(dec.plaintext_len(), MAX_RECORD_PLAINTEXT);

        let too_big = vec![0; MAX_RECORD_PLAINTEXT + TAG_LEN + 1];
        assert_eq!(
            Record {
                seq: 0,
                sealed: &too_big
            }
            .encode(),
            Err(MessageError::RecordTooLarge(MAX_PAYLOAD + 1))
        );
        assert_eq!(
            Record {
                seq: 0,
                sealed: &[0; 15]
            }
            .encode(),
            Err(MessageError::RecordTooShort(24))
        );
        assert_eq!(
            Record::decode(&enc[..24]),
            Err(MessageError::RecordTooShort(24))
        );
        // Smallest legal record: empty plaintext.
        let min = Record {
            seq: 7,
            sealed: &[0; TAG_LEN],
        }
        .encode()
        .unwrap();
        assert_eq!(min.len(), 25);
        assert_eq!(Record::decode(&min).unwrap().plaintext_len(), 0);
    }

    #[test]
    fn rejects_unknown_and_empty() {
        assert_eq!(Message::decode(&[]), Err(MessageError::Empty));
        assert_eq!(Message::decode(&[0x00]), Err(MessageError::UnknownType(0)));
        // The blueprint client's plaintext greeting is not an SGXRA message.
        assert_eq!(
            Message::decode(b"Hello, SGX server!"),
            Err(MessageError::UnknownType(b'H'))
        );
    }

    // --- key exchange ------------------------------------------------------

    struct Fixture {
        identity: IdentityKey,
        body: ReportBody,
        claims: VerifiedClaims,
    }

    fn fixture(seed: u8) -> Fixture {
        let identity = IdentityKey::generate(&mut TestRng::new(seed)).unwrap();
        let body = attested_body(&identity);
        // Test-only: the client treats this body as verified.
        let claims = VerifiedClaims::new(body, TcbStatus::UpToDate, Vec::new());
        Fixture {
            identity,
            body,
            claims,
        }
    }

    /// Runs the handshake through encoded bytes, as on the wire.
    fn handshake(f: &Fixture) -> (Session, Session) {
        let mut crng = TestRng::new(100);
        let mut erng = TestRng::new(200);
        let (client, hello) = ClientHandshake::start(&f.claims, &mut crng).unwrap();
        let hello = Hello::decode(&hello.encode()).unwrap();
        let (reply, enclave) = respond(&f.identity, &f.body, &hello, &mut erng).unwrap();
        let client = client.finish_payload(&reply.encode()).unwrap();
        (client, enclave)
    }

    #[test]
    fn full_handshake_and_records() {
        let f = fixture(1);
        let (mut client, mut enclave) = handshake(&f);
        assert_eq!(client.role(), Role::Client);
        assert_eq!(enclave.role(), Role::Enclave);
        for i in 0..4u8 {
            let req = client.seal(&[i; 100]).unwrap();
            assert_eq!(enclave.open(&req).unwrap(), [i; 100]);
            let resp = enclave.seal(&[i ^ 0xff; 50]).unwrap();
            assert_eq!(client.open(&resp).unwrap(), [i ^ 0xff; 50]);
        }
    }

    #[test]
    fn handshake_is_deterministic_given_randomness_and_fresh_otherwise() {
        let f = fixture(1);
        let (mut c1, _) = handshake(&f);
        let (mut c2, _) = handshake(&f);
        assert_eq!(c1.seal(b"x").unwrap(), c2.seal(b"x").unwrap());

        // A different client ephemeral yields unrelated keys.
        let (client, hello) = ClientHandshake::start(&f.claims, &mut TestRng::new(101)).unwrap();
        let (reply, _) = respond(&f.identity, &f.body, &hello, &mut TestRng::new(200)).unwrap();
        let mut c3 = client.finish(&reply).unwrap();
        assert_ne!(c1.seal(b"x").unwrap(), c3.seal(b"x").unwrap());
    }

    #[test]
    fn identity_key_roundtrips_through_secret_bytes() {
        let f = fixture(3);
        let restored = IdentityKey::from_secret_bytes(f.identity.secret_bytes());
        assert_eq!(restored.public_key(), f.identity.public_key());
        assert_eq!(restored.report_data(), f.identity.report_data());
        // Debug output never contains the secret.
        let dbg = alloc::format!("{:?}", f.identity);
        let secret_hex = alloc::format!("{}", Hex(&*f.identity.secret_bytes()));
        assert!(!dbg.contains(&secret_hex));
    }

    #[test]
    fn wrong_report_data_binding_is_rejected() {
        // An impostor (e.g. the operator) answers with its own key while the
        // client holds a genuine quote for the real enclave.
        let f = fixture(1);
        let impostor = IdentityKey::generate(&mut TestRng::new(66)).unwrap();
        let impostor_body = attested_body(&impostor);

        let (client, hello) = ClientHandshake::start(&f.claims, &mut TestRng::new(100)).unwrap();
        let (reply, _) =
            respond(&impostor, &impostor_body, &hello, &mut TestRng::new(200)).unwrap();
        assert_eq!(
            client.finish(&reply).unwrap_err(),
            HandshakeError::Binding(BindingError)
        );

        // A quote whose report_data commits to nothing useful (the
        // blueprint enclave's constant value).
        let blueprint = *crate::sgx::Quote::parse(crate::testutil::QUOTE_V3)
            .unwrap()
            .report_body();
        let claims = VerifiedClaims::new(blueprint, TcbStatus::UpToDate, Vec::new());
        let (client, hello) = ClientHandshake::start(&claims, &mut TestRng::new(100)).unwrap();
        let (reply, _) = respond(&f.identity, &f.body, &hello, &mut TestRng::new(200)).unwrap();
        assert_eq!(
            client.finish(&reply).unwrap_err(),
            HandshakeError::Binding(BindingError)
        );

        // Reserved bytes 32..64 of report_data must be zero.
        let mut raw = *f.body.as_bytes();
        raw[383] = 1;
        let claims =
            VerifiedClaims::new(ReportBody::from_array(raw), TcbStatus::UpToDate, Vec::new());
        let (client, hello) = ClientHandshake::start(&claims, &mut TestRng::new(100)).unwrap();
        let (reply, _) = respond(&f.identity, &f.body, &hello, &mut TestRng::new(200)).unwrap();
        assert_eq!(
            client.finish(&reply).unwrap_err(),
            HandshakeError::Binding(BindingError)
        );
    }

    #[test]
    fn enclave_refuses_report_that_does_not_commit_to_its_key() {
        let f = fixture(1);
        let other = fixture(2);
        let (_, hello) = ClientHandshake::start(&f.claims, &mut TestRng::new(100)).unwrap();
        assert_eq!(
            respond(&f.identity, &other.body, &hello, &mut TestRng::new(200)).unwrap_err(),
            HandshakeError::IdentityNotAttested
        );
    }

    #[test]
    fn replayed_identity_without_secret_fails_confirmation() {
        // The operator replays the genuine ek_pub (it is public) but does not
        // hold ek_sk: it can only use its own secret for the static DH.
        let f = fixture(1);
        let (client, hello) = ClientHandshake::start(&f.claims, &mut TestRng::new(100)).unwrap();
        let attacker = IdentityKey::generate(&mut TestRng::new(66)).unwrap();
        let (mut reply, _) = respond(
            &attacker,
            &attested_body(&attacker),
            &hello,
            &mut TestRng::new(200),
        )
        .unwrap();
        reply.identity_public = *f.identity.public_key();
        assert_eq!(
            client.finish(&reply).unwrap_err(),
            HandshakeError::ConfirmationFailed
        );
    }

    #[test]
    fn tampered_handshake_fails_confirmation() {
        let f = fixture(1);
        // Every byte of se_pub, s_nonce and confirm is covered.
        for (lo, hi) in [(34usize, 66usize), (66, 98), (98, 130)] {
            for pos in [lo, hi - 1] {
                let (client, hello) =
                    ClientHandshake::start(&f.claims, &mut TestRng::new(100)).unwrap();
                let (reply, _) =
                    respond(&f.identity, &f.body, &hello, &mut TestRng::new(200)).unwrap();
                let mut bytes = reply.encode();
                bytes[pos] ^= 0x01;
                let err = client.finish_payload(&bytes).unwrap_err();
                // A flipped bit in se_pub may (rarely) map to a low-order
                // point; either way the handshake fails.
                assert!(
                    matches!(
                        err,
                        HandshakeError::ConfirmationFailed | HandshakeError::NonContributory
                    ),
                    "pos {pos}: {err:?}"
                );
            }
        }

        // A modified HELLO (c_nonce) changes the enclave's transcript.
        let (client, mut hello) =
            ClientHandshake::start(&f.claims, &mut TestRng::new(100)).unwrap();
        hello.client_nonce[0] ^= 1;
        let (reply, _) = respond(&f.identity, &f.body, &hello, &mut TestRng::new(200)).unwrap();
        assert_eq!(
            client.finish(&reply).unwrap_err(),
            HandshakeError::ConfirmationFailed
        );

        // Malformed reply bytes.
        let (client, _) = ClientHandshake::start(&f.claims, &mut TestRng::new(100)).unwrap();
        assert!(matches!(
            client.finish_payload(&[0x02, 0x01, 0x00]),
            Err(HandshakeError::Message(MessageError::InvalidLength { .. }))
        ));
    }

    #[test]
    fn transcript_binds_the_attested_report_body() {
        // The client verified a report body that differs from the one the
        // enclave answers for (same key, so the binding check passes; e.g. a
        // different SVN or attributes in a replayed quote). Keys diverge.
        let f = fixture(1);
        let mut raw = *f.body.as_bytes();
        raw[258] ^= 1; // isv_svn
        let claims =
            VerifiedClaims::new(ReportBody::from_array(raw), TcbStatus::UpToDate, Vec::new());
        let (client, hello) = ClientHandshake::start(&claims, &mut TestRng::new(100)).unwrap();
        let (reply, _) = respond(&f.identity, &f.body, &hello, &mut TestRng::new(200)).unwrap();
        assert_eq!(
            client.finish(&reply).unwrap_err(),
            HandshakeError::ConfirmationFailed
        );
    }

    #[test]
    fn low_order_keys_are_rejected() {
        let f = fixture(1);
        // Identity (u = 0) and u = 1 are low-order points.
        for bad in [[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }] {
            let hello = Hello {
                client_public: bad,
                client_nonce: [0; 32],
            };
            assert_eq!(
                respond(&f.identity, &f.body, &hello, &mut TestRng::new(200)).unwrap_err(),
                HandshakeError::NonContributory
            );

            let (client, hello) =
                ClientHandshake::start(&f.claims, &mut TestRng::new(100)).unwrap();
            let (mut reply, _) =
                respond(&f.identity, &f.body, &hello, &mut TestRng::new(200)).unwrap();
            reply.ephemeral_public = bad;
            assert_eq!(
                client.finish(&reply).unwrap_err(),
                HandshakeError::NonContributory
            );
        }
    }

    #[test]
    fn rng_failure_is_reported() {
        let f = fixture(1);
        assert_eq!(
            ClientHandshake::start(&f.claims, &mut FailingRng).unwrap_err(),
            HandshakeError::Rng(RngError { code: 0x1234 })
        );
        assert!(IdentityKey::generate(&mut FailingRng).is_err());
        let (_, hello) = ClientHandshake::start(&f.claims, &mut TestRng::new(100)).unwrap();
        assert!(matches!(
            respond(&f.identity, &f.body, &hello, &mut FailingRng),
            Err(HandshakeError::Rng(_))
        ));
    }
}
