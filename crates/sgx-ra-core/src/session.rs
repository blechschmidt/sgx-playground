//! The SGXRA v1 protocol endpoints, independent of any transport.
//!
//! * [`EnclaveEndpoint`]: the enclave's protocol state machine. It is fed
//!   one inbound payload at a time (what `enclave_message` receives) and
//!   returns the outbound payload. It enforces the message order
//!   `HELLO` → `RECORD`*, and it wipes the session on any error.
//! * [`ClientChannel`]: the client's [`SecureChannel`] over any
//!   [`MessageTransport`]. It can only be opened from [`VerifiedClaims`].
//!
//! The executor protocol is strict request/response lockstep (PROTOCOL Q8),
//! so every client message gets exactly one reply.

use alloc::vec::Vec;
use core::fmt;

use crate::attestation::VerifiedClaims;
use crate::channel::{AttestedChannel, SecureChannel};
use crate::handshake::{
    self, ClientHandshake, HandshakeError, Hello, IdentityKey, MAX_RECORD_PLAINTEXT, MessageError,
    MessageType,
};
use crate::record::{RecordError, Session};
use crate::rng::Rng;
use crate::sgx::ReportBody;

/// Moves whole SGXRA messages (layer-1 payloads) to and from the peer.
///
/// The client implements it on top of the executor framing
/// ([`crate::wire`]); tests implement it in memory.
pub trait MessageTransport {
    /// Transport error type.
    type Error: fmt::Debug + fmt::Display;

    /// Sends one message.
    fn send(&mut self, message: &[u8]) -> Result<(), Self::Error>;

    /// Receives one message.
    fn recv(&mut self) -> Result<Vec<u8>, Self::Error>;
}

impl<T: MessageTransport + ?Sized> MessageTransport for &mut T {
    type Error = T::Error;

    fn send(&mut self, message: &[u8]) -> Result<(), Self::Error> {
        (**self).send(message)
    }

    fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        (**self).recv()
    }
}

// ---------------------------------------------------------------------------
// Enclave side
// ---------------------------------------------------------------------------

/// Why the enclave endpoint refused a message. These details stay inside
/// the enclave; the host only learns that the call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointError<E> {
    /// The payload is not a valid SGXRA message.
    Message(MessageError),
    /// A message arrived that is not allowed in the current state.
    UnexpectedMessage(MessageType),
    /// No report was created yet, so there is no attested key to answer for.
    NotAttested,
    /// A `HELLO` after a handshake already took place in this instance.
    HandshakeAlreadyDone,
    /// The handshake failed.
    Handshake(HandshakeError),
    /// A record could not be opened or sealed.
    Record(RecordError),
    /// The application rejected the request.
    App(E),
}

impl<E: fmt::Display> fmt::Display for EndpointError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(e) => e.fmt(f),
            Self::UnexpectedMessage(t) => write!(f, "unexpected {t:?} message"),
            Self::NotAttested => f.write_str("HELLO before the enclave report was created"),
            Self::HandshakeAlreadyDone => f.write_str("only one handshake per enclave instance"),
            Self::Handshake(e) => e.fmt(f),
            Self::Record(e) => e.fmt(f),
            Self::App(e) => write!(f, "application error: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> core::error::Error for EndpointError<E> {}

enum EndpointState {
    /// Waiting for the single `HELLO`.
    AwaitingHello,
    /// Session established.
    Established(Session),
    /// The handshake happened; the session has since failed or closed.
    Closed,
}

/// The enclave's protocol state machine.
///
/// Lifecycle: [`EnclaveEndpoint::new`] with the identity key, then
/// [`EnclaveEndpoint::set_report_body`] once the enclave has created the
/// report for its quote, then [`EnclaveEndpoint::handle`] per inbound
/// message. Only one handshake is accepted per endpoint, so a host cannot
/// make one enclave instance serve several (possibly interleaved) sessions.
pub struct EnclaveEndpoint {
    identity: IdentityKey,
    report_body: Option<ReportBody>,
    state: EndpointState,
}

impl EnclaveEndpoint {
    /// Creates an endpoint for `identity`.
    pub fn new(identity: IdentityKey) -> Self {
        Self {
            identity,
            report_body: None,
            state: EndpointState::AwaitingHello,
        }
    }

    /// The identity key (its [`IdentityKey::report_data`] goes into the
    /// report).
    pub fn identity(&self) -> &IdentityKey {
        &self.identity
    }

    /// Records the body of the report the enclave created. It must commit
    /// to the identity key; otherwise the endpoint fails closed at `HELLO`.
    pub fn set_report_body(&mut self, report_body: ReportBody) {
        self.report_body = Some(report_body);
    }

    /// Whether a session is currently established.
    pub fn is_established(&self) -> bool {
        matches!(self.state, EndpointState::Established(_))
    }

    /// Processes one inbound message and returns the reply payload.
    ///
    /// `app` maps a decrypted request to a response plaintext (at most
    /// [`MAX_RECORD_PLAINTEXT`] bytes). Any error, including one from
    /// `app`, ends the session permanently and wipes its keys.
    pub fn handle<E>(
        &mut self,
        message: &[u8],
        rng: &mut impl Rng,
        app: impl FnOnce(&[u8], &mut Vec<u8>) -> Result<(), E>,
    ) -> Result<Vec<u8>, EndpointError<E>> {
        let result = self.handle_inner(message, rng, app);
        if result.is_err() && !matches!(self.state, EndpointState::AwaitingHello) {
            // Dropping the session zeroizes its keys.
            self.state = EndpointState::Closed;
        }
        result
    }

    fn handle_inner<E>(
        &mut self,
        message: &[u8],
        rng: &mut impl Rng,
        app: impl FnOnce(&[u8], &mut Vec<u8>) -> Result<(), E>,
    ) -> Result<Vec<u8>, EndpointError<E>> {
        let &type_byte = message
            .first()
            .ok_or(EndpointError::Message(MessageError::Empty))?;
        let message_type = MessageType::from_byte(type_byte)
            .ok_or(EndpointError::Message(MessageError::UnknownType(type_byte)))?;

        match (message_type, &mut self.state) {
            (MessageType::Hello, EndpointState::AwaitingHello) => {
                let hello = Hello::decode(message).map_err(EndpointError::Message)?;
                let report_body = self
                    .report_body
                    .as_ref()
                    .ok_or(EndpointError::NotAttested)?;
                // From here on this instance has used up its handshake, even
                // if the handshake fails.
                self.state = EndpointState::Closed;
                let (reply, session) = handshake::respond(&self.identity, report_body, &hello, rng)
                    .map_err(EndpointError::Handshake)?;
                self.state = EndpointState::Established(session);
                Ok(reply.encode().to_vec())
            }
            (MessageType::Hello, _) => Err(EndpointError::HandshakeAlreadyDone),
            (MessageType::Record, EndpointState::Established(session)) => {
                let request = session.open(message).map_err(EndpointError::Record)?;
                let mut response = Vec::new();
                app(&request, &mut response).map_err(EndpointError::App)?;
                session.seal(&response).map_err(EndpointError::Record)
            }
            (MessageType::Record, EndpointState::Closed) => {
                Err(EndpointError::Record(RecordError::SessionFailed))
            }
            (other, _) => Err(EndpointError::UnexpectedMessage(other)),
        }
    }
}

impl fmt::Debug for EnclaveEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.state {
            EndpointState::AwaitingHello => "awaiting-hello",
            EndpointState::Established(_) => "established",
            EndpointState::Closed => "closed",
        };
        f.debug_struct("EnclaveEndpoint")
            .field("identity", &self.identity)
            .field("attested", &self.report_body.is_some())
            .field("state", &state)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Errors of a [`ClientChannel`].
#[derive(Debug)]
pub enum ChannelError<T> {
    /// The transport failed.
    Transport(T),
    /// The handshake failed; the enclave is not trusted.
    Handshake(HandshakeError),
    /// A record was rejected, or the channel already failed.
    Record(RecordError),
}

impl<T: fmt::Display> fmt::Display for ChannelError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Handshake(e) => e.fmt(f),
            Self::Record(e) => e.fmt(f),
        }
    }
}

impl<T: fmt::Debug + fmt::Display> core::error::Error for ChannelError<T> {}

/// The client end of an attested channel.
pub struct ClientChannel<T: MessageTransport> {
    transport: T,
    session: Session,
    claims: VerifiedClaims,
}

impl<T: MessageTransport> ClientChannel<T> {
    /// Runs the handshake over `transport` against the enclave described by
    /// `claims` (the verified, policy-accepted quote received from the same
    /// connection).
    pub fn connect(
        mut transport: T,
        claims: VerifiedClaims,
        rng: &mut impl Rng,
    ) -> Result<Self, ChannelError<T::Error>> {
        let (handshake, hello) =
            ClientHandshake::start(&claims, rng).map_err(ChannelError::Handshake)?;
        transport
            .send(&hello.encode())
            .map_err(ChannelError::Transport)?;
        let reply = transport.recv().map_err(ChannelError::Transport)?;
        let session = handshake
            .finish_payload(&reply)
            .map_err(ChannelError::Handshake)?;
        Ok(Self {
            transport,
            session,
            claims,
        })
    }

    /// Wipes the session keys and returns the transport.
    pub fn into_transport(mut self) -> T {
        self.session.close();
        self.transport
    }
}

impl<T: MessageTransport> SecureChannel for ClientChannel<T> {
    type Error = ChannelError<T::Error>;

    fn max_message_len(&self) -> usize {
        MAX_RECORD_PLAINTEXT
    }

    fn send(&mut self, plaintext: &[u8]) -> Result<(), Self::Error> {
        let record = self.session.seal(plaintext).map_err(ChannelError::Record)?;
        let sent = self.transport.send(&record);
        if sent.is_err() {
            // The record may or may not have reached the enclave; the
            // sequence numbers can no longer be trusted to agree.
            self.session.close();
        }
        sent.map_err(ChannelError::Transport)
    }

    fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        if self.session.is_failed() {
            return Err(ChannelError::Record(RecordError::SessionFailed));
        }
        let payload = match self.transport.recv() {
            Ok(p) => p,
            Err(e) => {
                self.session.close();
                return Err(ChannelError::Transport(e));
            }
        };
        self.session.open(&payload).map_err(ChannelError::Record)
    }
}

impl<T: MessageTransport> AttestedChannel for ClientChannel<T> {
    fn peer_claims(&self) -> &VerifiedClaims {
        &self.claims
    }
}

impl<T: MessageTransport> fmt::Debug for ClientChannel<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientChannel")
            .field("session", &self.session)
            .field("mr_enclave", &self.claims.identity().mr_enclave)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::TcbStatus;
    use crate::handshake::{HelloReply, MessageType};
    use crate::record::Role;
    use crate::testutil::{TestRng, attested_body};
    use crate::wire::MAX_PAYLOAD;
    use alloc::collections::VecDeque;

    #[derive(Debug, PartialEq, Eq)]
    enum HostError {
        /// Layer-1 status 0x02: the ECALL failed.
        EnclaveFailure,
        NoReply,
    }

    impl fmt::Display for HostError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(self, f)
        }
    }

    type Tamper = fn(&mut Vec<u8>);

    /// An in-memory untrusted host: delivers each client message to the
    /// enclave endpoint (as `enclave_message` would), optionally tampering
    /// with traffic in either direction.
    struct Host {
        endpoint: EnclaveEndpoint,
        rng: TestRng,
        replies: VecDeque<Result<Vec<u8>, HostError>>,
        log: Vec<Vec<u8>>,
        to_enclave: Option<Tamper>,
        to_client: Option<Tamper>,
    }

    impl Host {
        fn new() -> (Self, VerifiedClaims) {
            let identity = IdentityKey::generate(&mut TestRng::new(1)).unwrap();
            let body = attested_body(&identity);
            let mut endpoint = EnclaveEndpoint::new(identity);
            endpoint.set_report_body(body);
            let claims = VerifiedClaims::new(body, TcbStatus::UpToDate, Vec::new());
            let host = Self {
                endpoint,
                rng: TestRng::new(2),
                replies: VecDeque::new(),
                log: Vec::new(),
                to_enclave: None,
                to_client: None,
            };
            (host, claims)
        }

        fn deliver(&mut self, message: &[u8]) -> Result<Vec<u8>, HostError> {
            self.endpoint
                .handle(message, &mut self.rng, |req: &[u8], resp: &mut Vec<u8>| {
                    if req == b"fail" {
                        return Err("app refused");
                    }
                    resp.extend_from_slice(b"echo:");
                    resp.extend_from_slice(req);
                    Ok(())
                })
                .map_err(|_| HostError::EnclaveFailure)
        }
    }

    impl MessageTransport for Host {
        type Error = HostError;

        fn send(&mut self, message: &[u8]) -> Result<(), HostError> {
            // Layer-1 limits (PROTOCOL Q1-Q3) hold for every client message.
            assert!(!message.is_empty() && message.len() <= MAX_PAYLOAD);
            let mut message = message.to_vec();
            if let Some(t) = self.to_enclave {
                t(&mut message);
            }
            self.log.push(message.clone());
            let mut reply = self.deliver(&message);
            if let (Ok(r), Some(t)) = (&mut reply, self.to_client) {
                t(r);
            }
            self.replies.push_back(reply);
            Ok(())
        }

        fn recv(&mut self) -> Result<Vec<u8>, HostError> {
            self.replies.pop_front().unwrap_or(Err(HostError::NoReply))
        }
    }

    #[test]
    fn full_in_memory_session() {
        let (mut host, claims) = Host::new();
        let mut channel =
            ClientChannel::connect(&mut host, claims.clone(), &mut TestRng::new(3)).unwrap();
        assert_eq!(channel.peer_claims(), &claims);
        assert_eq!(channel.max_message_len(), 4071);
        for msg in [&b"hello"[..], b"", &[0xab; 4066]] {
            let reply = channel.request(msg).unwrap();
            assert_eq!(&reply[..5], b"echo:");
            assert_eq!(&reply[5..], msg);
        }
        drop(channel);

        // The untrusted host saw only HELLO and ciphertext.
        assert_eq!(host.log[0][0], MessageType::Hello as u8);
        for rec in &host.log[1..] {
            assert_eq!(rec[0], MessageType::Record as u8);
            assert!(!rec.windows(5).any(|w| w == b"hello"));
        }
        assert!(host.endpoint.is_established());
    }

    #[test]
    fn oversize_response_ends_session() {
        let (mut host, claims) = Host::new();
        let mut channel = ClientChannel::connect(&mut host, claims, &mut TestRng::new(3)).unwrap();
        // 4071-byte request → 4076-byte response, which does not fit.
        assert!(matches!(
            channel.request(&[0; MAX_RECORD_PLAINTEXT]),
            Err(ChannelError::Transport(HostError::EnclaveFailure))
        ));
        assert!(matches!(
            channel.request(b"again"),
            Err(ChannelError::Record(RecordError::SessionFailed))
        ));
    }

    #[test]
    fn app_error_ends_session() {
        let (mut host, claims) = Host::new();
        let mut channel = ClientChannel::connect(&mut host, claims, &mut TestRng::new(3)).unwrap();
        assert!(channel.request(b"fail").is_err());
        drop(channel);
        assert!(!host.endpoint.is_established());
        // Even a correctly formed next record is refused.
        assert_eq!(host.deliver(&[3; 25]), Err(HostError::EnclaveFailure));
    }

    #[test]
    fn tampered_request_kills_enclave_session() {
        let (mut host, claims) = Host::new();
        host.to_enclave = Some(|m| {
            if m[0] == MessageType::Record as u8 {
                let last = m.len() - 1;
                m[last] ^= 1;
            }
        });
        let mut channel = ClientChannel::connect(&mut host, claims, &mut TestRng::new(3)).unwrap();
        assert!(matches!(
            channel.request(b"hi"),
            Err(ChannelError::Transport(HostError::EnclaveFailure))
        ));
    }

    #[test]
    fn tampered_response_is_rejected_by_client() {
        let (mut host, claims) = Host::new();
        host.to_client = Some(|m| {
            if m[0] == MessageType::Record as u8 {
                m[12] ^= 0x80;
            }
        });
        let mut channel = ClientChannel::connect(&mut host, claims, &mut TestRng::new(3)).unwrap();
        assert!(matches!(
            channel.request(b"hi"),
            Err(ChannelError::Record(RecordError::Decryption))
        ));
        assert!(matches!(
            channel.request(b"hi"),
            Err(ChannelError::Record(RecordError::SessionFailed))
        ));
    }

    #[test]
    fn mitm_host_cannot_substitute_its_own_enclave_key() {
        // The host terminates the handshake itself with a key it controls
        // and forwards a genuine quote.
        let (mut host, claims) = Host::new();
        host.to_client = Some(|m| {
            if m[0] == MessageType::HelloReply as u8 {
                let mut reply = HelloReply::decode(m).unwrap();
                reply.identity_public = [9; 32];
                m.copy_from_slice(&reply.encode());
            }
        });
        let err = ClientChannel::connect(&mut host, claims, &mut TestRng::new(3)).unwrap_err();
        assert!(matches!(
            err,
            ChannelError::Handshake(HandshakeError::Binding(_))
        ));
    }

    #[test]
    fn enclave_enforces_message_order_and_single_handshake() {
        let (mut host, claims) = Host::new();
        let (_, hello) = ClientHandshake::start(&claims, &mut TestRng::new(3)).unwrap();

        // RECORD before HELLO, unknown and empty messages: refused, and the
        // endpoint still waits for HELLO.
        assert!(host.deliver(&[3; 25]).is_err());
        assert!(host.deliver(&[0x7f]).is_err());
        assert!(host.deliver(&[]).is_err());
        assert!(host.deliver(&[2; handshake::HELLO_REPLY_LEN]).is_err());
        assert!(!host.endpoint.is_established());

        let reply = host.deliver(&hello.encode()).unwrap();
        assert_eq!(reply.len(), handshake::HELLO_REPLY_LEN);
        assert!(host.endpoint.is_established());

        // A second HELLO is refused and ends the session.
        assert!(host.deliver(&hello.encode()).is_err());
        assert!(!host.endpoint.is_established());
        assert!(host.deliver(&hello.encode()).is_err());
    }

    #[test]
    fn hello_before_report_is_refused() {
        let identity = IdentityKey::generate(&mut TestRng::new(1)).unwrap();
        let body = attested_body(&identity);
        let claims = VerifiedClaims::new(body, TcbStatus::UpToDate, Vec::new());
        let mut endpoint = EnclaveEndpoint::new(identity);
        let (_, hello) = ClientHandshake::start(&claims, &mut TestRng::new(3)).unwrap();
        let app = |_: &[u8], _: &mut Vec<u8>| Ok::<(), ()>(());
        assert_eq!(
            endpoint.handle(&hello.encode(), &mut TestRng::new(2), app),
            Err(EndpointError::NotAttested)
        );
        endpoint.set_report_body(body);
        assert!(
            endpoint
                .handle(&hello.encode(), &mut TestRng::new(2), app)
                .is_ok()
        );
    }

    #[test]
    fn sessions_from_endpoint_and_client_agree_on_roles() {
        let (mut host, claims) = Host::new();
        let channel = ClientChannel::connect(&mut host, claims, &mut TestRng::new(3)).unwrap();
        assert_eq!(channel.session.role(), Role::Client);
    }
}
