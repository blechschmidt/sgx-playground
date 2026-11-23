//! Example enclave: sealing and a persistent long-term identity
//! (`docs/SEALING.md`).
//!
//! Requests ([`sealing_protocol`]) over the attested channel:
//!
//! * IDENTITY: proves possession of the enclave's long-term identity key
//!   `LK` for a client challenge, bound to this session's attested `ek_pub`.
//!   `LK` is sealed (MRENCLAVE policy by default, MRSIGNER with the cargo
//!   feature `mrsigner-identity`) and kept by the host through the storage
//!   OCALLs, so it survives restarts and clients can pin it. It is loaded
//!   on the first IDENTITY request of an instance.
//! * SEAL: seals client data to this enclave's MRENCLAVE and returns the
//!   blob (the client keeps it; only this code on this CPU opens it).
//! * UNSEAL: opens such a blob.
//!
//! Link with `enclave-sys/sealed-storage/Enclave.edl`
//! (`enclave-sys/build.sh --crate sealing-enclave --edl …`, or the flake's
//! `sealing-enclave` package). Behind a host without the storage OCALLs
//! (the blueprint `app`) the identity is reported as ephemeral.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use sealing_protocol::{CLIENT_DATA_AAD, ErrorCode, MAX_SEAL_INPUT, Request, Response};
use sgx_ra_enclave::sealing::KeyPolicy;
use sgx_ra_enclave::sgx_ra_core::identity::IdentityAssertion;
use sgx_ra_enclave::{AppError, EnclaveApp, SessionContext};

/// Key policy of the long-term identity.
pub const IDENTITY_POLICY: KeyPolicy = if cfg!(feature = "mrsigner-identity") {
    KeyPolicy::MrSigner
} else {
    KeyPolicy::MrEnclave
};

/// The platform operations the application needs. The enclave uses
/// [`SgxBackend`]; host-side unit tests substitute a mock, since the SGX
/// runtime cannot be linked into a test binary.
pub trait Backend: Default + Send + 'static {
    /// Proves the long-term identity for `challenge` within the session
    /// whose channel key is `session_public`. `Err` if the identity is
    /// unavailable or the challenge is invalid.
    fn prove_identity(
        &mut self,
        session_public: &[u8; 32],
        challenge: &[u8; 32],
    ) -> Result<IdentityAssertion, ErrorCode>;

    /// Seals to MRENCLAVE.
    fn seal(&mut self, data: &[u8], additional_data: &[u8]) -> Option<Vec<u8>>;

    /// Unseals an MRENCLAVE blob: `(plaintext, additional data)`.
    fn unseal(&mut self, blob: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
}

/// The SGX backend: `sgx_ra_enclave::{identity, sealing}` with the host
/// storage OCALLs.
#[cfg(not(test))]
pub use sgx_backend::SgxBackend;

#[cfg(not(test))]
mod sgx_backend {
    use super::*;
    use sgx_ra_enclave::SgxRng;
    use sgx_ra_enclave::identity::{IdentityConfig, IdentityError, LongTermIdentity};
    use sgx_ra_enclave::sealing;
    use sgx_ra_enclave::storage::OcallStorage;

    /// Where the long-term identity is sealed.
    const IDENTITY_CONFIG: IdentityConfig = IdentityConfig::new(IDENTITY_POLICY);

    /// See [`Backend`].
    #[derive(Debug, Default)]
    pub struct SgxBackend {
        /// Loaded on first use. A failure is kept for the rest of the
        /// instance: fail closed rather than retry into a different key.
        identity: Option<Result<LongTermIdentity, IdentityError>>,
    }

    impl Backend for SgxBackend {
        fn prove_identity(
            &mut self,
            session_public: &[u8; 32],
            challenge: &[u8; 32],
        ) -> Result<IdentityAssertion, ErrorCode> {
            let identity = self.identity.get_or_insert_with(|| {
                LongTermIdentity::load_or_create(IDENTITY_CONFIG, &mut OcallStorage, &mut SgxRng)
            });
            let identity = identity
                .as_ref()
                .map_err(|_| ErrorCode::IdentityUnavailable)?;
            // Fails only for a low-order challenge key.
            identity
                .prove(session_public, challenge)
                .map_err(|_| ErrorCode::BadRequest)
        }

        fn seal(&mut self, data: &[u8], additional_data: &[u8]) -> Option<Vec<u8>> {
            sealing::seal(data, additional_data).ok()
        }

        fn unseal(&mut self, blob: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
            let u = sealing::unseal(blob).ok()?;
            Some((u.plaintext.to_vec(), u.additional_data))
        }
    }
}

/// The sealing application.
#[derive(Debug, Default)]
pub struct SealingApp<B> {
    backend: B,
}

impl<B: Backend> SealingApp<B> {
    fn dispatch(&mut self, context: &SessionContext, request: &[u8]) -> Response {
        match Request::decode(request) {
            Ok(Request::Identity(challenge)) => {
                match self
                    .backend
                    .prove_identity(context.identity_public_key(), &challenge)
                {
                    Ok(assertion) => Response::Identity(assertion),
                    Err(code) => Response::Error(code),
                }
            }
            Ok(Request::Seal(data)) if data.len() <= MAX_SEAL_INPUT => {
                match self.backend.seal(data, CLIENT_DATA_AAD) {
                    Some(blob) => Response::Sealed(blob),
                    None => Response::Error(ErrorCode::SealFailed),
                }
            }
            Ok(Request::Seal(_)) => Response::Error(ErrorCode::SealFailed),
            // Only client-data blobs: never hand out the plaintext of a
            // blob sealed for another purpose (such as the identity key).
            Ok(Request::Unseal(blob)) => match self.backend.unseal(blob) {
                Some((plaintext, aad)) if aad == CLIENT_DATA_AAD => Response::Unsealed(plaintext),
                _ => Response::Error(ErrorCode::UnsealFailed),
            },
            Err(code) => Response::Error(code),
        }
    }
}

impl<B: Backend> EnclaveApp for SealingApp<B> {
    fn init() -> Self {
        Self::default()
    }

    fn handle(&mut self, _request: &[u8], _response: &mut Vec<u8>) -> Result<(), AppError> {
        // The framework always calls `handle_with_context`.
        Err(AppError::new("sealing-enclave needs the session context"))
    }

    fn handle_with_context(
        &mut self,
        context: &SessionContext,
        request: &[u8],
        response: &mut Vec<u8>,
    ) -> Result<(), AppError> {
        self.dispatch(context, request).encode_into(response);
        Ok(())
    }
}

#[cfg(not(test))]
sgx_ra_enclave::export_enclave!(SealingApp<SgxBackend>);

#[cfg(test)]
mod tests {
    use super::*;
    use sgx_ra_enclave::sgx_ra_core::identity::IdentityOrigin;

    /// "Seals" by prefixing a marker; records the session key it saw.
    #[derive(Debug, Default)]
    struct Mock {
        identity_unavailable: bool,
        seen_session: Option<[u8; 32]>,
    }

    impl Backend for Mock {
        fn prove_identity(
            &mut self,
            session_public: &[u8; 32],
            challenge: &[u8; 32],
        ) -> Result<IdentityAssertion, ErrorCode> {
            self.seen_session = Some(*session_public);
            if self.identity_unavailable {
                return Err(ErrorCode::IdentityUnavailable);
            }
            Ok(IdentityAssertion {
                origin: IdentityOrigin::Restored,
                policy: IDENTITY_POLICY,
                public_key: *challenge,
                proof: [0; 32],
            })
        }

        fn seal(&mut self, data: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
            let mut blob = alloc::vec![aad.len() as u8];
            blob.extend_from_slice(aad);
            blob.extend_from_slice(data);
            Some(blob)
        }

        fn unseal(&mut self, blob: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
            let (&n, rest) = blob.split_first()?;
            let (aad, data) = rest.split_at_checked(n as usize)?;
            Some((data.to_vec(), aad.to_vec()))
        }
    }

    fn call(app: &mut SealingApp<Mock>, request: &[u8]) -> Response {
        let mut out = Vec::new();
        app.handle_with_context(&SessionContext::new([9; 32]), request, &mut out)
            .unwrap();
        Response::decode(&out).unwrap()
    }

    #[test]
    fn malformed_requests_get_an_error_reply() {
        let mut app = SealingApp::<Mock>::init();
        for bad in [&[][..], &[0x01, 0], &[0x02], &[0x03], &[0x42, 1]] {
            assert_eq!(call(&mut app, bad), Response::Error(ErrorCode::BadRequest));
        }
    }

    #[test]
    fn identity_is_bound_to_the_session() {
        let mut app = SealingApp::<Mock>::init();
        let mut request = alloc::vec![0x01];
        request.extend_from_slice(&[5; 32]);
        let Response::Identity(a) = call(&mut app, &request) else {
            panic!("expected an identity")
        };
        assert_eq!(a.public_key, [5; 32]);
        assert_eq!(app.backend.seen_session, Some([9; 32]));
        app.backend.identity_unavailable = true;
        assert_eq!(
            call(&mut app, &request),
            Response::Error(ErrorCode::IdentityUnavailable)
        );
    }

    #[test]
    fn seal_unseal_and_purpose_binding() {
        let mut app = SealingApp::<Mock>::init();
        let Response::Sealed(blob) = call(&mut app, b"\x02secret") else {
            panic!("expected a blob")
        };
        let mut request = alloc::vec![0x03];
        request.extend_from_slice(&blob);
        assert_eq!(
            call(&mut app, &request),
            Response::Unsealed(b"secret".to_vec())
        );

        // A blob with other additional data (another purpose) is refused.
        let foreign = app.backend.seal(b"identity key", b"other").unwrap();
        let mut request = alloc::vec![0x03];
        request.extend_from_slice(&foreign);
        assert_eq!(
            call(&mut app, &request),
            Response::Error(ErrorCode::UnsealFailed)
        );
        assert_eq!(
            call(&mut app, b"\x03\xff"),
            Response::Error(ErrorCode::UnsealFailed)
        );
    }

    #[test]
    fn oversized_seal_is_refused_before_the_backend() {
        let mut app = SealingApp::<Mock>::init();
        let mut request = alloc::vec![0x02];
        request.resize(2 + MAX_SEAL_INPUT, 7);
        assert_eq!(
            call(&mut app, &request),
            Response::Error(ErrorCode::SealFailed)
        );
        request.pop();
        assert!(matches!(call(&mut app, &request), Response::Sealed(_)));
    }

    #[test]
    fn plain_handle_is_refused() {
        let mut out = Vec::new();
        assert!(SealingApp::<Mock>::init().handle(b"x", &mut out).is_err());
    }
}
