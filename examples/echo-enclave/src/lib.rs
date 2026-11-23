//! Example enclave: replies to every request with the request itself.
//!
//! Built as a `no_std` staticlib and linked into `enclave.so` by
//! `enclave-sys/build.sh`; the framework handles attestation and the secure
//! channel, so the application logic is only [`EchoApp::handle`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use sgx_ra_enclave::{AppError, EnclaveApp};

/// The echo application.
#[derive(Debug, Default)]
pub struct EchoApp;

impl EnclaveApp for EchoApp {
    fn init() -> Self {
        Self
    }

    fn handle(&mut self, request: &[u8], response: &mut Vec<u8>) -> Result<(), AppError> {
        response.extend_from_slice(request);
        Ok(())
    }
}

sgx_ra_enclave::export_enclave!(EchoApp);

#[cfg(test)]
mod tests {
    use super::*;
    use sgx_ra_enclave::MAX_RESPONSE_LEN;

    #[test]
    fn echoes() {
        let mut app = EchoApp::init();
        let mut out = Vec::new();
        app.handle(b"Hello, SGX server!", &mut out).unwrap();
        assert_eq!(out, b"Hello, SGX server!");

        let big = vec![0x5a; MAX_RESPONSE_LEN];
        let mut out = Vec::new();
        app.handle(&big, &mut out).unwrap();
        assert_eq!(out, big);
    }
}
