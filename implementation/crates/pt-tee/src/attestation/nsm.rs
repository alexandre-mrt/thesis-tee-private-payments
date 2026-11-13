//! Real attestation through the Nitro Secure Module (`/dev/nsm`), Linux only.
//!
//! This module is compiled only on Linux. It was compile-checked and
//! clippy-clean for `x86_64-unknown-linux-gnu` against
//! aws-nitro-enclaves-nsm-api 0.5.2 (`driver::{nsm_init, nsm_process_request,
//! nsm_exit}`, `api::{Request::Attestation, Response::Attestation,
//! Response::Error}`); it has not yet run against a real NSM device.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;

use super::{AttestationError, AttestationInputs, AttestationProvider};

const NSM_DEVICE: &str = "/dev/nsm";

/// Attestation provider backed by the NSM driver.
pub struct NsmProvider {
    fd: i32,
}

impl NsmProvider {
    /// Opens `/dev/nsm`. Fails outside a Nitro Enclave.
    pub fn open() -> Result<Self, AttestationError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(AttestationError::DeviceUnavailable(NSM_DEVICE.to_owned()));
        }
        Ok(Self { fd })
    }
}

impl Drop for NsmProvider {
    fn drop(&mut self) {
        nsm_exit(self.fd);
    }
}

impl AttestationProvider for NsmProvider {
    fn attest(&self, inputs: &AttestationInputs<'_>) -> Result<Vec<u8>, AttestationError> {
        let request = Request::Attestation {
            user_data: Some(ByteBuf::from(inputs.user_data.to_vec())),
            nonce: Some(ByteBuf::from(inputs.nonce.to_vec())),
            public_key: Some(ByteBuf::from(inputs.public_key.to_vec())),
        };
        match nsm_process_request(self.fd, request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(code) => Err(AttestationError::Nsm(format!("{code:?}"))),
            _ => Err(AttestationError::UnexpectedResponse),
        }
    }
}
