use std::future::Future;
use std::time::Duration;

use pt_tee::channel::PK_LEN;
use pt_tee::framing::{read_cbor_bounded, write_cbor};
use pt_tee::transport::{Endpoint, connect};
use tv_core::{Bytes32, CheckOp, EnclaveRequest, EnclaveResponse};

use crate::error::LinkError;

pub const MAX_ENCLAVE_RESPONSE: usize = 64 * 1024;

pub const ENCLAVE_CALL_TIMEOUT: Duration = Duration::from_secs(10);

pub trait EnclaveLink: Send + Sync + 'static {
    fn attest(
        &self,
        nonce: Bytes32,
        owner: Option<Bytes32>,
    ) -> impl Future<Output = Result<EnclaveResponse, LinkError>> + Send;

    fn cancel(
        &self,
        channel_pk: [u8; PK_LEN],
    ) -> impl Future<Output = Result<EnclaveResponse, LinkError>> + Send;

    fn check(
        &self,
        bank_nonce: Bytes32,
        op: CheckOp,
    ) -> impl Future<Output = Result<EnclaveResponse, LinkError>> + Send;
}

#[derive(Debug, Clone)]
pub struct TcpLink {
    endpoint: Endpoint,
    call_timeout: Duration,
}

impl TcpLink {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            call_timeout: ENCLAVE_CALL_TIMEOUT,
        }
    }

    pub fn with_call_timeout(self, call_timeout: Duration) -> Self {
        Self {
            call_timeout,
            ..self
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    async fn call(&self, request: &EnclaveRequest) -> Result<EnclaveResponse, LinkError> {
        tokio::time::timeout(self.call_timeout, self.exchange(request))
            .await
            .map_err(|_| LinkError::TimedOut {
                after: self.call_timeout,
            })?
    }

    async fn exchange(&self, request: &EnclaveRequest) -> Result<EnclaveResponse, LinkError> {
        let mut stream = connect(&self.endpoint).await?;
        write_cbor(&mut stream, request).await?;
        Ok(read_cbor_bounded(&mut stream, MAX_ENCLAVE_RESPONSE).await?)
    }
}

impl EnclaveLink for TcpLink {
    async fn attest(
        &self,
        nonce: Bytes32,
        owner: Option<Bytes32>,
    ) -> Result<EnclaveResponse, LinkError> {
        self.call(&EnclaveRequest::Attest { nonce, owner }).await
    }

    async fn cancel(&self, channel_pk: [u8; PK_LEN]) -> Result<EnclaveResponse, LinkError> {
        self.call(&EnclaveRequest::Cancel { channel_pk }).await
    }

    async fn check(&self, bank_nonce: Bytes32, op: CheckOp) -> Result<EnclaveResponse, LinkError> {
        self.call(&EnclaveRequest::Check { bank_nonce, op }).await
    }
}
