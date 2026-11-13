use std::sync::atomic::{AtomicU32, Ordering};

use pt_tee::attestation::AttestationVerifier;
use pt_tee::channel::{ClientChannel, PK_LEN};
use pt_tee::framing::{read_cbor_bounded, write_cbor};
use pt_tee::transport::{Endpoint, connect};
use serde::Serialize;
use tracing::debug;
use tv_core::{
    BankRequest, BankResponse, Bytes32, LogEntry, SealedBlob, encode_cbor, random_bytes32,
};

use crate::attest::{AttestationBundle, Trust, verify_bundle};
use crate::error::{ClientError, RETRY_COMMAND};
use crate::retry::with_backoff;

fn settles(request: &BankRequest) -> bool {
    matches!(
        request,
        BankRequest::Receive(_) | BankRequest::Enroll(_) | BankRequest::Refresh(_)
    )
}

pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub const LOG_PAGE: u64 = 256;

#[derive(Debug, Clone)]
pub struct Attested {
    pub bundle: AttestationBundle,
    pub channel_pk: [u8; PK_LEN],
}

pub struct BankClient {
    endpoint: Endpoint,
    verifier: AttestationVerifier,
}

impl BankClient {
    pub fn new(endpoint: Endpoint, trust: &Trust) -> Result<Self, ClientError> {
        let verifier = trust.verifier(&endpoint)?;
        Ok(Self { endpoint, verifier })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn verifier(&self) -> &AttestationVerifier {
        &self.verifier
    }

    async fn call_once(
        &self,
        request: &BankRequest,
        sent: &AtomicU32,
    ) -> Result<BankResponse, ClientError> {
        let mut stream = connect(&self.endpoint).await?;
        sent.fetch_add(1, Ordering::Relaxed);
        write_cbor(&mut stream, request).await?;
        Ok(read_cbor_bounded(&mut stream, MAX_RESPONSE_BYTES).await?)
    }

    pub async fn call(&self, request: &BankRequest) -> Result<BankResponse, ClientError> {
        let sent = AtomicU32::new(0);
        let response = with_backoff("bank", || self.call_once(request, &sent)).await?;
        let resent = sent.load(Ordering::Relaxed) > 1;
        Ok(match response {
            BankResponse::Refused if resent && settles(request) => {
                debug!("refused after a resend whose first answer was lost; reporting unavailable");
                BankResponse::Unavailable
            }
            other => other,
        })
    }

    pub async fn attest(&self, owner: &Bytes32) -> Result<Attested, ClientError> {
        let nonce = random_bytes32();
        let request = BankRequest::Attest {
            nonce,
            owner: *owner,
        };
        let (doc, manifest) = match self.call(&request).await? {
            BankResponse::Attestation { doc, manifest } => (doc, manifest),
            BankResponse::Unavailable => {
                return Err(ClientError::Unavailable {
                    retry: RETRY_COMMAND,
                });
            }
            BankResponse::Refused => return Err(ClientError::Refused),
            _ => return Err(ClientError::UnexpectedResponse { step: "attest" }),
        };
        let bundle = AttestationBundle {
            nonce,
            doc,
            manifest,
        };
        let channel_pk = verify_bundle(&self.verifier, &bundle)?;
        debug!(result_pk = %hex::encode(manifest.result_pk), "enclave attested");
        Ok(Attested { bundle, channel_pk })
    }

    pub async fn lookup(&self, serial: &Bytes32) -> Result<Option<LogEntry>, ClientError> {
        match self.call(&BankRequest::Lookup { serial: *serial }).await? {
            BankResponse::Entry(entry) => Ok(entry.map(|e| *e)),
            BankResponse::Refused => Err(ClientError::Refused),
            _ => Err(ClientError::UnexpectedResponse { step: "lookup" }),
        }
    }

    pub async fn log_range(&self, from: u64, limit: u64) -> Result<Vec<LogEntry>, ClientError> {
        match self.call(&BankRequest::LogRange { from, limit }).await? {
            BankResponse::Entries(entries) => Ok(entries),
            BankResponse::Refused => Err(ClientError::Refused),
            _ => Err(ClientError::UnexpectedResponse { step: "log-range" }),
        }
    }

    pub async fn full_log(&self) -> Result<Vec<LogEntry>, ClientError> {
        let mut all = Vec::new();
        loop {
            let page = self.log_range(all.len() as u64, LOG_PAGE).await?;
            let done = (page.len() as u64) < LOG_PAGE;
            all.extend(page);
            if done {
                return Ok(all);
            }
        }
    }
}

pub fn seal_to<T: Serialize>(
    channel_pk: &[u8; PK_LEN],
    secret: &T,
) -> Result<SealedBlob, ClientError> {
    let channel = ClientChannel::connect(channel_pk)?;
    let sealed = channel.seal_request(&encode_cbor(secret)?)?;
    Ok(SealedBlob {
        client_pk: channel.client_pk(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use pt_tee::framing::read_cbor;
    use pt_tee::transport::Listener;
    use tv_core::RefreshRequest;

    use super::*;

    fn refresh() -> BankRequest {
        BankRequest::Refresh(Box::new(RefreshRequest {
            channel_pk: [1u8; 32],
            pk: [2u8; 32],
            com_next: [3u8; 32],
            sig: tv_core::Signature([4u8; 64]),
            sealed: SealedBlob {
                client_pk: [5u8; 32],
                nonce: [6u8; 12],
                ciphertext: vec![],
            },
        }))
    }

    async fn refusing_bank(drop_first: usize) -> Endpoint {
        let listener = Listener::bind(&Endpoint::tcp("127.0.0.1:0").unwrap())
            .await
            .unwrap();
        let endpoint = listener.local_endpoint().unwrap();
        tokio::spawn(async move {
            for served in 0.. {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _: BankRequest = read_cbor(&mut stream).await.unwrap();
                if served >= drop_first {
                    write_cbor(&mut stream, &BankResponse::Refused)
                        .await
                        .unwrap();
                }
            }
        });
        endpoint
    }

    fn client(endpoint: Endpoint) -> BankClient {
        let trust = Trust {
            pcr0_hex: None,
            allow_mock: true,
        };
        BankClient::new(endpoint, &trust).unwrap()
    }

    #[tokio::test]
    async fn a_refusal_of_a_resent_operation_reads_as_unavailable() {
        let resent = client(refusing_bank(1).await);
        assert_eq!(
            resent.call(&refresh()).await.unwrap(),
            BankResponse::Unavailable
        );
        let lookup = BankRequest::Lookup { serial: [0u8; 32] };
        assert_eq!(
            client(refusing_bank(1).await).call(&lookup).await.unwrap(),
            BankResponse::Refused
        );
        let first_try = client(refusing_bank(0).await);
        assert_eq!(
            first_try.call(&refresh()).await.unwrap(),
            BankResponse::Refused
        );
    }
}
