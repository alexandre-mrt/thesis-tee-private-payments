use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use tv_bank::{EnclaveLink, LinkError};
use tv_core::{
    Bytes32, CheckOp, EnclaveResponse, EnclaveResult, SideKind, SigningKey, sign_result,
};
use tv_enclave::Enclave;

#[derive(Clone)]
pub enum Mode {
    Normal,
    Delay(Duration),
    DropNextAnswer,
    Lenient(SigningKey),
    LenientAfter(SigningKey, Duration),
    ForgeNonce(SigningKey),
    ForgeDigest(SigningKey),
}

struct Inner {
    enclave: RwLock<Arc<Enclave>>,
    mode: Mutex<Mode>,
}

#[derive(Clone)]
pub struct TestLink {
    inner: Arc<Inner>,
}

fn lenient(key: &SigningKey, bank_nonce: Bytes32, op: &CheckOp) -> EnclaveResponse {
    EnclaveResponse::Result(sign_result(
        key,
        bank_nonce,
        op.digest(),
        vec![SideKind::User; op.side_count()],
    ))
}

fn resign(
    key: &SigningKey,
    result: EnclaveResult,
    nonce: Bytes32,
    digest: Bytes32,
) -> EnclaveResponse {
    EnclaveResponse::Result(sign_result(key, nonce, digest, result.sides))
}

impl TestLink {
    pub fn new(enclave: Enclave) -> Self {
        Self {
            inner: Arc::new(Inner {
                enclave: RwLock::new(Arc::new(enclave)),
                mode: Mutex::new(Mode::Normal),
            }),
        }
    }

    pub fn enclave(&self) -> Arc<Enclave> {
        Arc::clone(
            &self
                .inner
                .enclave
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    pub fn replace(&self, enclave: Enclave) {
        *self
            .inner
            .enclave
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(enclave);
    }

    pub fn set_mode(&self, mode: Mode) {
        *self
            .inner
            .mode
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = mode;
    }

    fn take_mode(&self) -> Mode {
        let mut guard = self
            .inner
            .mode
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mode = guard.clone();
        if matches!(mode, Mode::DropNextAnswer) {
            *guard = Mode::Normal;
        }
        mode
    }
}

impl EnclaveLink for TestLink {
    async fn attest(
        &self,
        nonce: Bytes32,
        owner: Option<Bytes32>,
    ) -> Result<EnclaveResponse, LinkError> {
        Ok(self.enclave().attest(&nonce, owner))
    }

    async fn cancel(&self, channel_pk: [u8; 32]) -> Result<EnclaveResponse, LinkError> {
        Ok(self.enclave().cancel(&channel_pk))
    }

    async fn check(&self, bank_nonce: Bytes32, op: CheckOp) -> Result<EnclaveResponse, LinkError> {
        let enclave = self.enclave();
        match self.take_mode() {
            Mode::Normal => Ok(enclave.check(bank_nonce, &op)),
            Mode::Delay(delay) => {
                tokio::time::sleep(delay).await;
                Ok(enclave.check(bank_nonce, &op))
            }
            Mode::DropNextAnswer => {
                let _ = enclave.check(bank_nonce, &op);
                Err(LinkError::Unavailable(
                    "enclave crashed before answering".to_owned(),
                ))
            }
            Mode::Lenient(key) => Ok(lenient(&key, bank_nonce, &op)),
            Mode::LenientAfter(key, delay) => {
                tokio::time::sleep(delay).await;
                Ok(lenient(&key, bank_nonce, &op))
            }
            Mode::ForgeNonce(key) => match enclave.check(bank_nonce, &op) {
                EnclaveResponse::Result(result) => {
                    let mut other = bank_nonce;
                    other[0] ^= 0x01;
                    let digest = result.digest;
                    Ok(resign(&key, result, other, digest))
                }
                other => Ok(other),
            },
            Mode::ForgeDigest(key) => match enclave.check(bank_nonce, &op) {
                EnclaveResponse::Result(result) => {
                    let mut other = result.digest;
                    other[0] ^= 0x01;
                    Ok(resign(&key, result, bank_nonce, other))
                }
                other => Ok(other),
            },
        }
    }
}
