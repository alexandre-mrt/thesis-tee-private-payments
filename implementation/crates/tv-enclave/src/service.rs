use std::hint::black_box;
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::Arc;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use pt_tee::attestation::{AttestationInputs, AttestationProvider, user_data_for};
use pt_tee::channel::{EnclaveKeypair, PK_LEN, Sealed};
use serde::de::DeserializeOwned;
use tracing::{debug, info};
use tv_core::{
    BankKeys, BankVerifiers, Bytes32, CheckOp, EnclaveRequest, EnclaveResponse, Manifest,
    SealedBlob, SideKind, SigningKey, decode_cbor, manifest_digest, sign_result,
};

use crate::checks::{Checked, Refusal, check_enroll, check_pay, check_refresh};
use crate::error::EnclaveError;
use crate::keys::ChannelKeys;

const STACK_SCRUB_BYTES: usize = 64 * 1024;

#[inline(never)]
fn scrub_stack() {
    let mut scratch = [0u8; STACK_SCRUB_BYTES];
    black_box(&mut scratch);
}

pub struct Enclave {
    result_key: SigningKey,
    bank: BankVerifiers,
    provider: Box<dyn AttestationProvider>,
    user_data: Vec<u8>,
    keys: Mutex<ChannelKeys>,
}

#[cfg(any(test, feature = "test-hooks"))]
pub struct LeakedMemory {
    pub result_key: SigningKey,
    channel_keys: Vec<Arc<EnclaveKeypair>>,
}

#[cfg(any(test, feature = "test-hooks"))]
impl LeakedMemory {
    pub fn open_blob(&self, blob: &SealedBlob) -> Option<Vec<u8>> {
        self.channel_keys
            .iter()
            .find_map(|kp| open_with(kp, blob).ok())
    }

    pub fn channel_count(&self) -> usize {
        self.channel_keys.len()
    }
}

fn open_with(keypair: &EnclaveKeypair, blob: &SealedBlob) -> Result<Vec<u8>, Refusal> {
    let channel = keypair
        .accept(&blob.client_pk)
        .map_err(|_| Refusal::Opening)?;
    channel
        .open_request(&Sealed {
            nonce: blob.nonce,
            ciphertext: blob.ciphertext.clone(),
        })
        .map_err(|_| Refusal::Opening)
}

fn open_as<T: DeserializeOwned>(keypair: &EnclaveKeypair, blob: &SealedBlob) -> Result<T, Refusal> {
    decode_cbor(&open_with(keypair, blob)?).map_err(|_| Refusal::Opening)
}

impl Enclave {
    pub fn boot(
        bank: BankKeys,
        provider: Box<dyn AttestationProvider>,
    ) -> Result<Self, EnclaveError> {
        Self::boot_with(bank, provider, SigningKey::generate())
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn boot_with_result_key(
        bank: BankKeys,
        provider: Box<dyn AttestationProvider>,
        result_key: SigningKey,
    ) -> Result<Self, EnclaveError> {
        Self::boot_with(bank, provider, result_key)
    }

    fn boot_with(
        bank: BankKeys,
        provider: Box<dyn AttestationProvider>,
        result_key: SigningKey,
    ) -> Result<Self, EnclaveError> {
        let verifiers = BankVerifiers::parse(&bank)?;
        let manifest = Manifest {
            result_pk: result_key.public_key(),
            bank,
        };
        let user_data = user_data_for(&manifest_digest(&manifest));
        info!(result_pk = %hex::encode(manifest.result_pk), "enclave booted");
        Ok(Self {
            result_key,
            bank: verifiers,
            provider,
            user_data,
            keys: Mutex::new(ChannelKeys::default()),
        })
    }

    pub fn manifest(&self) -> Manifest {
        Manifest {
            result_pk: self.result_key.public_key(),
            bank: self.bank.keys(),
        }
    }

    pub fn result_pk(&self) -> Bytes32 {
        self.result_key.public_key()
    }

    pub fn pending_keys(&self) -> usize {
        self.keys().len()
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn leak_memory(&self) -> LeakedMemory {
        LeakedMemory {
            result_key: self.result_key.clone(),
            channel_keys: self.keys().snapshot(),
        }
    }

    fn keys(&self) -> std::sync::MutexGuard<'_, ChannelKeys> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn handle(&self, request: &EnclaveRequest) -> EnclaveResponse {
        match request {
            EnclaveRequest::Attest { nonce, owner } => self.attest(nonce, *owner),
            EnclaveRequest::Check { bank_nonce, op } => self.check(*bank_nonce, op),
            EnclaveRequest::Cancel { channel_pk } => self.cancel(channel_pk),
        }
    }

    pub fn cancel(&self, channel_pk: &[u8; PK_LEN]) -> EnclaveResponse {
        self.keys().take(channel_pk, Instant::now());
        EnclaveResponse::Cancelled
    }

    pub fn attest(&self, nonce: &Bytes32, owner: Option<Bytes32>) -> EnclaveResponse {
        let public_key = match owner {
            Some(owner) => self.keys().issue(Instant::now(), owner).public_key(),
            None => EnclaveKeypair::generate().public_key(),
        };
        let inputs = AttestationInputs {
            nonce,
            user_data: &self.user_data,
            public_key: &public_key,
        };
        match self.provider.attest(&inputs) {
            Ok(doc) => EnclaveResponse::Attestation {
                doc,
                manifest: self.manifest(),
                channel_pk: public_key,
            },
            Err(err) => {
                debug!(error = %err, "attestation failed");
                EnclaveResponse::Refused
            }
        }
    }

    pub fn check(&self, bank_nonce: Bytes32, op: &CheckOp) -> EnclaveResponse {
        let response = self.check_unscrubbed(bank_nonce, op);
        scrub_stack();
        response
    }

    #[inline(never)]
    fn check_unscrubbed(&self, bank_nonce: Bytes32, op: &CheckOp) -> EnclaveResponse {
        let now = Instant::now();
        let Some(key) = self.keys().peek(op.channel_pk(), now) else {
            return Self::refuse();
        };
        if key.owner != *op.owner() {
            return Self::refuse();
        }
        let consume = || {
            self.keys()
                .take(op.channel_pk(), now)
                .map(drop)
                .ok_or(Refusal::ChannelKey)
        };
        match self.run_checks(&key.keypair, op, consume) {
            Ok(checked) => EnclaveResponse::Result(sign_result(
                &self.result_key,
                bank_nonce,
                checked.digest,
                checked.sides,
            )),
            Err(_) => {
                black_box(sign_result(
                    &self.result_key,
                    bank_nonce,
                    op.digest(),
                    vec![SideKind::User; op.side_count()],
                ));
                Self::refuse()
            }
        }
    }

    fn refuse() -> EnclaveResponse {
        debug!("check refused");
        EnclaveResponse::Refused
    }

    fn run_checks(
        &self,
        keypair: &EnclaveKeypair,
        op: &CheckOp,
        consume: impl FnOnce() -> Result<(), Refusal>,
    ) -> Result<Checked, Refusal> {
        match op {
            CheckOp::Pay(receive) => {
                let payer = open_as(keypair, &receive.payer)?;
                let payee = open_as(keypair, &receive.payee)?;
                consume()?;
                check_pay(&self.bank, &receive.public, &payer, &payee)
            }
            CheckOp::Enroll(request) => {
                let secret = open_as(keypair, &request.sealed)?;
                consume()?;
                check_enroll(request, &secret)
            }
            CheckOp::Refresh(request) => {
                let secret = open_as(keypair, &request.sealed)?;
                consume()?;
                check_refresh(&self.bank, request, &secret)
            }
        }
    }
}

#[cfg(test)]
mod tests;
