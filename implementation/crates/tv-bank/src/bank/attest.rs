use std::sync::{MutexGuard, PoisonError};
use std::time::Instant;

use pt_tee::channel::PK_LEN;
use tracing::warn;
use tv_core::{BankResponse, Bytes32, EnclaveResponse};

use super::{Bank, Outcome};
use crate::journal::LogWriter;
use crate::link::EnclaveLink;
use crate::quota::AttestQuota;

impl<L: EnclaveLink, W: LogWriter> Bank<L, W> {
    pub fn pending_attestations_for(&self, source: &str) -> usize {
        self.quota().pending_for(source)
    }

    pub(super) fn quota(&self) -> MutexGuard<'_, AttestQuota> {
        self.quota.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) async fn attest(&self, nonce: Bytes32, source: &str, owner: Bytes32) -> Outcome {
        match self.link.attest(nonce, Some(owner)).await {
            Ok(EnclaveResponse::Attestation {
                doc,
                manifest,
                channel_pk,
            }) if manifest.bank == self.keys() => {
                let evicted = self.quota().record(Instant::now(), source, channel_pk);
                self.cancel(&evicted).await;
                Outcome::reply(BankResponse::Attestation { doc, manifest })
            }
            Ok(EnclaveResponse::Attestation { .. }) => Outcome::refuse("enclave manifest keys"),
            Ok(_) => Outcome::refuse("enclave refused the attestation"),
            Err(err) => {
                warn!(error = %err, "enclave unreachable");
                Outcome::reply(BankResponse::Unavailable)
            }
        }
    }

    async fn cancel(&self, evicted: &[[u8; PK_LEN]]) {
        for channel_pk in evicted {
            match self.link.cancel(*channel_pk).await {
                Ok(EnclaveResponse::Cancelled) => {}
                Ok(_) => warn!("enclave did not confirm a channel key cancel"),
                Err(err) => warn!(error = %err, "channel key cancel failed"),
            }
        }
    }
}
