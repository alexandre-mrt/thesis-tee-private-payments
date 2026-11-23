use serde::{Deserialize, Serialize};

use crate::EPOCH_SECS;
use crate::entry::LogEntry;
use crate::error::CoreError;
use crate::evidence::{chain_next, entry_hash, receipt_digest};
use crate::sig::{Signature, SigningKey, VerifyingKey};
use crate::types::Bytes32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub seq: u64,
    pub epoch: u64,
    pub chain: Bytes32,
    pub rcpt: Signature,
}

pub fn epoch_of(unix_secs: u64) -> u64 {
    unix_secs / EPOCH_SECS
}

impl LogEntry {
    pub fn receipt(&self) -> Receipt {
        Receipt {
            seq: self.seq,
            epoch: self.epoch,
            chain: self.chain,
            rcpt: self.rcpt,
        }
    }

    pub fn with_receipt(self, receipt: &Receipt) -> LogEntry {
        LogEntry {
            seq: receipt.seq,
            epoch: receipt.epoch,
            chain: receipt.chain,
            rcpt: receipt.rcpt,
            ..self
        }
    }

    pub fn sealed(self, prev: &Bytes32, key: &SigningKey) -> LogEntry {
        let e = entry_hash(&self);
        let chain = chain_next(prev, &e);
        let rcpt = key.sign(&receipt_digest(self.seq, self.epoch, &e, &chain));
        LogEntry {
            chain,
            rcpt,
            ..self
        }
    }

    pub fn verify_receipt(&self, key: &VerifyingKey) -> Result<(), CoreError> {
        let digest = receipt_digest(self.seq, self.epoch, &entry_hash(self), &self.chain);
        key.verify(&digest, &self.rcpt)
    }

    pub fn verify_link(&self, prev: &Bytes32) -> Result<(), CoreError> {
        if chain_next(prev, &entry_hash(self)) != self.chain {
            return Err(CoreError::BrokenChain { seq: self.seq });
        }
        Ok(())
    }
}

pub fn is_fork(key: &VerifyingKey, a: &LogEntry, b: &LogEntry) -> bool {
    a.seq == b.seq
        && a.verify_receipt(key).is_ok()
        && b.verify_receipt(key).is_ok()
        && (entry_hash(a), a.chain) != (entry_hash(b), b.chain)
}
