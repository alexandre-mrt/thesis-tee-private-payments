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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::chain_genesis;
    use crate::wire::OpKind;

    fn entry(seq: u64, serial: u8) -> LogEntry {
        LogEntry {
            seq,
            kind: OpKind::Refresh,
            serials: vec![[serial; 32]],
            commitments: vec![[serial + 1; 32]],
            sigs: vec![Signature([2u8; 64])],
            owner_sigs: vec![Signature([3u8; 64])],
            digest: [4u8; 32],
            c_v: None,
            h_ctx: None,
            epoch: epoch_of(7 * EPOCH_SECS + 5),
            chain: [0u8; 32],
            rcpt: Signature([0u8; 64]),
        }
    }

    #[test]
    fn a_sealed_entry_verifies_extends_its_predecessor_and_travels_as_a_receipt() {
        let key = SigningKey::generate();
        let pk = VerifyingKey::parse(&key.public_key()).unwrap();
        let genesis = chain_genesis(&key.public_key());
        let first = entry(0, 1).sealed(&genesis, &key);
        let second = entry(1, 2).sealed(&first.chain, &key);
        assert_eq!(first.epoch, 7);
        assert!(first.verify_receipt(&pk).is_ok() && second.verify_receipt(&pk).is_ok());
        assert!(first.verify_link(&genesis).is_ok() && second.verify_link(&first.chain).is_ok());
        assert_eq!(
            second.verify_link(&genesis),
            Err(CoreError::BrokenChain { seq: 1 })
        );
        let other = VerifyingKey::parse(&SigningKey::generate().public_key()).unwrap();
        assert_eq!(first.verify_receipt(&other), Err(CoreError::BadSignature));
        let rebuilt = entry(0, 1).with_receipt(&first.receipt());
        assert_eq!(rebuilt, first);
        let moved = LogEntry {
            epoch: 8,
            ..first.clone()
        };
        assert!(moved.verify_receipt(&pk).is_err());
    }

    #[test]
    fn two_signed_entries_for_one_position_are_a_fork() {
        let key = SigningKey::generate();
        let pk = VerifyingKey::parse(&key.public_key()).unwrap();
        let genesis = chain_genesis(&key.public_key());
        let honest = entry(0, 1).sealed(&genesis, &key);
        let rewritten = entry(0, 9).sealed(&genesis, &key);
        assert!(is_fork(&pk, &honest, &rewritten));
        assert!(!is_fork(&pk, &honest, &honest));
        let forged = LogEntry {
            rcpt: Signature([1u8; 64]),
            ..rewritten
        };
        assert!(!is_fork(&pk, &honest, &forged));
    }
}
