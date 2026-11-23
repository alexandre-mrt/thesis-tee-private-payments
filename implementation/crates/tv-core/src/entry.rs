use serde::{Deserialize, Serialize};

use crate::commit::{PayFields, enroll_digest, pay_digest, refresh_digest};
use crate::error::CoreError;
use crate::sig::{Signature, VerifyingKey};
use crate::types::Bytes32;
use crate::wire::OpKind;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub kind: OpKind,
    pub serials: Vec<Bytes32>,
    pub commitments: Vec<Bytes32>,
    pub sigs: Vec<Signature>,
    pub owner_sigs: Vec<Signature>,
    pub digest: Bytes32,
    pub c_v: Option<Bytes32>,
    pub h_ctx: Option<Bytes32>,
}

fn malformed(what: &'static str) -> CoreError {
    CoreError::MalformedEntry { what }
}

impl LogEntry {
    pub fn sig_for(&self, commitment: &Bytes32) -> Option<Signature> {
        self.commitments
            .iter()
            .position(|c| c == commitment)
            .and_then(|i| self.sigs.get(i).copied())
    }

    pub fn side_count(&self) -> usize {
        match self.kind {
            OpKind::Pay => 2,
            OpKind::Enroll | OpKind::Refresh => 1,
        }
    }

    pub fn recomputed_digest(&self) -> Result<Bytes32, CoreError> {
        let sides = self.side_count();
        if self.serials.len() != sides || self.commitments.len() != sides {
            return Err(malformed("serial or commitment count"));
        }
        let evidence = (self.c_v, self.h_ctx);
        match (
            self.kind,
            self.serials.as_slice(),
            self.commitments.as_slice(),
        ) {
            (OpKind::Pay, [pk_a, pk_b], [com_a_next, com_b_next]) => {
                let (Some(c_v), Some(h_ctx)) = evidence else {
                    return Err(malformed("pay entry without C_v and h_ctx"));
                };
                Ok(pay_digest(&PayFields {
                    pk_a,
                    com_a_next,
                    pk_b,
                    com_b_next,
                    c_v: &c_v,
                    h_ctx: &h_ctx,
                }))
            }
            (_, _, _) if evidence != (None, None) => {
                Err(malformed("C_v or h_ctx outside a payment"))
            }
            (OpKind::Enroll, [pk0], [com0]) => Ok(enroll_digest(pk0, com0)),
            (OpKind::Refresh, [pk], [com_next]) => Ok(refresh_digest(pk, com_next)),
            _ => Err(malformed("entry shape")),
        }
    }

    pub fn verify_owners(&self) -> Result<(), CoreError> {
        if self.recomputed_digest()? != self.digest {
            return Err(malformed("digest"));
        }
        if self.owner_sigs.len() != self.serials.len() || self.sigs.len() != self.serials.len() {
            return Err(malformed("signature count"));
        }
        self.serials
            .iter()
            .zip(&self.owner_sigs)
            .try_for_each(|(serial, sig)| {
                VerifyingKey::parse(serial)?.verify_digest(&self.digest, sig)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::SigningKey;

    fn pay_entry() -> (LogEntry, SigningKey, SigningKey) {
        let (alice, bob) = (SigningKey::generate(), SigningKey::generate());
        let unsigned = LogEntry {
            seq: 0,
            kind: OpKind::Pay,
            serials: vec![alice.public_key(), bob.public_key()],
            commitments: vec![[3u8; 32], [4u8; 32]],
            sigs: vec![Signature([5u8; 64]), Signature([6u8; 64])],
            owner_sigs: Vec::new(),
            digest: [0u8; 32],
            c_v: Some([8u8; 32]),
            h_ctx: Some([9u8; 32]),
        };
        let digest = unsigned.recomputed_digest().unwrap();
        let entry = LogEntry {
            owner_sigs: vec![alice.sign(&digest), bob.sign(&digest)],
            digest,
            ..unsigned
        };
        (entry, alice, bob)
    }

    #[test]
    fn log_entry_sig_lookup_follows_commitment_position() {
        let (entry, _, _) = pay_entry();
        assert_eq!(entry.sig_for(&[4u8; 32]), Some(Signature([6u8; 64])));
        assert_eq!(entry.sig_for(&[9u8; 32]), None);
    }

    #[test]
    fn owner_signatures_replay_b2_on_the_recomputed_digest() {
        let (entry, alice, _) = pay_entry();
        assert!(entry.verify_owners().is_ok());
        let swapped = LogEntry {
            owner_sigs: vec![entry.owner_sigs[1], entry.owner_sigs[0]],
            ..entry.clone()
        };
        assert_eq!(swapped.verify_owners(), Err(CoreError::BadSignature));
        let other_amount = LogEntry {
            c_v: Some([1u8; 32]),
            ..entry.clone()
        };
        assert!(other_amount.verify_owners().is_err());
        let missing = LogEntry {
            h_ctx: None,
            ..entry.clone()
        };
        assert!(missing.verify_owners().is_err());
        let refresh = LogEntry {
            kind: OpKind::Refresh,
            serials: vec![alice.public_key()],
            commitments: vec![[3u8; 32]],
            sigs: vec![Signature([5u8; 64])],
            owner_sigs: vec![],
            ..entry
        };
        assert!(refresh.verify_owners().is_err());
        let digest = refresh_digest(&alice.public_key(), &[3u8; 32]);
        let signed = LogEntry {
            owner_sigs: vec![alice.sign(&digest)],
            digest,
            c_v: None,
            h_ctx: None,
            ..refresh
        };
        assert!(signed.verify_owners().is_ok());
    }
}
