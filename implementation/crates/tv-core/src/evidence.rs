use sha2::{Digest, Sha256};

use crate::entry::LogEntry;
use crate::sig::Signature;
use crate::types::Bytes32;
use crate::wire::OpKind;
use crate::{DOMAIN_CHAIN, DOMAIN_CHAIN0, DOMAIN_ENTRY, DOMAIN_RCPT};

fn kind_byte(kind: OpKind) -> u8 {
    match kind {
        OpKind::Enroll => 0,
        OpKind::Pay => 1,
        OpKind::Refresh => 2,
    }
}

fn count(h: &mut Sha256, n: usize) {
    h.update(u64::try_from(n).unwrap_or(u64::MAX).to_be_bytes());
}

fn hash_list(h: &mut Sha256, items: &[Bytes32]) {
    count(h, items.len());
    items.iter().for_each(|item| h.update(item));
}

fn hash_sigs(h: &mut Sha256, sigs: &[Signature]) {
    count(h, sigs.len());
    sigs.iter().for_each(|sig| h.update(sig.0));
}

fn hash_option(h: &mut Sha256, value: Option<&Bytes32>) {
    match value {
        Some(bytes) => {
            h.update([1u8]);
            h.update(bytes);
        }
        None => h.update([0u8]),
    }
}

pub fn entry_hash(entry: &LogEntry) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_ENTRY);
    h.update(entry.seq.to_be_bytes());
    h.update([kind_byte(entry.kind)]);
    hash_list(&mut h, &entry.serials);
    hash_list(&mut h, &entry.commitments);
    hash_sigs(&mut h, &entry.sigs);
    hash_sigs(&mut h, &entry.owner_sigs);
    h.update(entry.digest);
    hash_option(&mut h, entry.c_v.as_ref());
    hash_option(&mut h, entry.h_ctx.as_ref());
    h.finalize().into()
}

pub fn chain_genesis(receipt_pk: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_CHAIN0);
    h.update(receipt_pk);
    h.finalize().into()
}

pub fn chain_next(prev: &Bytes32, entry_hash: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_CHAIN);
    h.update(prev);
    h.update(entry_hash);
    h.finalize().into()
}

pub fn receipt_digest(seq: u64, epoch: u64, entry_hash: &Bytes32, chain: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_RCPT);
    h.update(seq.to_be_bytes());
    h.update(epoch.to_be_bytes());
    h.update(entry_hash);
    h.update(chain);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> LogEntry {
        LogEntry {
            seq: 4,
            kind: OpKind::Pay,
            serials: vec![[1u8; 32], [2u8; 32]],
            commitments: vec![[3u8; 32], [4u8; 32]],
            sigs: vec![Signature([5u8; 64]), Signature([6u8; 64])],
            owner_sigs: vec![Signature([7u8; 64]), Signature([8u8; 64])],
            digest: [9u8; 32],
            c_v: Some([10u8; 32]),
            h_ctx: Some([11u8; 32]),
        }
    }

    #[test]
    fn the_entry_hash_binds_every_field_and_each_field_boundary() {
        let base = entry_hash(&entry());
        let variants = [
            LogEntry { seq: 5, ..entry() },
            LogEntry {
                kind: OpKind::Refresh,
                ..entry()
            },
            LogEntry {
                serials: vec![[1u8; 32]],
                commitments: vec![[2u8; 32], [3u8; 32], [4u8; 32]],
                ..entry()
            },
            LogEntry {
                sigs: vec![Signature([5u8; 64])],
                owner_sigs: vec![
                    Signature([6u8; 64]),
                    Signature([7u8; 64]),
                    Signature([8u8; 64]),
                ],
                ..entry()
            },
            LogEntry {
                digest: [0u8; 32],
                ..entry()
            },
            LogEntry {
                c_v: None,
                ..entry()
            },
            LogEntry {
                c_v: Some([11u8; 32]),
                h_ctx: Some([10u8; 32]),
                ..entry()
            },
        ];
        for variant in &variants {
            assert_ne!(entry_hash(variant), base, "{variant:?}");
        }
        assert_eq!(entry_hash(&entry()), base);
    }

    #[test]
    fn chain_and_receipt_digests_are_domain_separated_and_ordered() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_ne!(chain_next(&a, &b), chain_next(&b, &a));
        assert_ne!(chain_genesis(&a), chain_genesis(&b));
        assert_ne!(chain_genesis(&a), chain_next(&a, &a));
        let r = receipt_digest(1, 2, &a, &b);
        assert_ne!(r, receipt_digest(2, 1, &a, &b));
        assert_ne!(r, receipt_digest(1, 2, &b, &a));
        assert_ne!(r, chain_next(&a, &b));
    }
}
