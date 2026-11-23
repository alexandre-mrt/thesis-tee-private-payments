use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use tv_core::{BankResponse, Bytes32, LogEntry, OpKind, chain_genesis};

use crate::error::BankError;

pub const MAX_RANGE: u64 = 1024;

#[derive(Debug, Serialize)]
pub struct Index {
    receipt_pk: Bytes32,
    head: Bytes32,
    entries: Vec<LogEntry>,
    spent: BTreeSet<Bytes32>,
    #[serde(serialize_with = "hex_keys")]
    enrolled: BTreeMap<Bytes32, usize>,
    commitments: BTreeSet<Bytes32>,
    #[serde(serialize_with = "hex_keys")]
    by_serial: BTreeMap<Bytes32, usize>,
    #[serde(serialize_with = "hex_keys")]
    by_digest: BTreeMap<Bytes32, usize>,
}

fn hex_keys<S: serde::Serializer>(
    map: &BTreeMap<Bytes32, usize>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let keyed: BTreeMap<String, usize> = map.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
    keyed.serialize(serializer)
}

impl Index {
    pub fn new(receipt_pk: Bytes32) -> Self {
        Self {
            receipt_pk,
            head: chain_genesis(&receipt_pk),
            entries: Vec::new(),
            spent: BTreeSet::new(),
            enrolled: BTreeMap::new(),
            commitments: BTreeSet::new(),
            by_serial: BTreeMap::new(),
            by_digest: BTreeMap::new(),
        }
    }

    pub fn receipt_pk(&self) -> Bytes32 {
        self.receipt_pk
    }

    pub fn head(&self) -> Bytes32 {
        self.head
    }

    pub fn apply(&mut self, entry: LogEntry) -> Result<(), BankError> {
        let position = self.entries.len();
        if entry.seq != position as u64 {
            return Err(BankError::Corrupt {
                line: position,
                reason: format!("seq {} at position {position}", entry.seq),
            });
        }
        for serial in &entry.serials {
            match entry.kind {
                OpKind::Enroll => {
                    self.enrolled.insert(*serial, position);
                }
                OpKind::Pay | OpKind::Refresh => {
                    self.spent.insert(*serial);
                }
            }
            self.by_serial.insert(*serial, position);
        }
        self.commitments.extend(entry.commitments.iter().copied());
        self.by_digest.insert(entry.digest, position);
        self.head = entry.chain;
        self.entries.push(entry);
        Ok(())
    }

    pub fn truncate(&mut self, len: usize) -> Result<(), BankError> {
        let kept: Vec<LogEntry> = self.entries.drain(..len.min(self.entries.len())).collect();
        *self = Self::new(self.receipt_pk);
        kept.into_iter().try_for_each(|entry| self.apply(entry))
    }

    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_spent(&self, serial: &Bytes32) -> bool {
        self.spent.contains(serial)
    }

    pub fn is_fresh_serial(&self, serial: &Bytes32) -> bool {
        !self.spent.contains(serial) && !self.enrolled.contains_key(serial)
    }

    pub fn is_fresh_commitment(&self, com: &Bytes32) -> bool {
        !self.commitments.contains(com)
    }

    pub fn answer(&self, digest: &Bytes32) -> Option<(usize, BankResponse)> {
        let position = *self.by_digest.get(digest)?;
        let answer = self.entries.get(position).and_then(answer_for)?;
        Some((position, answer))
    }

    pub fn lookup(&self, serial: &Bytes32) -> Option<&LogEntry> {
        self.lookup_within(serial, self.entries.len())
    }

    pub fn lookup_within(&self, serial: &Bytes32, end: usize) -> Option<&LogEntry> {
        let latest = *self.by_serial.get(serial)?;
        let position = if latest < end {
            latest
        } else {
            *self.enrolled.get(serial).filter(|p| **p < end)?
        };
        self.entries.get(position)
    }

    pub fn range(&self, from: u64, limit: u64) -> Vec<LogEntry> {
        self.range_within(from, limit, self.entries.len())
    }

    pub fn range_within(&self, from: u64, limit: u64, end: usize) -> Vec<LogEntry> {
        let from = usize::try_from(from).unwrap_or(usize::MAX);
        let limit = usize::try_from(limit.min(MAX_RANGE)).unwrap_or(0);
        self.entries[..end.min(self.entries.len())]
            .iter()
            .skip(from)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<LogEntry> {
        self.entries
    }

    pub fn spent_count(&self) -> usize {
        self.spent.len()
    }
}

pub fn answer_for(entry: &LogEntry) -> Option<BankResponse> {
    match (entry.kind, entry.sigs.as_slice()) {
        (OpKind::Pay, [a, b]) => Some(BankResponse::Settled {
            sig_a_next: *a,
            sig_b_next: *b,
            receipt: entry.receipt(),
        }),
        (OpKind::Enroll, [sig]) => Some(BankResponse::Enrolled {
            sig: *sig,
            receipt: entry.receipt(),
        }),
        (OpKind::Refresh, [sig]) => Some(BankResponse::Refreshed {
            sig: *sig,
            receipt: entry.receipt(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use tv_core::Signature;

    use super::*;

    fn entry(seq: u64, kind: OpKind, serial: u8) -> LogEntry {
        LogEntry {
            seq,
            kind,
            serials: vec![[serial; 32]],
            commitments: vec![[serial + 100; 32]],
            sigs: vec![Signature([seq as u8; 64])],
            owner_sigs: vec![Signature([seq as u8 + 1; 64])],
            digest: [seq as u8 + 50; 32],
            c_v: None,
            h_ctx: None,
            epoch: 0,
            chain: [seq as u8 + 60; 32],
            rcpt: Signature([seq as u8 + 70; 64]),
        }
    }

    #[test]
    fn sequence_gaps_are_corrupt() {
        let mut index = Index::new([0u8; 32]);
        index.apply(entry(0, OpKind::Enroll, 1)).unwrap();
        assert!(matches!(
            index.apply(entry(2, OpKind::Enroll, 2)),
            Err(BankError::Corrupt { .. })
        ));
    }

    #[test]
    fn bounded_lookups_fall_back_to_the_enroll_entry_and_truncate_rebuilds() {
        let mut index = Index::new([0u8; 32]);
        index.apply(entry(0, OpKind::Enroll, 1)).unwrap();
        index.apply(entry(1, OpKind::Refresh, 1)).unwrap();
        index.apply(entry(2, OpKind::Refresh, 2)).unwrap();
        assert_eq!(index.lookup(&[1u8; 32]).unwrap().kind, OpKind::Refresh);
        assert_eq!(
            index.lookup_within(&[1u8; 32], 1).unwrap().kind,
            OpKind::Enroll
        );
        assert!(index.lookup_within(&[1u8; 32], 0).is_none());
        assert!(index.lookup_within(&[2u8; 32], 2).is_none());
        assert_eq!(index.range_within(0, 10, 1).len(), 1);
        assert_eq!(index.answer(&[51u8; 32]).unwrap().0, 1);
        index.truncate(1).unwrap();
        assert_eq!(index.len(), 1);
        assert!(!index.is_spent(&[1u8; 32]));
        assert!(!index.is_fresh_serial(&[1u8; 32]));
        assert!(index.is_fresh_serial(&[2u8; 32]));
        assert!(index.is_fresh_commitment(&[102u8; 32]));
        assert!(index.answer(&[51u8; 32]).is_none());
        assert!(index.lookup(&[2u8; 32]).is_none());
        assert_eq!(index.lookup(&[1u8; 32]).unwrap().kind, OpKind::Enroll);
    }
}
