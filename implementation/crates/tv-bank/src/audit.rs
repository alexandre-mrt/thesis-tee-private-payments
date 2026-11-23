use std::collections::BTreeSet;
use std::path::Path;

use tv_core::{Bytes32, CoreError, LogEntry, OpKind};

use crate::error::BankError;
use crate::flight::replay;
use crate::journal::LOG_FILE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Audit {
    pub entries: u64,
    pub payments: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("entry at position {position} carries seq {seq}")]
    Sequence { position: u64, seq: u64 },
    #[error("entry {seq}: owner signatures do not verify on the recomputed digest (B2): {source}")]
    Owners {
        seq: u64,
        #[source]
        source: CoreError,
    },
    #[error("entry {seq}: serial {serial} {reason} (B4)")]
    Serial {
        seq: u64,
        serial: String,
        reason: &'static str,
    },
}

#[derive(Default)]
struct Replay {
    spent: BTreeSet<Bytes32>,
    enrolled: BTreeSet<Bytes32>,
    commitments: BTreeSet<Bytes32>,
    audit: Audit,
}

impl Replay {
    fn serial_error(seq: u64, serial: &Bytes32, reason: &'static str) -> AuditError {
        AuditError::Serial {
            seq,
            serial: hex::encode(serial),
            reason,
        }
    }

    fn check_serials(&self, entry: &LogEntry) -> Result<(), AuditError> {
        let distinct: BTreeSet<&Bytes32> = entry.serials.iter().collect();
        if let Some(first) = entry.serials.first()
            && distinct.len() != entry.serials.len()
        {
            return Err(Self::serial_error(
                entry.seq,
                first,
                "repeats within the entry",
            ));
        }
        for serial in &entry.serials {
            if self.spent.contains(serial) {
                return Err(Self::serial_error(entry.seq, serial, "was already spent"));
            }
            if entry.kind == OpKind::Enroll && self.enrolled.contains(serial) {
                return Err(Self::serial_error(
                    entry.seq,
                    serial,
                    "was already enrolled",
                ));
            }
        }
        Ok(())
    }

    fn apply(&mut self, position: u64, entry: &LogEntry) -> Result<(), AuditError> {
        if entry.seq != position {
            return Err(AuditError::Sequence {
                position,
                seq: entry.seq,
            });
        }
        entry.verify_owners().map_err(|source| AuditError::Owners {
            seq: entry.seq,
            source,
        })?;
        self.check_serials(entry)?;
        if entry.kind == OpKind::Enroll
            && let Some(reused) = entry
                .commitments
                .iter()
                .find(|c| self.commitments.contains(*c))
        {
            return Err(Self::serial_error(
                entry.seq,
                reused,
                "enrolls a commitment already in the log",
            ));
        }
        let target = match entry.kind {
            OpKind::Enroll => &mut self.enrolled,
            OpKind::Pay | OpKind::Refresh => &mut self.spent,
        };
        target.extend(entry.serials.iter().copied());
        self.commitments.extend(entry.commitments.iter().copied());
        self.audit.entries += 1;
        self.audit.payments += u64::from(entry.kind == OpKind::Pay);
        Ok(())
    }
}

pub fn audit_entries(entries: &[LogEntry]) -> Result<Audit, AuditError> {
    let mut replay = Replay::default();
    for (position, entry) in (0u64..).zip(entries) {
        replay.apply(position, entry)?;
    }
    Ok(replay.audit)
}

pub fn read_log_entries(dir: &Path) -> Result<Vec<LogEntry>, BankError> {
    let path = dir.join(LOG_FILE);
    let bytes = std::fs::read(&path).map_err(BankError::file(&path))?;
    let (index, _) = replay(&bytes)?;
    Ok(index.into_entries())
}
