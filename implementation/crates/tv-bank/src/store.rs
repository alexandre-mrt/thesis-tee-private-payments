use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use tracing::{error, warn};
use tv_core::{BankResponse, Bytes32, LogEntry};

use crate::error::BankError;
use crate::flight::{replay, trailer};
use crate::index::Index;
pub use crate::index::{MAX_RANGE, answer_for};
use crate::journal::{Journal, open_log};
pub use crate::journal::{LOG_FILE, LogWriter, create_log};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    seq: usize,
    generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    Durable,
    Staged,
    RolledBack,
}

pub struct Flight {
    pub bytes: Vec<u8>,
    pub end: usize,
}

pub struct Store<W: LogWriter = File> {
    journal: Journal<W>,
    index: Index,
    len: u64,
    durable: usize,
    generation: u64,
    ended: Vec<usize>,
    staged: Vec<u8>,
    in_flight: bool,
    poisoned: bool,
}

impl Store<File> {
    pub fn open(dir: &Path) -> Result<Self, BankError> {
        Self::from_writer(open_log(dir)?)
    }
}

impl<W: LogWriter> Store<W> {
    pub fn from_writer(mut writer: W) -> Result<Self, BankError> {
        let bytes = writer.read_all()?;
        let (index, consumed) = replay(&bytes)?;
        if consumed < bytes.len() {
            warn!(
                dropped = bytes.len() - consumed,
                "torn final flight truncated"
            );
            writer.truncate(consumed as u64)?;
        }
        let durable = index.entries().len();
        Ok(Self {
            journal: Arc::new(Mutex::new(writer)),
            index,
            len: consumed as u64,
            durable,
            generation: 0,
            ended: Vec::new(),
            staged: Vec::new(),
            in_flight: false,
            poisoned: false,
        })
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    pub fn durable(&self) -> usize {
        self.durable
    }

    pub fn journal(&self) -> Journal<W> {
        Arc::clone(&self.journal)
    }

    pub fn healthy(&self) -> Result<(), BankError> {
        if self.poisoned {
            return Err(BankError::StorePoisoned);
        }
        Ok(())
    }

    pub fn entries(&self) -> &[LogEntry] {
        &self.index.entries()[..self.durable]
    }

    pub fn lookup(&self, serial: &Bytes32) -> Option<&LogEntry> {
        self.index.lookup_within(serial, self.durable)
    }

    pub fn range(&self, from: u64, limit: u64) -> Vec<LogEntry> {
        self.index.range_within(from, limit, self.durable)
    }

    pub fn answer(&self, digest: &Bytes32) -> Option<(Ticket, BankResponse)> {
        let (seq, answer) = self.index.answer(digest)?;
        let generation = (seq >= self.durable).then_some(self.generation);
        Some((Ticket { seq, generation }, answer))
    }

    pub fn durability(&self, ticket: Ticket) -> Result<Durability, BankError> {
        self.healthy()?;
        Ok(match ticket.generation {
            Some(generation) if generation != self.generation => {
                match usize::try_from(generation)
                    .ok()
                    .and_then(|index| self.ended.get(index))
                {
                    Some(&boundary) if ticket.seq < boundary => Durability::Durable,
                    _ => Durability::RolledBack,
                }
            }
            _ if ticket.seq < self.durable => Durability::Durable,
            _ => Durability::Staged,
        })
    }

    pub fn stage(&mut self, entry: LogEntry) -> Result<Ticket, BankError> {
        self.healthy()?;
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        let seq = self.index.entries().len();
        self.index.apply(entry)?;
        self.staged.extend_from_slice(&line);
        Ok(Ticket {
            seq,
            generation: Some(self.generation),
        })
    }

    pub fn take_flight(&mut self) -> Option<Flight> {
        if self.poisoned || self.in_flight || self.staged.is_empty() {
            return None;
        }
        self.in_flight = true;
        let mut bytes = std::mem::take(&mut self.staged);
        bytes.extend(trailer(&bytes));
        Some(Flight {
            bytes,
            end: self.index.entries().len(),
        })
    }

    pub fn confirm(&mut self, written: usize, end: usize) {
        self.len += written as u64;
        self.durable = end;
        self.in_flight = false;
    }

    pub fn roll_back(&mut self, cause: std::io::Error) -> BankError {
        self.in_flight = false;
        self.staged.clear();
        self.ended.push(self.durable);
        self.generation += 1;
        let truncated = self
            .journal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .truncate(self.len)
            .map_err(BankError::Io);
        let reverted = self.index.truncate(self.durable);
        match truncated.and(reverted) {
            Ok(()) => {
                warn!(error = %cause, "log write failed; log truncated back to its durable length");
                BankError::Io(cause)
            }
            Err(err) => {
                self.poisoned = true;
                error!(write = %cause, roll_back = %err, "log write and roll back failed; store poisoned");
                BankError::StorePoisoned
            }
        }
    }

    pub fn flush_blocking(&mut self) -> Result<(), BankError> {
        if self.in_flight {
            return Err(BankError::FlushInProgress);
        }
        let Some(flight) = self.take_flight() else {
            return self.healthy();
        };
        let written = flight.bytes.len();
        let end = flight.end;
        let result = self
            .journal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .append(&flight.bytes);
        match result {
            Ok(()) => {
                self.confirm(written, end);
                Ok(())
            }
            Err(err) => Err(self.roll_back(err)),
        }
    }

    pub fn append(&mut self, entry: LogEntry) -> Result<(), BankError> {
        self.stage(entry)?;
        self.flush_blocking()
    }

    pub fn raw_bytes(&mut self) -> Result<Vec<u8>, BankError> {
        Ok(self
            .journal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .read_all()?)
    }
}

#[cfg(test)]
mod tests {
    use tv_core::{OpKind, Signature};

    use super::*;
    use crate::journal::testing::{Fault, entry, faulty, set_fault, temp_dir};

    #[test]
    fn append_replay_torn_tail_and_lock() {
        let dir = temp_dir("replay");
        create_log(&dir).unwrap();
        assert!(matches!(create_log(&dir), Err(BankError::File { .. })));
        let mut store = Store::open(&dir).unwrap();
        assert!(store.index().is_empty());
        store.append(entry(0, OpKind::Enroll, 1)).unwrap();
        store.append(entry(1, OpKind::Refresh, 1)).unwrap();
        store.append(entry(2, OpKind::Pay, 2)).unwrap();
        assert!(matches!(Store::open(&dir), Err(BankError::Locked { .. })));
        drop(store);
        let path = dir.join(LOG_FILE);
        let good = std::fs::read(&path).unwrap();
        let mut torn = good.clone();
        torn.truncate(good.len() - 7);
        std::fs::write(&path, &torn).unwrap();
        let store = Store::open(&dir).unwrap();
        assert_eq!(store.index().len(), 2);
        assert_eq!(store.lookup(&[1u8; 32]).unwrap().kind, OpKind::Refresh);
        assert!(store.index().is_spent(&[1u8; 32]));
        assert!(!store.index().is_fresh_serial(&[1u8; 32]));
        assert!(store.index().is_fresh_serial(&[2u8; 32]));
        assert!(!store.index().is_fresh_commitment(&[101u8; 32]));
        let (ticket, answer) = store.answer(&[51u8; 32]).unwrap();
        assert_eq!(
            answer,
            BankResponse::Refreshed {
                sig: Signature([1u8; 64])
            }
        );
        assert_eq!(store.durability(ticket).unwrap(), Durability::Durable);
        assert_eq!(store.range(1, 10).len(), 1);
        drop(store);
        let mut corrupt = good.clone();
        corrupt[5] = b'#';
        std::fs::write(&path, &corrupt).unwrap();
        assert!(matches!(
            Store::open(&dir),
            Err(BankError::Corrupt { line: 0, .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn staged_entries_are_invisible_until_flushed_and_a_rollback_reverts_them() {
        let dir = temp_dir("staged");
        let mut store = faulty(&dir, Fault::None);
        store.append(entry(0, OpKind::Enroll, 1)).unwrap();
        let ticket = store.stage(entry(1, OpKind::Refresh, 1)).unwrap();
        assert_eq!(store.durability(ticket).unwrap(), Durability::Staged);
        assert_eq!(store.entries().len(), 1);
        assert_eq!(store.lookup(&[1u8; 32]).unwrap().kind, OpKind::Enroll);
        assert_eq!(store.range(0, 10).len(), 1);
        assert!(store.index().is_spent(&[1u8; 32]));
        let (found, _) = store.answer(&[51u8; 32]).unwrap();
        assert_eq!(found, ticket);
        set_fault(&store, Fault::WriteThenFail);
        assert!(matches!(store.flush_blocking(), Err(BankError::Io(_))));
        assert_eq!(store.durability(ticket).unwrap(), Durability::RolledBack);
        assert!(!store.index().is_spent(&[1u8; 32]));
        assert_eq!(store.index().len(), 1);
        assert!(store.answer(&[51u8; 32]).is_none());
        set_fault(&store, Fault::None);
        let again = store.stage(entry(1, OpKind::Refresh, 1)).unwrap();
        assert_ne!(again, ticket);
        store.flush_blocking().unwrap();
        assert_eq!(store.durability(again).unwrap(), Durability::Durable);
        assert_eq!(store.durability(ticket).unwrap(), Durability::RolledBack);
        assert_eq!(store.lookup(&[1u8; 32]).unwrap().kind, OpKind::Refresh);
        drop(store);
        let reopened = Store::open(&dir).unwrap();
        assert_eq!(reopened.entries().len(), 2);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_append_is_rolled_back_so_the_serial_stays_unspent_on_disk_and_in_memory() {
        let dir = temp_dir("rollback");
        let mut store = faulty(&dir, Fault::None);
        store.append(entry(0, OpKind::Enroll, 1)).unwrap();
        drop(store);
        let len_before = std::fs::metadata(dir.join(LOG_FILE)).unwrap().len();
        let mut store = faulty(&dir, Fault::WriteThenFail);
        assert!(matches!(
            store.append(entry(1, OpKind::Refresh, 1)),
            Err(BankError::Io(_))
        ));
        assert!(!store.index().is_spent(&[1u8; 32]));
        assert_eq!(store.index().len(), 1);
        assert_eq!(
            std::fs::metadata(dir.join(LOG_FILE)).unwrap().len(),
            len_before
        );
        set_fault(&store, Fault::None);
        store.append(entry(1, OpKind::Refresh, 1)).unwrap();
        assert!(store.index().is_spent(&[1u8; 32]));
        drop(store);
        let reopened = Store::open(&dir).unwrap();
        assert_eq!(reopened.index().len(), 2);
        assert!(reopened.index().is_spent(&[1u8; 32]));
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_roll_back_poisons_the_store_until_restart() {
        let dir = temp_dir("poison");
        let mut store = faulty(&dir, Fault::WriteThenFailAndNoTruncate);
        assert!(matches!(
            store.append(entry(0, OpKind::Refresh, 1)),
            Err(BankError::StorePoisoned)
        ));
        assert!(matches!(store.healthy(), Err(BankError::StorePoisoned)));
        assert!(!store.index().is_spent(&[1u8; 32]));
        set_fault(&store, Fault::None);
        assert!(matches!(
            store.append(entry(0, OpKind::Refresh, 1)),
            Err(BankError::StorePoisoned)
        ));
        drop(store);
        let restarted = Store::open(&dir).unwrap();
        assert!(restarted.healthy().is_ok());
        assert_eq!(restarted.index().len(), 1);
        assert!(restarted.index().is_spent(&[1u8; 32]));
        drop(restarted);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
