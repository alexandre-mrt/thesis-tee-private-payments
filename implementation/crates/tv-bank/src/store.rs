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
