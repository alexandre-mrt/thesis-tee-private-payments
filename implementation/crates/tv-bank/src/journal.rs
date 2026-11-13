use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;

use crate::error::BankError;
use crate::flight::header;

pub const LOG_FILE: &str = "log.jsonl";

pub trait LogWriter: Send + 'static {
    fn read_all(&mut self) -> std::io::Result<Vec<u8>>;

    fn append(&mut self, bytes: &[u8]) -> std::io::Result<()>;

    fn truncate(&mut self, len: u64) -> std::io::Result<()>;
}

impl LogWriter for File {
    fn read_all(&mut self) -> std::io::Result<Vec<u8>> {
        self.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.write_all(bytes)?;
        self.sync_data()
    }

    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        self.set_len(len)?;
        self.sync_all()
    }
}

pub type Journal<W> = Arc<Mutex<W>>;

pub fn create_log(dir: &Path) -> Result<(), BankError> {
    let path = dir.join(LOG_FILE);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| {
            file.write_all(&header())?;
            file.sync_all()
        })
        .and_then(|()| File::open(dir)?.sync_all())
        .map_err(BankError::file(&path))
}

pub fn open_log(dir: &Path) -> Result<File, BankError> {
    let path = dir.join(LOG_FILE);
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(&path)
        .map_err(BankError::file(&path))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(BankError::Locked {
            path: path.display().to_string(),
        }),
        Err(TryLockError::Error(err)) => Err(BankError::file(&path)(err)),
    }
}

pub(crate) fn is_zeroed_tail<T: DeserializeOwned>(raw: &[u8], rest: &[u8]) -> bool {
    raw.contains(&0)
        && !rest
            .split(|b| *b == b'\n')
            .any(|line| serde_json::from_slice::<T>(line).is_ok())
}

#[cfg(test)]
mod tests {
    use super::testing::temp_dir;
    use super::*;
    use crate::store::Store;

    #[test]
    fn an_unopenable_log_error_names_the_log_file() {
        let dir = temp_dir("log-is-dir");
        std::fs::create_dir(dir.join(LOG_FILE)).unwrap();
        let err = Store::open(&dir).err().unwrap();
        assert!(matches!(err, BankError::File { .. }));
        assert!(err.to_string().contains(LOG_FILE), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::fs::{File, OpenOptions};
    use std::io::Error;
    use std::path::{Path, PathBuf};
    use std::sync::PoisonError;

    use tv_core::{LogEntry, OpKind, Signature};

    use super::{LOG_FILE, LogWriter};
    use crate::store::Store;

    pub fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tv-store-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    pub fn entry(seq: u64, kind: OpKind, serial: u8) -> LogEntry {
        let sigs = match kind {
            OpKind::Pay => vec![Signature([seq as u8; 64]), Signature([seq as u8 + 1; 64])],
            _ => vec![Signature([seq as u8; 64])],
        };
        LogEntry {
            seq,
            kind,
            serials: vec![[serial; 32]],
            commitments: vec![[serial + 100; 32]],
            sigs,
            digest: [seq as u8 + 50; 32],
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Fault {
        None,
        WriteThenFail,
        WriteThenFailAndNoTruncate,
    }

    pub struct FaultyWriter {
        file: File,
        pub fault: Fault,
        pub appends: usize,
    }

    impl LogWriter for FaultyWriter {
        fn read_all(&mut self) -> std::io::Result<Vec<u8>> {
            self.file.read_all()
        }

        fn append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.appends += 1;
            self.file.append(bytes)?;
            match self.fault {
                Fault::None => Ok(()),
                _ => Err(Error::other("disk full after the write")),
            }
        }

        fn truncate(&mut self, len: u64) -> std::io::Result<()> {
            if self.fault == Fault::WriteThenFailAndNoTruncate {
                return Err(Error::other("truncate failed"));
            }
            self.file.truncate(len)
        }
    }

    pub fn faulty(dir: &Path, fault: Fault) -> Store<FaultyWriter> {
        if !dir.join(LOG_FILE).exists() {
            super::create_log(dir).unwrap();
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(dir.join(LOG_FILE))
            .unwrap();
        Store::from_writer(FaultyWriter {
            file,
            fault,
            appends: 0,
        })
        .unwrap()
    }

    pub fn set_fault(store: &Store<FaultyWriter>, fault: Fault) {
        store
            .journal()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fault = fault;
    }

    pub fn appends(store: &Store<FaultyWriter>) -> usize {
        store
            .journal()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .appends
    }
}
