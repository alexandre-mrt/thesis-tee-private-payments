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
