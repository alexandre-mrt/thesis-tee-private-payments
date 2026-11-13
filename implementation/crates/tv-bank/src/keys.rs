use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tv_core::{Bytes32, SigningKey};

use crate::error::BankError;

fn sync_parent(path: &Path) -> Result<(), BankError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn write_secret_file(path: &Path, text: &str) -> Result<(), BankError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| BankError::KeyFile(format!("{}: {e}", path.display())))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    sync_parent(path)
}

fn read_hex32(path: &Path) -> Result<Bytes32, BankError> {
    let named = |e: std::io::Error| BankError::KeyFile(format!("{}: {e}", path.display()));
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(named)?
        .read_to_string(&mut text)
        .map_err(named)?;
    let bytes = hex::decode(text.trim())
        .map_err(|_| BankError::KeyFile(format!("{} is not hex", path.display())))?;
    bytes
        .try_into()
        .map_err(|_| BankError::KeyFile(format!("{} is not 32 bytes", path.display())))
}

pub fn write_key(path: &Path, key: &SigningKey) -> Result<(), BankError> {
    write_secret_file(path, &hex::encode(key.to_bytes()))
}

pub fn read_key(path: &Path) -> Result<SigningKey, BankError> {
    Ok(SigningKey::from_bytes(&read_hex32(path)?))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(path: &Path) -> PathBuf {
    let unique = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!("tmp-{}-{unique}", std::process::id()))
}

pub fn write_public(path: &Path, pk: &Bytes32) -> Result<(), BankError> {
    let tmp = temp_path(path);
    let mut file = File::create(&tmp)?;
    file.write_all(hex::encode(pk).as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    sync_parent(path)
}

pub fn read_public(path: &Path) -> Result<Option<Bytes32>, BankError> {
    if !path.exists() {
        return Ok(None);
    }
    read_hex32(path).map(Some)
}
