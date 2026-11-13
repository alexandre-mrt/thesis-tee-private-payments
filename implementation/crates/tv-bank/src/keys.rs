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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_files_roundtrip_and_never_overwrite() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tv-keys-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.key");
        let key = SigningKey::generate();
        write_key(&path, &key).unwrap();
        assert_eq!(read_key(&path).unwrap().public_key(), key.public_key());
        assert!(matches!(write_key(&path, &key), Err(BankError::KeyFile(_))));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let pk_path = dir.join("enclave.pk");
        assert_eq!(read_public(&pk_path).unwrap(), None);
        write_public(&pk_path, &[7u8; 32]).unwrap();
        write_public(&pk_path, &[8u8; 32]).unwrap();
        assert_eq!(read_public(&pk_path).unwrap(), Some([8u8; 32]));
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        assert!(matches!(
            write_public(&dir.join("missing").join("enclave.pk"), &[9u8; 32]),
            Err(BankError::Io(_))
        ));
        assert_eq!(read_public(&pk_path).unwrap(), Some([8u8; 32]));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_public_key_writes_leave_one_whole_key() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tv-keys-race-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let pk_path = dir.join("enclave.pk");
        let writers: Vec<_> = (0..16u8)
            .map(|n| {
                let pk_path = pk_path.clone();
                std::thread::spawn(move || write_public(&pk_path, &[n; 32]))
            })
            .collect();
        for writer in writers {
            writer.join().unwrap().unwrap();
        }
        let written = read_public(&pk_path).unwrap().unwrap();
        assert!(written.iter().all(|b| *b == written[0]) && written[0] < 16);
        write_public(&pk_path, &[8u8; 32]).unwrap();
        assert_eq!(read_public(&pk_path).unwrap(), Some([8u8; 32]));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_directory_in_place_of_a_key_file_is_named_in_the_error() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tv-keys-dir-{nanos}"));
        let pk_path = dir.join("enclave.pk");
        let key_path = dir.join("state.key");
        std::fs::create_dir_all(&pk_path).unwrap();
        std::fs::create_dir_all(&key_path).unwrap();
        let err = read_public(&pk_path).unwrap_err();
        assert!(matches!(err, BankError::KeyFile(_)));
        assert!(err.to_string().contains("enclave.pk"), "{err}");
        let err = read_key(&key_path).err().unwrap();
        assert!(err.to_string().contains("state.key"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
