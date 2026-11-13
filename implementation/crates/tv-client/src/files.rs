use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::warn;
use tv_core::{Bytes32, SealedBlob, Signature};

use crate::attest::AttestationBundle;
use crate::error::ClientError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestFile {
    pub v: u64,
    pub pk_b: Bytes32,
    pub com_b_next: Bytes32,
    pub attestation: AttestationBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferFile {
    pub channel_pk: Bytes32,
    pub pk_a: Bytes32,
    pub com_a_next: Bytes32,
    pub sig_a: Signature,
    pub payer: SealedBlob,
    pub pk_b: Bytes32,
    pub com_b_next: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptFile {
    pub digest: Bytes32,
    pub pk_a: Bytes32,
    pub com_a_next: Bytes32,
    pub sig_a_next: Signature,
}

pub fn file_error(what: &'static str, path: &Path, reason: &dyn std::fmt::Display) -> ClientError {
    ClientError::File {
        what,
        path: path.display().to_string(),
        reason: reason.to_string(),
    }
}

pub const PRIVATE_FILE_MODE: u32 = 0o600;

pub const SHARED_FILE_MODE: u32 = 0o644;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(path: &Path) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    PathBuf::from(name)
}

#[cfg_attr(
    not(unix),
    allow(unused_variables, reason = "the mode is a unix permission")
)]
fn create_temp(tmp: &Path, mode: u32) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    options.open(tmp)
}

pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = temp_path(path);
    let written = (|| {
        let mut file = create_temp(&tmp, mode)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(err) = written {
        if let Err(cleanup) = std::fs::remove_file(&tmp)
            && cleanup.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %tmp.display(), error = %cleanup, "leaving a temporary file behind");
        }
        return Err(err);
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

pub fn write_json<T: Serialize>(
    path: &Path,
    what: &'static str,
    value: &T,
) -> Result<(), ClientError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_atomic(path, &bytes, SHARED_FILE_MODE).map_err(|e| file_error(what, path, &e))
}

pub fn read_json<T: DeserializeOwned>(path: &Path, what: &'static str) -> Result<T, ClientError> {
    let bytes = std::fs::read(path).map_err(|e| file_error(what, path, &e))?;
    serde_json::from_slice(&bytes).map_err(|e| file_error(what, path, &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tv-files-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn assert_names(err: &ClientError, what: &str) {
        assert!(
            matches!(err, ClientError::File { what: w, .. } if *w == what),
            "{err}"
        );
        assert!(err.to_string().starts_with(&format!("{what} file ")));
    }

    #[test]
    fn file_errors_name_the_kind_of_file() {
        let dir = files_dir("errors");
        let missing = read_json::<ReceiptFile>(&dir.join("receipt.json"), "receipt").unwrap_err();
        assert_names(&missing, "receipt");
        assert!(!missing.to_string().contains("wallet"));
        let garbled = dir.join("offer.json");
        std::fs::write(&garbled, b"{").unwrap();
        assert_names(
            &read_json::<OfferFile>(&garbled, "offer").unwrap_err(),
            "offer",
        );
        let unwritable = dir.join("nowhere").join("request.json");
        assert_names(
            &write_json(&unwritable, "request", &42u8).unwrap_err(),
            "request",
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writes_are_atomic_and_a_directory_target_leaves_nothing_behind() {
        let dir = files_dir("atomic");
        let target = dir.join("receipt.json");
        write_json(&target, "receipt", &1u8).unwrap();
        write_json(&target, "receipt", &2u8).unwrap();
        assert_eq!(read_json::<u8>(&target, "receipt").unwrap(), 2);
        let occupied = dir.join("rcdir");
        std::fs::create_dir(&occupied).unwrap();
        let err = write_json(&occupied, "receipt", &3u8).unwrap_err();
        assert!(matches!(
            err,
            ClientError::File {
                what: "receipt",
                ..
            }
        ));
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
