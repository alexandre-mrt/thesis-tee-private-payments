use std::fs::File;
use std::path::{Path, PathBuf};

use tracing::warn;
use tv_client::{Wallet, WalletData};
use tv_core::{BankKeys, Seed, SignedState, SigningKey, State, derive_r, derive_sk, sign_state};

use crate::error::BankError;
use crate::genesis::write_genesis;
use crate::journal::{LOG_FILE, create_log};
use crate::keys::{read_key, write_key};

pub const STATE_KEY_FILE: &str = "state.key";
pub const ISSUANCE_KEY_FILE: &str = "issuance.key";
pub const ENCLAVE_PK_FILE: &str = "enclave.pk";
pub const BANK_WALLET_FILE: &str = "bank-wallet.json";
pub const DEFAULT_RESERVE: u64 = 1_000_000_000;

const REQUIRED_FILES: [&str; 4] = [
    STATE_KEY_FILE,
    ISSUANCE_KEY_FILE,
    BANK_WALLET_FILE,
    LOG_FILE,
];

pub fn bank_wallet_path(dir: &Path) -> PathBuf {
    dir.join(BANK_WALLET_FILE)
}

fn is_empty_dir(dir: &Path) -> Result<bool, BankError> {
    Ok(std::fs::read_dir(dir)?.next().is_none())
}

fn staging_dir(dir: &Path) -> Result<PathBuf, BankError> {
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| BankError::DataDirName {
            path: dir.display().to_string(),
        })?;
    Ok(dir.with_file_name(format!("{name}.init-{}", std::process::id())))
}

fn sync_dir(dir: &Path) -> Result<(), BankError> {
    Ok(File::open(dir)?.sync_all()?)
}

fn populate(dir: &Path, reserve: u64) -> Result<BankKeys, BankError> {
    let state_key = SigningKey::generate();
    let issuance_key = SigningKey::generate();
    write_key(&dir.join(STATE_KEY_FILE), &state_key)?;
    write_key(&dir.join(ISSUANCE_KEY_FILE), &issuance_key)?;
    let keys = BankKeys {
        state_pk: state_key.public_key(),
        issuance_pk: issuance_key.public_key(),
    };
    let seed = Seed::generate();
    let state = State {
        balance: reserve,
        pk: derive_sk(&seed, 0)?.public_key(),
        r: derive_r(&seed, 0)?,
    };
    let sig = sign_state(&issuance_key, &state.commitment());
    write_genesis(dir, &SignedState { state, sig })?;
    Wallet::create_with(
        &bank_wallet_path(dir),
        WalletData {
            seed,
            bank: keys,
            index: 0,
            state: Some(SignedState { state, sig }),
            pending: None,
        },
    )?;
    create_log(dir)?;
    Ok(keys)
}

pub fn init(dir: &Path, reserve: u64) -> Result<BankKeys, BankError> {
    let staging = staging_dir(dir)?;
    if dir.exists() && !is_empty_dir(dir)? {
        return Err(BankError::DataDirNotEmpty {
            path: dir.display().to_string(),
        });
    }
    std::fs::create_dir(&staging)?;
    let keys = match populate(&staging, reserve) {
        Ok(keys) => keys,
        Err(err) => {
            if let Err(cleanup) = std::fs::remove_dir_all(&staging) {
                warn!(path = %staging.display(), error = %cleanup, "staging dir left behind");
            }
            return Err(err);
        }
    };
    std::fs::rename(&staging, dir)?;
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        sync_dir(parent)?;
    }
    Ok(keys)
}

pub fn require_complete(dir: &Path) -> Result<(), BankError> {
    match REQUIRED_FILES.iter().find(|name| !dir.join(name).is_file()) {
        Some(missing) => Err(BankError::DataDirIncomplete {
            path: dir.display().to_string(),
            missing,
        }),
        None => Ok(()),
    }
}

pub fn read_keys(dir: &Path) -> Result<BankKeys, BankError> {
    Ok(BankKeys {
        state_pk: read_key(&dir.join(STATE_KEY_FILE))?.public_key(),
        issuance_pk: read_key(&dir.join(ISSUANCE_KEY_FILE))?.public_key(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tv-init-{tag}-{nanos}"));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn init_is_all_or_nothing_and_never_touches_a_populated_dir() {
        let root = scratch("atomic");
        let dir = root.join("bank");
        let keys = init(&dir, 7).unwrap();
        assert_eq!(names(&root), vec!["bank"]);
        assert!(require_complete(&dir).is_ok());
        assert_eq!(read_keys(&dir).unwrap(), keys);
        let before = std::fs::read(dir.join(STATE_KEY_FILE)).unwrap();

        assert!(matches!(
            init(&dir, 7),
            Err(BankError::DataDirNotEmpty { .. })
        ));
        assert_eq!(std::fs::read(dir.join(STATE_KEY_FILE)).unwrap(), before);
        assert_eq!(names(&root), vec!["bank"]);

        let partial = root.join("partial");
        std::fs::create_dir(&partial).unwrap();
        std::fs::write(partial.join(ISSUANCE_KEY_FILE), b"stale").unwrap();
        assert!(matches!(
            init(&partial, 7),
            Err(BankError::DataDirNotEmpty { .. })
        ));
        assert!(matches!(
            require_complete(&partial),
            Err(BankError::DataDirIncomplete {
                missing: STATE_KEY_FILE,
                ..
            })
        ));

        let empty = root.join("empty");
        std::fs::create_dir(&empty).unwrap();
        init(&empty, 7).unwrap();
        assert!(require_complete(&empty).is_ok());
        assert!(matches!(
            init(&root.join(".."), 7),
            Err(BankError::DataDirName { .. })
        ));
        assert_eq!(names(&root), vec!["bank", "empty", "partial"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_missing_bank_wallet_makes_the_dir_incomplete() {
        let root = scratch("wallet");
        let dir = root.join("bank");
        init(&dir, 7).unwrap();
        std::fs::remove_file(bank_wallet_path(&dir)).unwrap();
        assert!(matches!(
            require_complete(&dir),
            Err(BankError::DataDirIncomplete {
                missing: BANK_WALLET_FILE,
                ..
            })
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
