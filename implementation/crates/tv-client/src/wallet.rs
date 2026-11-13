use std::ffi::OsString;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tv_core::{
    BankKeys, Bytes32, Opening, Seed, SideKind, Signature, SignedState, SigningKey, State,
    derive_r, derive_sk, verify_state,
};

use crate::error::ClientError;
use crate::files::{PRIVATE_FILE_MODE, file_error, read_json, write_atomic};

pub const LOCK_SUFFIX: &str = ".lock";

pub const WALLET_FILE_KIND: &str = "wallet";

const WALLET_LOCK_KIND: &str = "wallet lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pending {
    Enroll {
        com0: Bytes32,
        digest: Bytes32,
    },
    Request {
        v: u64,
        com_next: Bytes32,
        channel_pk: Bytes32,
        result_pk: Bytes32,
    },
    Pay {
        v: u64,
        pk_b: Bytes32,
        com_b_next: Bytes32,
        com_a_next: Bytes32,
        digest: Bytes32,
    },
    Refresh {
        com_next: Bytes32,
        digest: Bytes32,
    },
}

impl Pending {
    pub fn what(&self) -> &'static str {
        match self {
            Pending::Enroll { .. } => "enroll",
            Pending::Request { .. } => "request",
            Pending::Pay { .. } => "payment",
            Pending::Refresh { .. } => "refresh",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletData {
    pub seed: Seed,
    pub bank: BankKeys,
    pub index: u64,
    pub state: Option<SignedState>,
    pub pending: Option<Pending>,
}

impl WalletData {
    pub fn read(path: &Path) -> Result<Self, ClientError> {
        read_json(path, WALLET_FILE_KIND)
    }
}

pub fn lock_path(path: &Path) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(LOCK_SUFFIX);
    PathBuf::from(name)
}

fn acquire_lock(path: &Path) -> Result<File, ClientError> {
    let lock_file = lock_path(path);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_file)
        .map_err(|e| file_error(WALLET_LOCK_KIND, &lock_file, &e))?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(ClientError::WalletLocked {
            path: path.display().to_string(),
        }),
        Err(TryLockError::Error(err)) => Err(file_error(WALLET_LOCK_KIND, &lock_file, &err)),
    }
}

#[derive(Debug)]
pub struct Wallet {
    path: PathBuf,
    data: WalletData,
    _lock: File,
}

impl Wallet {
    pub fn create(path: &Path, seed: Seed, bank: BankKeys) -> Result<Self, ClientError> {
        let data = WalletData {
            seed,
            bank,
            index: 0,
            state: None,
            pending: None,
        };
        Self::create_with(path, data)
    }

    pub fn create_with(path: &Path, data: WalletData) -> Result<Self, ClientError> {
        let lock = acquire_lock(path)?;
        if path.exists() {
            return Err(file_error(WALLET_FILE_KIND, path, &"already exists"));
        }
        let wallet = Self {
            path: path.to_path_buf(),
            data,
            _lock: lock,
        };
        wallet.save()?;
        Ok(wallet)
    }

    pub fn load(path: &Path) -> Result<Self, ClientError> {
        std::fs::metadata(path).map_err(|e| file_error(WALLET_FILE_KIND, path, &e))?;
        let lock = acquire_lock(path)?;
        let data = WalletData::read(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            data,
            _lock: lock,
        })
    }

    pub fn save(&self) -> Result<(), ClientError> {
        let bytes = serde_json::to_vec_pretty(&self.data)?;
        write_atomic(&self.path, &bytes, PRIVATE_FILE_MODE)
            .map_err(|e| file_error(WALLET_FILE_KIND, &self.path, &e))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn data(&self) -> &WalletData {
        &self.data
    }

    pub fn seed(&self) -> Seed {
        self.data.seed
    }

    pub fn bank(&self) -> BankKeys {
        self.data.bank
    }

    pub fn index(&self) -> u64 {
        self.data.index
    }

    pub fn state(&self) -> Option<&SignedState> {
        self.data.state.as_ref()
    }

    pub fn signed_state(&self) -> Result<SignedState, ClientError> {
        self.data.state.ok_or(ClientError::NotEnrolled)
    }

    pub fn balance(&self) -> u64 {
        self.data.state.map_or(0, |s| s.state.balance)
    }

    pub fn pending(&self) -> Option<&Pending> {
        self.data.pending.as_ref()
    }

    pub fn is_bank_state(&self) -> bool {
        self.data.state.is_some_and(|s| {
            verify_state(&self.data.bank.issuance_pk, &s.state.commitment(), &s.sig).is_ok()
        })
    }

    pub fn on_enrolled_serial(&self) -> bool {
        self.data.index == 0 && self.data.state.is_some() && !self.is_bank_state()
    }

    pub fn key_at(&self, index: u64) -> Result<SigningKey, ClientError> {
        Ok(derive_sk(&self.data.seed, index)?)
    }

    pub fn r_at(&self, index: u64) -> Result<Bytes32, ClientError> {
        Ok(derive_r(&self.data.seed, index)?)
    }

    pub fn current_key(&self) -> Result<SigningKey, ClientError> {
        self.key_at(self.data.index)
    }

    pub fn current_pk(&self) -> Result<Bytes32, ClientError> {
        Ok(self.current_key()?.public_key())
    }

    pub fn next_pk(&self) -> Result<Bytes32, ClientError> {
        Ok(self.key_at(self.data.index + 1)?.public_key())
    }

    pub fn next_r(&self) -> Result<Bytes32, ClientError> {
        self.r_at(self.data.index + 1)
    }

    pub fn opening(&self) -> Result<Opening, ClientError> {
        let signed = self.signed_state()?;
        let side = if self.is_bank_state() {
            SideKind::Bank
        } else {
            SideKind::User
        };
        Ok(Opening {
            balance: signed.state.balance,
            r: signed.state.r,
            sig: signed.sig,
            side,
            next_pk: self.next_pk()?,
            next_r: self.next_r()?,
        })
    }

    pub fn verify_new_state(&self, com: &Bytes32, sig: &Signature) -> Result<(), ClientError> {
        let bank = self.data.bank;
        if verify_state(&bank.state_pk, com, sig).is_ok()
            || verify_state(&bank.issuance_pk, com, sig).is_ok()
        {
            return Ok(());
        }
        Err(ClientError::BadStateSignature)
    }

    pub fn set_pending(&mut self, pending: Option<Pending>) -> Result<(), ClientError> {
        self.data.pending = pending;
        self.save()
    }

    pub fn set_enrolled(&mut self, state: State, sig: Signature) -> Result<(), ClientError> {
        self.data.state = Some(SignedState { state, sig });
        self.data.pending = None;
        self.save()
    }

    pub fn advance(&mut self, balance: u64, sig: Signature) -> Result<(), ClientError> {
        let index = self.data.index + 1;
        let state = State {
            balance,
            pk: self.key_at(index)?.public_key(),
            r: self.r_at(index)?,
        };
        self.data.index = index;
        self.data.state = Some(SignedState { state, sig });
        self.data.pending = None;
        self.save()
    }

    pub fn restore(&mut self, index: u64, state: Option<SignedState>) -> Result<(), ClientError> {
        self.data.index = index;
        self.data.state = state;
        self.data.pending = None;
        self.save()
    }
}
