use std::path::{Path, PathBuf};

use tv_client::files::PRIVATE_FILE_MODE;
use tv_client::ops::Session;
use tv_client::{Debits, write_atomic};
use tv_core::SignedState;

use crate::error::BankError;
use crate::ledger::read_issuances;

pub const GENESIS_FILE: &str = "bank-genesis.json";

pub fn genesis_path(dir: &Path) -> PathBuf {
    dir.join(GENESIS_FILE)
}

pub fn write_genesis(dir: &Path, genesis: &SignedState) -> Result<(), BankError> {
    let path = genesis_path(dir);
    let bytes = serde_json::to_vec_pretty(genesis)?;
    write_atomic(&path, &bytes, PRIVATE_FILE_MODE).map_err(BankError::file(&path))
}

pub fn read_genesis(dir: &Path) -> Result<SignedState, BankError> {
    let path = genesis_path(dir);
    let bytes = std::fs::read(&path).map_err(BankError::file(&path))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn debits(dir: &Path) -> Result<Debits, BankError> {
    Ok(read_issuances(dir)?
        .into_iter()
        .map(|record| (record.digest, record.amount))
        .collect())
}

pub async fn recover(dir: &Path, session: &Session) -> Result<String, BankError> {
    let genesis = read_genesis(dir)?;
    let debits = debits(dir)?;
    Ok(session.recover_from_genesis(genesis, &debits).await?)
}
