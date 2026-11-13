#![forbid(unsafe_code)]

pub mod bank;
pub mod commit;
pub mod error;
pub mod flight;
pub mod genesis;
pub mod index;
pub mod inflight;
pub mod init;
pub mod journal;
pub mod keys;
pub mod ledger;
pub mod link;
pub mod quota;
pub mod registry;
pub mod store;

pub use bank::{BANK_SOURCE, Bank, Outcome, Policy};
pub use commit::{Committer, SharedStore};
pub use error::{BankError, LinkError};
pub use genesis::{GENESIS_FILE, read_genesis};
pub use index::{Index, MAX_RANGE, answer_for};
pub use init::{
    BANK_WALLET_FILE, DEFAULT_RESERVE, ENCLAVE_PK_FILE, ISSUANCE_KEY_FILE, STATE_KEY_FILE,
    bank_wallet_path, init, read_keys, require_complete,
};
pub use ledger::{
    ISSUANCE_LEDGER_FILE, IssuanceRecord, issue, ledger_path, read_issuances, record_issuance,
};
pub use link::{EnclaveLink, TcpLink};
pub use quota::{AttestQuota, MAX_PENDING_KEYS_PER_SOURCE};
pub use registry::{EnclaveTrust, attest_enclave, parse_enclave};
pub use store::{Durability, LOG_FILE, LogWriter, Store, Ticket, create_log};

pub const DEFAULT_LISTEN: &str = tv_client::DEFAULT_BANK;

pub const DEFAULT_ENCLAVE: &str = pt_tee::MOCK_ENCLAVE_LISTEN;
