#![forbid(unsafe_code)]

pub mod error;
pub mod flight;
pub mod index;
pub mod journal;
pub mod keys;
pub mod store;

pub use error::{BankError, LinkError};
pub use index::{Index, MAX_RANGE, answer_for};
pub use store::{Durability, LOG_FILE, LogWriter, Store, Ticket, create_log};

pub const DEFAULT_LISTEN: &str = tv_client::DEFAULT_BANK;

pub const DEFAULT_ENCLAVE: &str = pt_tee::MOCK_ENCLAVE_LISTEN;
