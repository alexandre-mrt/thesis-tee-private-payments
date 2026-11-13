#![forbid(unsafe_code)]

pub mod attest;
pub mod bank;
pub mod error;
pub mod files;
pub mod retry;
pub mod wallet;

pub use attest::{AttestationBundle, PCR0_LEN, Trust, parse_pcr0, verify_bundle};
pub use bank::{Attested, BankClient, seal_to};
pub use error::ClientError;
pub use files::{
    OfferFile, ReceiptFile, RequestFile, file_error, read_json, write_atomic, write_json,
};
pub use wallet::{Pending, Wallet, WalletData};

pub const DEFAULT_BANK: &str = "127.0.0.1:7700";
