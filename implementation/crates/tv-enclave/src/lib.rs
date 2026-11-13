#![forbid(unsafe_code)]

pub mod checks;
pub mod error;
pub mod keys;
pub mod service;

pub use checks::{Refusal, check_enroll, check_pay, check_refresh};
pub use error::EnclaveError;
pub use keys::{ChannelKeys, MAX_KEY_AGE, MAX_PENDING_KEYS};
pub use service::Enclave;
#[cfg(feature = "test-hooks")]
pub use service::LeakedMemory;

pub use zeroizing_alloc::ZeroAlloc;
