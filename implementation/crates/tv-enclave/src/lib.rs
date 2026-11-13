#![forbid(unsafe_code)]

pub mod checks;
pub mod error;
pub mod keys;

pub use checks::{Refusal, check_enroll, check_pay, check_refresh};
pub use error::EnclaveError;
pub use keys::{ChannelKeys, MAX_KEY_AGE, MAX_PENDING_KEYS};

pub use zeroizing_alloc::ZeroAlloc;
