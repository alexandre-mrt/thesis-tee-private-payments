#![forbid(unsafe_code)]

pub mod error;
pub mod keys;

pub use error::EnclaveError;
pub use keys::{ChannelKeys, MAX_KEY_AGE, MAX_PENDING_KEYS};

pub use zeroizing_alloc::ZeroAlloc;
