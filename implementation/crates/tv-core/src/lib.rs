#![forbid(unsafe_code)]

use std::time::Duration;

pub mod cbor;
pub mod commit;
pub mod error;
pub mod sig;
pub mod types;

pub use cbor::{decode_cbor, encode_cbor};
pub use commit::{commitment, enroll_digest, manifest_digest, pay_digest, refresh_digest};
pub use error::CoreError;
pub use sig::{
    BankVerifiers, SIG_LEN, Signature, SigningKey, VerifyingKey, sign_digest, sign_state,
    verify_digest, verify_state,
};
pub use types::{
    BankKeys, Bytes32, Manifest, Opening, SideKind, SignedState, State, random_bytes32,
};

pub const B_MAX: u64 = 1_000_000;

pub const ATTEST_NONCE_LEN: usize = 32;

pub const MAX_PENDING_KEYS: usize = 1 << 16;

pub const MAX_KEY_AGE: Duration = Duration::from_secs(10 * 60);

pub const ATTEST_CLOCK_SKEW: Duration = Duration::from_secs(30);

pub const HKDF_SALT: &[u8] = b"tv/v1";
pub const LABEL_SK: &[u8] = b"sk";
pub const LABEL_R: &[u8] = b"r";
pub const DOMAIN_COM: &[u8] = b"tv/v1/com";
pub const DOMAIN_STATE: &[u8] = b"tv/v1/state";
pub const DOMAIN_PAY: &[u8] = b"tv/v1/pay";
pub const DOMAIN_REFRESH: &[u8] = b"tv/v1/refresh";
pub const DOMAIN_ENROLL: &[u8] = b"tv/v1/enroll";
pub const DOMAIN_RESULT: &[u8] = b"tv/v1/result/ok";
pub const DOMAIN_MANIFEST: &[u8] = b"tv/v1/manifest";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_distinct_and_namespaced() {
        let domains = [
            DOMAIN_COM,
            DOMAIN_STATE,
            DOMAIN_PAY,
            DOMAIN_REFRESH,
            DOMAIN_ENROLL,
            DOMAIN_RESULT,
            DOMAIN_MANIFEST,
        ];
        for (i, a) in domains.iter().enumerate() {
            for (j, b) in domains.iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
            assert!(a.starts_with(b"tv/v1/"));
        }
        assert_eq!(B_MAX, 1_000_000);
    }
}
