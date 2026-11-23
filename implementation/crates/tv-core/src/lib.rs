#![forbid(unsafe_code)]

use std::time::Duration;

pub mod cbor;
pub mod commit;
pub mod derive;
pub mod entry;
pub mod error;
pub mod evidence;
pub mod pair;
pub mod proof;
pub mod receipt;
pub mod result;
pub mod sig;
pub mod types;
pub mod wire;

pub use cbor::{decode_cbor, encode_cbor};
pub use commit::{
    PayFields, amount_commitment, commitment, context_hash, enroll_digest, manifest_digest,
    pay_digest, refresh_digest,
};
pub use derive::{Seed, derive_r, derive_sk};
pub use entry::LogEntry;
pub use error::CoreError;
pub use evidence::{chain_genesis, chain_next, entry_hash, receipt_digest};
pub use pair::{PairSecret, designated_key};
pub use proof::{
    AmountOpening, ContextOpening, Presentation, Proof, ProofFacts, ProofKeys, Role,
    designated_tag, sign_presentation, verify_proof,
};
pub use receipt::{Receipt, epoch_of, is_fork};
pub use result::{EnclaveResult, sign_result, verify_result, verify_result_with};
pub use sig::{
    BankVerifiers, SIG_LEN, Signature, SigningKey, VerifyingKey, sign_digest, sign_state,
    verify_digest, verify_state,
};
pub use types::{
    BankKeys, Bytes32, Manifest, Opening, SideKind, SignedState, State, random_bytes32,
};
pub use wire::{
    BankRequest, BankResponse, CheckOp, EnclaveRequest, EnclaveResponse, EnrollRequest,
    EnrollSecret, OpKind, PayPublic, PaySecret, Receive, RefreshRequest, RefreshSecret, SealedBlob,
};

pub const B_MAX: u64 = 1_000_000;

pub const ATTEST_NONCE_LEN: usize = 32;

pub const MAX_PENDING_KEYS: usize = 1 << 16;

pub const MAX_KEY_AGE: Duration = Duration::from_secs(10 * 60);

pub const ATTEST_CLOCK_SKEW: Duration = Duration::from_secs(30);

pub const HKDF_SALT: &[u8] = b"tv/v1";
pub const LABEL_SK: &[u8] = b"sk";
pub const LABEL_R: &[u8] = b"r";
pub const LABEL_PAIR: &[u8] = b"pair";
pub const LABEL_RV: &[u8] = b"rv";
pub const LABEL_NCTX: &[u8] = b"ctx";
pub const LABEL_DV: &[u8] = b"dv";
pub const DOMAIN_COM: &[u8] = b"tv/v1/com";
pub const DOMAIN_STATE: &[u8] = b"tv/v1/state";
pub const DOMAIN_PAY: &[u8] = b"tv/v1/pay/2";
pub const DOMAIN_REFRESH: &[u8] = b"tv/v1/refresh";
pub const DOMAIN_ENROLL: &[u8] = b"tv/v1/enroll";
pub const DOMAIN_RESULT: &[u8] = b"tv/v1/result/ok";
pub const DOMAIN_MANIFEST: &[u8] = b"tv/v1/manifest";
pub const DOMAIN_AMT: &[u8] = b"tv/v1/amt";
pub const DOMAIN_CTX: &[u8] = b"tv/v1/ctx";
pub const DOMAIN_ENTRY: &[u8] = b"tv/v1/entry";
pub const DOMAIN_CHAIN: &[u8] = b"tv/v1/chain";
pub const DOMAIN_CHAIN0: &[u8] = b"tv/v1/chain/0";
pub const DOMAIN_RCPT: &[u8] = b"tv/v1/rcpt";
pub const DOMAIN_POP: &[u8] = b"tv/v1/pop";
pub const DOMAIN_DV: &[u8] = b"tv/v1/dv";

pub const MAX_MEMO_LEN: usize = 1024;

pub const EPOCH_SECS: u64 = 3600;

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
            DOMAIN_AMT,
            DOMAIN_CTX,
            DOMAIN_ENTRY,
            DOMAIN_CHAIN,
            DOMAIN_CHAIN0,
            DOMAIN_RCPT,
            DOMAIN_POP,
            DOMAIN_DV,
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
