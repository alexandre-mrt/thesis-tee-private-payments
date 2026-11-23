use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::types::{Bytes32, Manifest};
use crate::{
    DOMAIN_AMT, DOMAIN_COM, DOMAIN_CTX, DOMAIN_ENROLL, DOMAIN_MANIFEST, DOMAIN_PAY, DOMAIN_REFRESH,
    MAX_MEMO_LEN,
};

pub fn commitment(balance: u64, pk: &Bytes32, r: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_COM);
    h.update(balance.to_be_bytes());
    h.update(pk);
    h.update(r);
    h.finalize().into()
}

pub fn amount_commitment(v: u64, r_v: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_AMT);
    h.update(v.to_be_bytes());
    h.update(r_v);
    h.finalize().into()
}

pub fn context_hash(n_ctx: &Bytes32, memo: &[u8]) -> Result<Bytes32, CoreError> {
    let too_long = CoreError::MemoTooLong {
        len: memo.len(),
        max: MAX_MEMO_LEN,
    };
    if memo.len() > MAX_MEMO_LEN {
        return Err(too_long);
    }
    let len = u32::try_from(memo.len()).map_err(|_| too_long)?;
    let mut h = Sha256::new();
    h.update(DOMAIN_CTX);
    h.update(n_ctx);
    h.update(len.to_be_bytes());
    h.update(memo);
    Ok(h.finalize().into())
}

pub fn pay_digest(
    pk_a: &Bytes32,
    com_a_next: &Bytes32,
    pk_b: &Bytes32,
    com_b_next: &Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_PAY);
    h.update(pk_a);
    h.update(com_a_next);
    h.update(pk_b);
    h.update(com_b_next);
    h.finalize().into()
}

pub fn refresh_digest(pk: &Bytes32, com_next: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_REFRESH);
    h.update(pk);
    h.update(com_next);
    h.finalize().into()
}

pub fn enroll_digest(pk0: &Bytes32, com0: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_ENROLL);
    h.update(pk0);
    h.update(com0);
    h.finalize().into()
}

pub fn manifest_digest(manifest: &Manifest) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_MANIFEST);
    h.update(manifest.result_pk);
    h.update(manifest.bank.state_pk);
    h.update(manifest.bank.issuance_pk);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BankKeys;

    #[test]
    fn commitments_bind_every_field() {
        let c = commitment(5, &[1u8; 32], &[2u8; 32]);
        assert_ne!(c, commitment(6, &[1u8; 32], &[2u8; 32]));
        assert_ne!(c, commitment(5, &[3u8; 32], &[2u8; 32]));
        assert_ne!(c, commitment(5, &[1u8; 32], &[4u8; 32]));
        assert_eq!(c, commitment(5, &[1u8; 32], &[2u8; 32]));
    }

    #[test]
    fn amount_commitments_bind_amount_and_blind() {
        let r = [5u8; 32];
        let c = amount_commitment(7, &r);
        assert_eq!(c, amount_commitment(7, &r));
        assert_ne!(c, amount_commitment(8, &r));
        assert_ne!(c, amount_commitment(7, &[6u8; 32]));
        assert_ne!(c, commitment(7, &r, &r));
    }

    #[test]
    fn context_hashes_bind_nonce_and_memo_and_bound_the_memo() {
        let n = [1u8; 32];
        let empty = context_hash(&n, b"").unwrap();
        assert_ne!(empty, context_hash(&[2u8; 32], b"").unwrap());
        assert_ne!(empty, context_hash(&n, b"invoice 42").unwrap());
        assert_ne!(
            context_hash(&n, b"ab").unwrap(),
            context_hash(&n, b"a").unwrap()
        );
        assert!(context_hash(&n, &[0u8; MAX_MEMO_LEN]).is_ok());
        assert_eq!(
            context_hash(&n, &[0u8; MAX_MEMO_LEN + 1]),
            Err(CoreError::MemoTooLong {
                len: MAX_MEMO_LEN + 1,
                max: MAX_MEMO_LEN
            })
        );
    }

    #[test]
    fn digests_are_domain_separated_and_amount_free() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let pay = pay_digest(&a, &b, &a, &b);
        assert_ne!(pay, pay_digest(&b, &a, &a, &b));
        assert_ne!(pay, pay_digest(&a, &b, &b, &a));
        assert_ne!(refresh_digest(&a, &b), enroll_digest(&a, &b));
        let m = Manifest {
            result_pk: a,
            bank: BankKeys {
                state_pk: b,
                issuance_pk: a,
            },
        };
        let swapped = Manifest {
            result_pk: a,
            bank: BankKeys {
                state_pk: a,
                issuance_pk: b,
            },
        };
        assert_ne!(manifest_digest(&m), manifest_digest(&swapped));
    }
}
