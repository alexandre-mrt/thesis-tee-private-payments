use sha2::{Digest, Sha256};

use crate::types::{Bytes32, Manifest};
use crate::{DOMAIN_COM, DOMAIN_ENROLL, DOMAIN_MANIFEST, DOMAIN_PAY, DOMAIN_REFRESH};

pub fn commitment(balance: u64, pk: &Bytes32, r: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_COM);
    h.update(balance.to_be_bytes());
    h.update(pk);
    h.update(r);
    h.finalize().into()
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
