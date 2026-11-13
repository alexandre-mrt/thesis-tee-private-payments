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
