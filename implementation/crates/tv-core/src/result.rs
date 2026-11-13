use serde::{Deserialize, Serialize};

use crate::DOMAIN_RESULT;
use crate::error::CoreError;
use crate::sig::{Signature, SigningKey, VerifyingKey};
use crate::types::{Bytes32, SideKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveResult {
    pub bank_nonce: Bytes32,
    pub digest: Bytes32,
    pub sides: Vec<SideKind>,
    pub sig: Signature,
}

fn result_message(bank_nonce: &Bytes32, digest: &Bytes32, sides: &[SideKind]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN_RESULT.len() + 64 + sides.len());
    m.extend_from_slice(DOMAIN_RESULT);
    m.extend_from_slice(bank_nonce);
    m.extend_from_slice(digest);
    m.extend(sides.iter().map(|s| u8::from(s.is_bank())));
    m
}

pub fn sign_result(
    key: &SigningKey,
    bank_nonce: Bytes32,
    digest: Bytes32,
    sides: Vec<SideKind>,
) -> EnclaveResult {
    let sig = key.sign(&result_message(&bank_nonce, &digest, &sides));
    EnclaveResult {
        bank_nonce,
        digest,
        sides,
        sig,
    }
}

pub fn verify_result(
    result_pk: &Bytes32,
    result: &EnclaveResult,
    expected_nonce: &Bytes32,
    expected_digest: &Bytes32,
) -> Result<(), CoreError> {
    verify_result_with(
        &VerifyingKey::parse(result_pk)?,
        result,
        expected_nonce,
        expected_digest,
    )
}

pub fn verify_result_with(
    result_key: &VerifyingKey,
    result: &EnclaveResult,
    expected_nonce: &Bytes32,
    expected_digest: &Bytes32,
) -> Result<(), CoreError> {
    if result.bank_nonce != *expected_nonce || result.digest != *expected_digest {
        return Err(CoreError::BadSignature);
    }
    result_key.verify(
        &result_message(&result.bank_nonce, &result.digest, &result.sides),
        &result.sig,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_binds_nonce_digest_sides_and_key() {
        let key = SigningKey::generate();
        let pk = key.public_key();
        let n = [1u8; 32];
        let m = [2u8; 32];
        let r = sign_result(&key, n, m, vec![SideKind::User, SideKind::Bank]);
        assert!(verify_result(&pk, &r, &n, &m).is_ok());
        assert!(verify_result(&pk, &r, &[3u8; 32], &m).is_err());
        assert!(verify_result(&pk, &r, &n, &[3u8; 32]).is_err());
        let mut other_nonce = r.clone();
        other_nonce.bank_nonce = [3u8; 32];
        assert!(verify_result(&pk, &other_nonce, &[3u8; 32], &m).is_err());
        let mut flipped = r.clone();
        flipped.sides = vec![SideKind::Bank, SideKind::User];
        assert!(verify_result(&pk, &flipped, &n, &m).is_err());
        let other = SigningKey::generate().public_key();
        assert!(verify_result(&other, &r, &n, &m).is_err());
    }
}
