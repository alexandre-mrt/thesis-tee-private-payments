use ed25519_dalek::{Signer, VerifyingKey as DalekVerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::DOMAIN_STATE;
use crate::error::CoreError;
use crate::types::{BankKeys, Bytes32};

pub const SIG_LEN: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_bytes")] pub [u8; SIG_LEN]);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0))
    }
}

#[derive(Clone)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey(pk={})", hex::encode(self.public_key()))
    }
}

impl SigningKey {
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(bytes: &Bytes32) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> Bytes32 {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> Bytes32 {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message).to_bytes())
    }
}

#[derive(Clone)]
pub struct VerifyingKey {
    bytes: Bytes32,
    key: DalekVerifyingKey,
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifyingKey({})", hex::encode(self.bytes))
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl VerifyingKey {
    pub fn parse(pk: &Bytes32) -> Result<Self, CoreError> {
        let key = DalekVerifyingKey::from_bytes(pk).map_err(|_| CoreError::InvalidKeyMaterial {
            what: "Ed25519 public key",
        })?;
        Ok(Self { bytes: *pk, key })
    }

    pub fn to_bytes(&self) -> Bytes32 {
        self.bytes
    }

    pub fn is_weak(&self) -> bool {
        self.key.is_weak()
    }

    pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<(), CoreError> {
        self.key
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig.0))
            .map_err(|_| CoreError::BadSignature)
    }

    pub fn verify_state(&self, com: &Bytes32, sig: &Signature) -> Result<(), CoreError> {
        self.verify(&state_message(com), sig)
    }

    pub fn verify_digest(&self, digest: &Bytes32, sig: &Signature) -> Result<(), CoreError> {
        self.verify(digest, sig)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankVerifiers {
    pub state: VerifyingKey,
    pub issuance: VerifyingKey,
}

impl BankVerifiers {
    pub fn parse(keys: &BankKeys) -> Result<Self, CoreError> {
        Ok(Self {
            state: VerifyingKey::parse(&keys.state_pk)?,
            issuance: VerifyingKey::parse(&keys.issuance_pk)?,
        })
    }

    pub fn keys(&self) -> BankKeys {
        BankKeys {
            state_pk: self.state.to_bytes(),
            issuance_pk: self.issuance.to_bytes(),
        }
    }
}

pub fn verify(pk: &Bytes32, message: &[u8], sig: &Signature) -> Result<(), CoreError> {
    VerifyingKey::parse(pk)?.verify(message, sig)
}

fn state_message(com: &Bytes32) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN_STATE.len() + 32);
    m.extend_from_slice(DOMAIN_STATE);
    m.extend_from_slice(com);
    m
}

pub fn sign_state(key: &SigningKey, com: &Bytes32) -> Signature {
    key.sign(&state_message(com))
}

pub fn verify_state(pk: &Bytes32, com: &Bytes32, sig: &Signature) -> Result<(), CoreError> {
    verify(pk, &state_message(com), sig)
}

pub fn sign_digest(key: &SigningKey, digest: &Bytes32) -> Signature {
    key.sign(digest)
}

pub fn verify_digest(pk: &Bytes32, digest: &Bytes32, sig: &Signature) -> Result<(), CoreError> {
    verify(pk, digest, sig)
}
