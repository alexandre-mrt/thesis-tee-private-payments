use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::CoreError;
use crate::sig::SigningKey;
use crate::types::{Bytes32, random_bytes32};
use crate::{HKDF_SALT, LABEL_R, LABEL_SK};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seed(pub Bytes32);

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(..)")
    }
}

impl Seed {
    pub fn generate() -> Self {
        Self(random_bytes32())
    }

    pub fn from_hex(text: &str) -> Result<Self, CoreError> {
        let bytes = hex::decode(text.trim())
            .map_err(|_| CoreError::InvalidKeyMaterial { what: "seed hex" })?;
        let seed: Bytes32 = bytes
            .try_into()
            .map_err(|_| CoreError::InvalidKeyMaterial {
                what: "seed length",
            })?;
        Ok(Self(seed))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

fn expand(seed: &Seed, label: &[u8], index: u64) -> Result<Bytes32, CoreError> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &seed.0);
    let mut info = Vec::with_capacity(label.len() + 8);
    info.extend_from_slice(label);
    info.extend_from_slice(&index.to_be_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|_| CoreError::Derivation)?;
    Ok(out)
}

pub fn derive_sk(seed: &Seed, index: u64) -> Result<SigningKey, CoreError> {
    Ok(SigningKey::from_bytes(&expand(seed, LABEL_SK, index)?))
}

pub fn derive_r(seed: &Seed, index: u64) -> Result<Bytes32, CoreError> {
    expand(seed, LABEL_R, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_index_separated() {
        let seed = Seed::generate();
        let a = derive_sk(&seed, 0).unwrap();
        let b = derive_sk(&seed, 0).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), derive_sk(&seed, 1).unwrap().public_key());
        assert_ne!(derive_r(&seed, 0).unwrap(), derive_r(&seed, 1).unwrap());
        assert_ne!(derive_r(&seed, 0).unwrap(), a.to_bytes());
        let other = Seed::generate();
        assert_ne!(derive_sk(&other, 0).unwrap().public_key(), a.public_key());
    }

    #[test]
    fn seed_hex_roundtrip() {
        let seed = Seed::generate();
        assert_eq!(Seed::from_hex(&seed.to_hex()).unwrap(), seed);
        assert!(Seed::from_hex("zz").is_err());
        assert!(Seed::from_hex(&"ab".repeat(31)).is_err());
        assert_eq!(format!("{seed:?}"), "Seed(..)");
    }
}
