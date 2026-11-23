use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CoreError;
use crate::sig::{SigningKey, VerifyingKey};
use crate::types::Bytes32;
use crate::{HKDF_SALT, LABEL_DV, LABEL_NCTX, LABEL_PAIR, LABEL_RV};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairSecret {
    k_ab: Bytes32,
}

impl std::fmt::Debug for PairSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairSecret(..)")
    }
}

fn weak_peer() -> CoreError {
    CoreError::InvalidKeyMaterial {
        what: "peer key for a pair secret",
    }
}

pub fn x25519_with(own: &SigningKey, peer: &Bytes32) -> Result<Bytes32, CoreError> {
    let peer_key = VerifyingKey::parse(peer)?;
    if peer_key.is_weak() || own.public_key() == *peer {
        return Err(weak_peer());
    }
    let secret = StaticSecret::from(own.scalar_bytes());
    let shared = secret.diffie_hellman(&PublicKey::from(peer_key.montgomery()));
    if !shared.was_contributory() {
        return Err(weak_peer());
    }
    Ok(shared.to_bytes())
}

fn expand(prk: &Bytes32, label: &[u8]) -> Result<Bytes32, CoreError> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CoreError::Derivation)?;
    let mut out = [0u8; 32];
    hk.expand(label, &mut out)
        .map_err(|_| CoreError::Derivation)?;
    Ok(out)
}

fn extract(
    ikm: &Bytes32,
    label: &[u8],
    pk_a: &Bytes32,
    pk_b: &Bytes32,
) -> Result<Bytes32, CoreError> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut info = Vec::with_capacity(label.len() + 64);
    info.extend_from_slice(label);
    info.extend_from_slice(pk_a);
    info.extend_from_slice(pk_b);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|_| CoreError::Derivation)?;
    Ok(out)
}

impl PairSecret {
    pub fn derive(own: &SigningKey, pk_a: &Bytes32, pk_b: &Bytes32) -> Result<Self, CoreError> {
        let mine = own.public_key();
        let peer = match (mine == *pk_a, mine == *pk_b) {
            (true, false) => pk_b,
            (false, true) => pk_a,
            _ => {
                return Err(CoreError::InvalidKeyMaterial {
                    what: "own key for a pair secret",
                });
            }
        };
        let mut dh = x25519_with(own, peer)?;
        let k_ab = extract(&dh, LABEL_PAIR, pk_a, pk_b);
        dh.zeroize();
        Ok(Self { k_ab: k_ab? })
    }

    pub fn r_v(&self) -> Result<Bytes32, CoreError> {
        expand(&self.k_ab, LABEL_RV)
    }

    pub fn n_ctx(&self) -> Result<Bytes32, CoreError> {
        expand(&self.k_ab, LABEL_NCTX)
    }
}

pub fn designated_key(own: &SigningKey, peer: &Bytes32) -> Result<Bytes32, CoreError> {
    let mut dh = x25519_with(own, peer)?;
    let mine = own.public_key();
    let (first, second) = if mine < *peer {
        (&mine, peer)
    } else {
        (peer, &mine)
    };
    let key = extract(&dh, LABEL_DV, first, second);
    dh.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn openings(secret: &PairSecret) -> (Bytes32, Bytes32) {
        (secret.r_v().unwrap(), secret.n_ctx().unwrap())
    }

    proptest! {
        #[test]
        fn nr3_both_owners_derive_the_same_secret_and_any_key_change_moves_it(
            a in any::<[u8; 32]>(),
            b in any::<[u8; 32]>(),
            c in any::<[u8; 32]>(),
        ) {
            prop_assume!(a != b && a != c && b != c);
            let (sk_a, sk_b, sk_c) = (SigningKey::from_bytes(&a), SigningKey::from_bytes(&b), SigningKey::from_bytes(&c));
            let (pk_a, pk_b, pk_c) = (sk_a.public_key(), sk_b.public_key(), sk_c.public_key());
            let alice = openings(&PairSecret::derive(&sk_a, &pk_a, &pk_b).unwrap());
            let bob = openings(&PairSecret::derive(&sk_b, &pk_a, &pk_b).unwrap());
            prop_assert_eq!(alice, bob);
            prop_assert_ne!(alice.0, alice.1);
            let other_payee = openings(&PairSecret::derive(&sk_a, &pk_a, &pk_c).unwrap());
            let other_payer = openings(&PairSecret::derive(&sk_c, &pk_c, &pk_b).unwrap());
            prop_assert_ne!(alice, other_payee);
            prop_assert_ne!(alice, other_payer);
            let swapped = openings(&PairSecret::derive(&sk_a, &pk_b, &pk_a).unwrap());
            prop_assert_ne!(alice, swapped);
        }
    }

    #[test]
    fn nr8_a_small_order_or_invalid_peer_key_fails_on_both_sides() {
        let alice = key(1);
        let pk_a = alice.public_key();
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut order_two = [0u8; 32];
        order_two[0] = 0xec;
        order_two[1..31].fill(0xff);
        order_two[31] = 0x7f;
        for weak in [identity, order_two] {
            assert!(VerifyingKey::parse(&weak).is_ok_and(|k| k.is_weak()));
            assert!(PairSecret::derive(&alice, &pk_a, &weak).is_err());
            assert!(PairSecret::derive(&alice, &weak, &pk_a).is_err());
            assert!(designated_key(&alice, &weak).is_err());
        }
        let invalid = (0u8..=255)
            .map(|b| [b; 32])
            .find(|bytes| VerifyingKey::parse(bytes).is_err())
            .unwrap();
        assert!(PairSecret::derive(&alice, &pk_a, &invalid).is_err());
    }

    #[test]
    fn a_key_that_is_neither_side_or_both_sides_is_refused() {
        let (alice, bob, carol) = (key(1), key(2), key(3));
        let (pk_a, pk_b) = (alice.public_key(), bob.public_key());
        assert!(PairSecret::derive(&carol, &pk_a, &pk_b).is_err());
        assert!(PairSecret::derive(&alice, &pk_a, &pk_a).is_err());
        assert_eq!(
            format!("{:?}", PairSecret::derive(&alice, &pk_a, &pk_b).unwrap()),
            "PairSecret(..)"
        );
    }

    #[test]
    fn designated_keys_agree_between_prover_and_verifier_only() {
        let (prover, verifier, other) = (key(4), key(5), key(6));
        let tag_key = designated_key(&prover, &verifier.public_key()).unwrap();
        assert_eq!(
            tag_key,
            designated_key(&verifier, &prover.public_key()).unwrap()
        );
        assert_ne!(
            tag_key,
            designated_key(&other, &prover.public_key()).unwrap()
        );
    }
}
