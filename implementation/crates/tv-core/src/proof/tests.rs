use proptest::prelude::*;

use super::*;
use crate::evidence::chain_genesis;
use crate::pair::PairSecret;
use crate::sig::sign_state;
use crate::types::BankKeys;

const MEMO: &str = "invoice 2026-118";

struct World {
    alice: SigningKey,
    bob: SigningKey,
    carol: SigningKey,
    bank: BankVerifiers,
    receipt: VerifyingKey,
    entry: LogEntry,
    amount: AmountOpening,
    context: ContextOpening,
}

fn world(v: u64) -> World {
    let (alice, bob, carol) = (
        SigningKey::from_bytes(&[1u8; 32]),
        SigningKey::from_bytes(&[2u8; 32]),
        SigningKey::from_bytes(&[3u8; 32]),
    );
    let (state, issuance, receipt) = (
        SigningKey::from_bytes(&[4u8; 32]),
        SigningKey::from_bytes(&[5u8; 32]),
        SigningKey::from_bytes(&[6u8; 32]),
    );
    let (pk_a, pk_b) = (alice.public_key(), bob.public_key());
    let pair = PairSecret::derive(&alice, &pk_a, &pk_b).unwrap();
    let commitments = vec![[7u8; 32], [8u8; 32]];
    let unsigned = LogEntry {
        seq: 3,
        kind: OpKind::Pay,
        serials: vec![pk_a, pk_b],
        sigs: commitments.iter().map(|c| sign_state(&state, c)).collect(),
        commitments,
        owner_sigs: Vec::new(),
        digest: [0u8; 32],
        c_v: Some(pair.amount_commitment(v).unwrap()),
        h_ctx: Some(pair.context_hash(MEMO.as_bytes()).unwrap()),
        epoch: 9,
        chain: [0u8; 32],
        rcpt: Signature([0u8; 64]),
    };
    let digest = unsigned.recomputed_digest().unwrap();
    let entry = LogEntry {
        owner_sigs: vec![alice.sign(&digest), bob.sign(&digest)],
        digest,
        ..unsigned
    }
    .sealed(&chain_genesis(&receipt.public_key()), &receipt);
    World {
        bank: BankVerifiers::parse(&BankKeys {
            state_pk: state.public_key(),
            issuance_pk: issuance.public_key(),
        })
        .unwrap(),
        receipt: VerifyingKey::parse(&receipt.public_key()).unwrap(),
        amount: AmountOpening {
            v,
            r_v: pair.r_v().unwrap(),
        },
        context: ContextOpening {
            n_ctx: pair.n_ctx().unwrap(),
            memo: MEMO.to_owned(),
        },
        entry,
        alice,
        bob,
        carol,
    }
}

const CHALLENGE: Bytes32 = [42u8; 32];

fn proof(w: &World, mode: usize) -> Proof {
    let (role, key) = match mode % 2 {
        0 => (Role::Payer, &w.alice),
        _ => (Role::Payee, &w.bob),
    };
    let presentation = match mode {
        0 | 1 => Presentation::Signed {
            role,
            sig: sign_presentation(key, role, &w.entry, &CHALLENGE),
        },
        2 => Presentation::Amount,
        _ => Presentation::Designated {
            role,
            verifier_pk: w.carol.public_key(),
            tag: designated_tag(key, &w.carol.public_key(), role, &w.entry, &CHALLENGE).unwrap(),
        },
    };
    Proof {
        entry: w.entry.clone(),
        amount: w.amount,
        context: Some(w.context.clone()),
        challenge: CHALLENGE,
        presentation,
    }
}

fn check(w: &World, p: &Proof, challenge: &Bytes32) -> Result<ProofFacts, CoreError> {
    let keys = ProofKeys {
        bank: &w.bank,
        receipt: &w.receipt,
    };
    verify_proof(&keys, p, challenge, Some(&w.carol))
}

fn flip(bytes: &mut [u8], at: usize) {
    let i = at % bytes.len();
    bytes[i] ^= 1;
}

fn mutate(p: &Proof, which: usize, at: usize) -> Option<Proof> {
    let mut m = p.clone();
    match (which, &mut m.presentation) {
        (0, _) => m.amount.v = m.amount.v.wrapping_add(1),
        (1, _) => flip(&mut m.amount.r_v, at),
        (2, _) => flip(&mut m.context.as_mut()?.n_ctx, at),
        (3, _) => m.context.as_mut()?.memo.push('x'),
        (4, Presentation::Amount) => return None,
        (4, _) => flip(&mut m.challenge, at),
        (5, _) => flip(m.entry.c_v.as_mut()?, at),
        (6, _) => flip(&mut m.entry.owner_sigs[at % 2].0, at),
        (7, _) => flip(&mut m.entry.sigs[at % 2].0, at),
        (8, _) => flip(&mut m.entry.rcpt.0, at),
        (9, _) => m.entry.seq += 1,
        (10, Presentation::Signed { sig, .. }) => flip(&mut sig.0, at),
        (10, Presentation::Designated { tag, .. }) => flip(tag, at),
        (11, Presentation::Signed { role, .. } | Presentation::Designated { role, .. }) => {
            *role = match role {
                Role::Payer => Role::Payee,
                Role::Payee => Role::Payer,
            }
        }
        _ => return None,
    }
    Some(m)
}

#[test]
fn honest_proofs_of_every_mode_verify_and_state_what_they_prove() {
    let w = world(250);
    for mode in 0..5 {
        let facts = check(&w, &proof(&w, mode), &CHALLENGE).unwrap();
        assert_eq!((facts.seq, facts.epoch, facts.v), (3, 9, 250));
        assert_eq!(facts.memo.as_deref(), Some(MEMO));
        assert_eq!(facts.transferable, mode < 2);
    }
    let payer = check(&w, &proof(&w, 0), &CHALLENGE).unwrap();
    assert_eq!(payer.holder, Some((Role::Payer, w.alice.public_key())));
    assert_eq!(check(&w, &proof(&w, 2), &CHALLENGE).unwrap().holder, None);
    let amount_only = Proof {
        context: None,
        ..proof(&w, 2)
    };
    assert_eq!(check(&w, &amount_only, &CHALLENGE).unwrap().memo, None);
}

#[test]
fn nr7_a_designated_tag_is_one_the_verifier_could_have_made_itself() {
    let w = world(17);
    let Presentation::Designated { tag, .. } = proof(&w, 3).presentation else {
        panic!("not designated");
    };
    let forged_by_verifier = designated_tag(
        &w.carol,
        &w.bob.public_key(),
        Role::Payee,
        &w.entry,
        &CHALLENGE,
    )
    .unwrap();
    assert_eq!(tag, forged_by_verifier);
    let keys = ProofKeys {
        bank: &w.bank,
        receipt: &w.receipt,
    };
    let other = SigningKey::from_bytes(&[9u8; 32]);
    assert!(verify_proof(&keys, &proof(&w, 3), &CHALLENGE, Some(&other)).is_err());
    assert!(verify_proof(&keys, &proof(&w, 3), &CHALLENGE, None).is_err());
}

#[test]
fn a_designated_proof_hides_who_presented_but_not_the_amount_or_context() {
    let w = world(17);
    let keys = ProofKeys {
        bank: &w.bank,
        receipt: &w.receipt,
    };
    let re_presented = Proof {
        presentation: Presentation::Amount,
        ..proof(&w, 3)
    };
    let facts = verify_proof(&keys, &re_presented, &CHALLENGE, None).unwrap();
    assert_eq!(facts.v, 17);
    assert_eq!(facts.memo.as_deref(), Some(MEMO));
    assert_eq!(facts.holder, None);
}

proptest! {
    #[test]
    fn nr7_any_changed_field_or_another_challenge_is_refused(
        v in 1u64..1_000_000,
        mode in 0usize..5,
        which in 0usize..12,
        at in 0usize..64,
    ) {
        let w = world(v);
        let honest = proof(&w, mode);
        prop_assert!(check(&w, &honest, &CHALLENGE).is_ok());
        let other_challenge = [at as u8 ^ 0x80; 32];
        prop_assert_eq!(check(&w, &honest, &other_challenge).is_err(), true);
        if let Some(changed) = mutate(&honest, which, at) {
            prop_assert!(check(&w, &changed, &changed.challenge).is_err());
        }
    }
}
