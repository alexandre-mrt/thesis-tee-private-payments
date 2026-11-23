use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;
use tv_bank::Store;
use tv_core::{
    AmountOpening, BankKeys, BankVerifiers, Bytes32, ContextOpening, LogEntry, OpKind, PairSecret,
    Presentation, Proof, ProofKeys, Role, Signature, SigningKey, VerifyingKey, chain_genesis,
    designated_tag, sign_presentation, sign_state, verify_proof,
};

use crate::profile::time;

const MEMO: &[u8] = b"invoice 2026-118";
const CHALLENGE: Bytes32 = [42u8; 32];

struct World {
    alice: SigningKey,
    bob_pk: Bytes32,
    verifier: SigningKey,
    receipt: SigningKey,
    bank: BankVerifiers,
    receipt_pk: VerifyingKey,
    unsealed: LogEntry,
    entry: LogEntry,
    amount: AmountOpening,
    context: ContextOpening,
}

fn entry(alice: &SigningKey, bob: &SigningKey, state: &SigningKey) -> Result<LogEntry> {
    let (pk_a, pk_b) = (alice.public_key(), bob.public_key());
    let pair = PairSecret::derive(alice, &pk_a, &pk_b)?;
    let commitments = vec![[7u8; 32], [8u8; 32]];
    let unsigned = LogEntry {
        seq: 0,
        kind: OpKind::Pay,
        serials: vec![pk_a, pk_b],
        sigs: commitments.iter().map(|c| sign_state(state, c)).collect(),
        commitments,
        owner_sigs: Vec::new(),
        digest: [0u8; 32],
        c_v: Some(pair.amount_commitment(1)?),
        h_ctx: Some(pair.context_hash(MEMO)?),
        epoch: 0,
        chain: [0u8; 32],
        rcpt: Signature([0u8; 64]),
    };
    let digest = unsigned.recomputed_digest()?;
    Ok(LogEntry {
        owner_sigs: vec![alice.sign(&digest), bob.sign(&digest)],
        digest,
        ..unsigned
    })
}

fn world() -> Result<World> {
    let (alice, bob) = (SigningKey::generate(), SigningKey::generate());
    let (state, receipt) = (SigningKey::generate(), SigningKey::generate());
    let unsealed = entry(&alice, &bob, &state)?;
    let entry = unsealed
        .clone()
        .sealed(&chain_genesis(&receipt.public_key()), &receipt);
    let pair = PairSecret::derive(&alice, &alice.public_key(), &bob.public_key())?;
    Ok(World {
        bank: BankVerifiers::parse(&BankKeys {
            state_pk: state.public_key(),
            issuance_pk: SigningKey::generate().public_key(),
        })?,
        receipt_pk: VerifyingKey::parse(&receipt.public_key())?,
        amount: AmountOpening {
            v: 1,
            r_v: pair.r_v()?,
        },
        context: ContextOpening {
            n_ctx: pair.n_ctx()?,
            memo: String::from_utf8_lossy(MEMO).into_owned(),
        },
        bob_pk: bob.public_key(),
        verifier: SigningKey::generate(),
        unsealed,
        entry,
        alice,
        receipt,
    })
}

fn proof(w: &World, presentation: Presentation) -> Proof {
    Proof {
        entry: w.entry.clone(),
        amount: w.amount,
        context: Some(w.context.clone()),
        challenge: CHALLENGE,
        presentation,
    }
}

fn proofs(w: &World) -> Result<(Proof, Proof)> {
    let role = Role::Payer;
    let signed = Presentation::Signed {
        role,
        sig: sign_presentation(&w.alice, role, &w.entry, &CHALLENGE),
    };
    let tag = designated_tag(
        &w.alice,
        &w.verifier.public_key(),
        role,
        &w.entry,
        &CHALLENGE,
    )?;
    let designated = Presentation::Designated {
        role,
        verifier_pk: w.verifier.public_key(),
        tag,
    };
    Ok((proof(w, signed), proof(w, designated)))
}

pub fn costs(n: usize) -> Result<Vec<(&'static str, Duration)>> {
    let w = world()?;
    let (signed, designated) = proofs(&w)?;
    let keys = ProofKeys {
        bank: &w.bank,
        receipt: &w.receipt_pk,
    };
    let genesis = chain_genesis(&w.receipt.public_key());
    let (pk_a, bob_pk) = (w.alice.public_key(), w.bob_pk);
    Ok(vec![
        (
            "evidence: pair secret + C_v + h_ctx (per party)",
            time(n, || -> Result<_> {
                let pair = PairSecret::derive(&w.alice, &pk_a, &bob_pk)?;
                Ok((pair.amount_commitment(1)?, pair.context_hash(MEMO)?))
            }),
        ),
        (
            "evidence: seal entry (entry hash, chain, receipt signature)",
            time(n, || w.unsealed.clone().sealed(&genesis, &w.receipt)),
        ),
        (
            "evidence: verify receipt and chain link",
            time(n, || {
                w.entry
                    .verify_link(&genesis)
                    .and_then(|()| w.entry.verify_receipt(&w.receipt_pk))
            }),
        ),
        (
            "evidence: verify owner signatures of a Pay entry (B2 replay)",
            time(n, || w.entry.verify_owners()),
        ),
        (
            "evidence: prover, sign presentation",
            time(n, || {
                sign_presentation(&w.alice, Role::Payer, &w.entry, &CHALLENGE)
            }),
        ),
        (
            "evidence: verify_proof, payer mode",
            time(n, || verify_proof(&keys, &signed, &CHALLENGE, None)),
        ),
        (
            "evidence: verify_proof, designated mode",
            time(n, || {
                verify_proof(&keys, &designated, &CHALLENGE, Some(&w.verifier))
            }),
        ),
    ])
}

pub fn replay_per_entry(dir: &Path, entries: usize) -> Result<Duration> {
    let start = Instant::now();
    let store = Store::open(dir)?;
    let elapsed = start.elapsed();
    anyhow::ensure!(store.entries().len() == entries, "replay lost entries");
    Ok(elapsed.div_f64(entries.max(1) as f64))
}
