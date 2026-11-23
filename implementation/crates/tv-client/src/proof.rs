use std::path::Path;

use tv_core::{
    AmountOpening, BankVerifiers, Bytes32, ContextOpening, LogEntry, OpKind, PairSecret,
    Presentation, Proof, ProofFacts, ProofKeys, Role, SigningKey, VerifyingKey, amount_commitment,
    context_hash, designated_tag, sign_presentation, verify_proof,
};

use crate::error::ClientError;
use crate::files::{read_json, write_json};
use crate::ops::Session;
use crate::recover::{Debits, verify_chain, walk};
use crate::wallet::Wallet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Payer,
    Payee,
    Amount,
    Designated { verifier_pk: Bytes32 },
}

struct Holding {
    role: Role,
    key: SigningKey,
    v: u64,
}

fn cannot(reason: &'static str) -> ClientError {
    ClientError::Prove { reason }
}

fn holding(wallet: &Wallet, log: &[LogEntry], entry: &LogEntry) -> Result<Holding, ClientError> {
    let walked = walk(wallet, log, None, &Debits::new())?;
    let step = walked
        .steps
        .iter()
        .find(|step| step.seq == entry.seq)
        .ok_or(cannot(
            "this wallet's serials did not take part in that entry",
        ))?;
    let key = wallet.key_at(step.index)?;
    let role = match entry.serials.iter().position(|s| *s == key.public_key()) {
        Some(0) => Role::Payer,
        Some(_) => Role::Payee,
        None => return Err(cannot("the entry does not spend this wallet's serial")),
    };
    let v = step.before.abs_diff(step.after);
    Ok(Holding { role, key, v })
}

fn context(
    wallet: &Wallet,
    pair: &PairSecret,
    entry: &LogEntry,
) -> Result<Option<ContextOpening>, ClientError> {
    let n_ctx = pair.n_ctx()?;
    let memo = wallet
        .memo_for(&entry.digest)
        .unwrap_or_default()
        .to_owned();
    let opens = entry.h_ctx == Some(context_hash(&n_ctx, memo.as_bytes())?);
    Ok(opens.then_some(ContextOpening { n_ctx, memo }))
}

fn presentation(
    h: &Holding,
    mode: Mode,
    entry: &LogEntry,
    challenge: &Bytes32,
) -> Result<Presentation, ClientError> {
    let role = h.role;
    Ok(match mode {
        Mode::Payer | Mode::Payee if (mode == Mode::Payer) != (role == Role::Payer) => {
            return Err(cannot("this wallet holds the other side of that payment"));
        }
        Mode::Payer | Mode::Payee => Presentation::Signed {
            role,
            sig: sign_presentation(&h.key, role, entry, challenge),
        },
        Mode::Amount => Presentation::Amount,
        Mode::Designated { verifier_pk } => Presentation::Designated {
            role,
            verifier_pk,
            tag: designated_tag(&h.key, &verifier_pk, role, entry, challenge)?,
        },
    })
}

pub fn prove(
    wallet: &Wallet,
    log: &[LogEntry],
    seq: u64,
    mode: Mode,
    challenge: Bytes32,
) -> Result<Proof, ClientError> {
    verify_chain(wallet, log)?;
    let entry = usize::try_from(seq)
        .ok()
        .and_then(|i| log.get(i))
        .filter(|e| e.kind == OpKind::Pay)
        .ok_or(cannot("no payment at that position of the log"))?;
    let [pk_a, pk_b] = entry.serials.as_slice() else {
        return Err(cannot("a payment entry names two serials"));
    };
    let h = holding(wallet, log, entry)?;
    let pair = PairSecret::derive(&h.key, pk_a, pk_b)?;
    let amount = AmountOpening {
        v: h.v,
        r_v: pair.r_v()?,
    };
    if entry.c_v != Some(amount_commitment(amount.v, &amount.r_v)) {
        return Err(cannot(
            "the amount commitment does not open to this wallet's amount",
        ));
    }
    Ok(Proof {
        entry: entry.clone(),
        amount,
        context: context(wallet, &pair, entry)?,
        challenge,
        presentation: presentation(&h, mode, entry, &challenge)?,
    })
}

pub fn check(
    wallet: &Wallet,
    proof: &Proof,
    challenge: &Bytes32,
    verifier: Option<&SigningKey>,
) -> Result<ProofFacts, ClientError> {
    let bank = BankVerifiers::parse(&wallet.bank())?;
    let receipt = VerifyingKey::parse(&wallet.receipt_pk())?;
    let keys = ProofKeys {
        bank: &bank,
        receipt: &receipt,
    };
    Ok(verify_proof(&keys, proof, challenge, verifier)?)
}

fn describe(facts: &ProofFacts) -> String {
    let memo = facts
        .memo
        .as_deref()
        .map_or("not opened".to_owned(), |m| format!("{m:?}"));
    let holder = match facts.holder {
        Some((role, pk)) => format!("{role:?} key {}", hex::encode(pk)),
        None => "nobody (amount only)".to_owned(),
    };
    let kind = if facts.transferable {
        "transferable"
    } else {
        "not transferable"
    };
    format!(
        "proof verified: payment {} in epoch {} moved {}, memo {memo}, presented by {holder} ({kind})",
        facts.seq, facts.epoch, facts.v
    )
}

impl Session {
    pub async fn prove_payment(
        &self,
        seq: u64,
        mode: Mode,
        challenge: Bytes32,
        out: &Path,
    ) -> Result<String, ClientError> {
        let wallet = Wallet::load(self.wallet_path())?;
        let log = self.bank().full_log().await?;
        let proof = prove(&wallet, &log, seq, mode, challenge)?;
        write_json(out, "proof", &proof)?;
        Ok(format!(
            "proof of payment {seq} written to {}",
            out.display()
        ))
    }

    pub fn verify_payment(
        &self,
        proof: &Path,
        challenge: &Bytes32,
        verifier: Option<&SigningKey>,
    ) -> Result<String, ClientError> {
        let wallet = Wallet::load(self.wallet_path())?;
        let proof: Proof = read_json(proof, "proof")?;
        Ok(describe(&check(&wallet, &proof, challenge, verifier)?))
    }
}
