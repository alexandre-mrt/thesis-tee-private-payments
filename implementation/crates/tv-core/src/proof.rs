#[cfg(test)]
mod tests;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::commit::{amount_commitment, context_hash};
use crate::entry::LogEntry;
use crate::error::CoreError;
use crate::pair::designated_key;
use crate::sig::{BankVerifiers, Signature, SigningKey, VerifyingKey};
use crate::types::Bytes32;
use crate::wire::OpKind;
use crate::{DOMAIN_DV, DOMAIN_POP};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Payer,
    Payee,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Payer => 0,
            Role::Payee => 1,
        }
    }

    fn index(self) -> usize {
        usize::from(self.byte())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmountOpening {
    pub v: u64,
    pub r_v: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextOpening {
    pub n_ctx: Bytes32,
    pub memo: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presentation {
    Amount,
    Signed {
        role: Role,
        sig: Signature,
    },
    Designated {
        role: Role,
        verifier_pk: Bytes32,
        tag: Bytes32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub entry: LogEntry,
    pub amount: AmountOpening,
    pub context: Option<ContextOpening>,
    pub challenge: Bytes32,
    pub presentation: Presentation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofFacts {
    pub seq: u64,
    pub epoch: u64,
    pub v: u64,
    pub memo: Option<String>,
    pub holder: Option<(Role, Bytes32)>,
    pub transferable: bool,
}

pub struct ProofKeys<'a> {
    pub bank: &'a BankVerifiers,
    pub receipt: &'a VerifyingKey,
}

fn refused(what: &'static str) -> CoreError {
    CoreError::BadProof { what }
}

pub fn presentation_digest(role: Role, entry: &LogEntry, challenge: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN_POP);
    h.update([role.byte()]);
    h.update(entry.seq.to_be_bytes());
    h.update(entry.digest);
    h.update(challenge);
    h.finalize().into()
}

pub fn sign_presentation(
    own: &SigningKey,
    role: Role,
    entry: &LogEntry,
    challenge: &Bytes32,
) -> Signature {
    own.sign(&presentation_digest(role, entry, challenge))
}

fn tag_mac(
    key: &Bytes32,
    role: Role,
    entry: &LogEntry,
    challenge: &Bytes32,
) -> Result<Hmac<Sha256>, CoreError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| CoreError::Derivation)?;
    mac.update(DOMAIN_DV);
    mac.update(&presentation_digest(role, entry, challenge));
    Ok(mac)
}

pub fn designated_tag(
    own: &SigningKey,
    peer: &Bytes32,
    role: Role,
    entry: &LogEntry,
    challenge: &Bytes32,
) -> Result<Bytes32, CoreError> {
    let mac = tag_mac(&designated_key(own, peer)?, role, entry, challenge)?;
    Ok(mac.finalize().into_bytes().into())
}

fn holder_key(entry: &LogEntry, role: Role) -> Result<Bytes32, CoreError> {
    entry
        .serials
        .get(role.index())
        .copied()
        .ok_or(refused("holder serial"))
}

fn check_settlement(keys: &ProofKeys<'_>, entry: &LogEntry) -> Result<(), CoreError> {
    if entry.kind != OpKind::Pay {
        return Err(refused("entry is not a payment"));
    }
    entry
        .verify_receipt(keys.receipt)
        .map_err(|_| refused("receipt (V1)"))?;
    entry
        .verify_owners()
        .map_err(|_| refused("owner signatures on m (V2, V3)"))?;
    let state_signed = entry.commitments.iter().zip(&entry.sigs).all(|(com, sig)| {
        keys.bank.state.verify_state(com, sig).is_ok()
            || keys.bank.issuance.verify_state(com, sig).is_ok()
    });
    if !state_signed {
        return Err(refused("bank state signatures (V4)"));
    }
    Ok(())
}

fn check_openings(proof: &Proof) -> Result<Option<String>, CoreError> {
    let e = &proof.entry;
    if e.c_v != Some(amount_commitment(proof.amount.v, &proof.amount.r_v)) {
        return Err(refused("amount opening (V5)"));
    }
    let Some(ctx) = &proof.context else {
        return Ok(None);
    };
    if e.h_ctx != Some(context_hash(&ctx.n_ctx, ctx.memo.as_bytes())?) {
        return Err(refused("context opening (V6)"));
    }
    Ok(Some(ctx.memo.clone()))
}

fn check_presentation(
    proof: &Proof,
    verifier: Option<&SigningKey>,
) -> Result<Option<(Role, Bytes32)>, CoreError> {
    let entry = &proof.entry;
    match proof.presentation {
        Presentation::Amount => Ok(None),
        Presentation::Signed { role, sig } => {
            let holder = holder_key(entry, role)?;
            VerifyingKey::parse(&holder)?
                .verify(&presentation_digest(role, entry, &proof.challenge), &sig)
                .map_err(|_| refused("presentation signature (V7)"))?;
            Ok(Some((role, holder)))
        }
        Presentation::Designated {
            role,
            verifier_pk,
            tag,
        } => {
            let verifier = verifier.ok_or(refused("designated proof without the verifier key"))?;
            if verifier.public_key() != verifier_pk {
                return Err(refused("designated for another verifier"));
            }
            let holder = holder_key(entry, role)?;
            tag_mac(
                &designated_key(verifier, &holder)?,
                role,
                entry,
                &proof.challenge,
            )?
            .verify_slice(&tag)
            .map_err(|_| refused("designated tag (V7)"))?;
            Ok(Some((role, holder)))
        }
    }
}

pub fn verify_proof(
    keys: &ProofKeys<'_>,
    proof: &Proof,
    challenge: &Bytes32,
    verifier: Option<&SigningKey>,
) -> Result<ProofFacts, CoreError> {
    if proof.challenge != *challenge {
        return Err(refused("challenge"));
    }
    check_settlement(keys, &proof.entry)?;
    let memo = check_openings(proof)?;
    let holder = check_presentation(proof, verifier)?;
    Ok(ProofFacts {
        seq: proof.entry.seq,
        epoch: proof.entry.epoch,
        v: proof.amount.v,
        memo,
        holder,
        transferable: matches!(proof.presentation, Presentation::Signed { .. }),
    })
}
