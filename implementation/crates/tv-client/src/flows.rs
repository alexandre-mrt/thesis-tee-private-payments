use tracing::warn;
use tv_core::{
    BankRequest, BankResponse, Bytes32, EnrollRequest, EnrollSecret, OpKind, RefreshRequest,
    RefreshSecret, Signature, State, commitment, enroll_digest, refresh_digest, sign_digest,
};

use crate::bank::{Attested, BankClient, seal_to};
use crate::error::{ClientError, PAY_NOT_SETTLED, RETRY_ENROLL, RETRY_REFRESH};
use crate::files::ReceiptFile;
use crate::wallet::{Pending, Wallet};

pub fn check_manifest(wallet: &Wallet, attested: &Attested) -> Result<(), ClientError> {
    if attested.bundle.manifest.bank != wallet.bank() {
        return Err(ClientError::BankKeyMismatch);
    }
    Ok(())
}

pub async fn enroll(wallet: &mut Wallet, bank: &BankClient) -> Result<(), ClientError> {
    if wallet.state().is_some() {
        return Err(ClientError::AlreadyEnrolled);
    }
    if let Some(pending) = wallet.pending()
        && !matches!(pending, Pending::Enroll { .. })
    {
        return Err(ClientError::pending_blocks(pending));
    }
    let key = wallet.current_key()?;
    let pk0 = key.public_key();
    let r0 = wallet.r_at(wallet.index())?;
    let com0 = commitment(0, &pk0, &r0);
    let digest = enroll_digest(&pk0, &com0);
    wallet.set_pending(Some(Pending::Enroll { com0, digest }))?;
    let attested = bank.attest(&pk0).await?;
    check_manifest(wallet, &attested)?;
    let sealed = seal_to(&attested.channel_pk, &EnrollSecret { r0 })?;
    let request = BankRequest::Enroll(Box::new(EnrollRequest {
        channel_pk: attested.channel_pk,
        pk0,
        com0,
        sig: sign_digest(&key, &digest),
        sealed,
    }));
    match bank.call(&request).await? {
        BankResponse::Enrolled { sig } => {
            wallet.verify_new_state(&com0, &sig)?;
            wallet.set_enrolled(
                State {
                    balance: 0,
                    pk: pk0,
                    r: r0,
                },
                sig,
            )
        }
        BankResponse::Unavailable => Err(ClientError::Unavailable {
            retry: RETRY_ENROLL,
        }),
        BankResponse::Refused => Err(ClientError::Refused),
        _ => Err(ClientError::UnexpectedResponse { step: "enroll" }),
    }
}

pub async fn enroll_and_refresh(wallet: &mut Wallet, bank: &BankClient) -> Result<(), ClientError> {
    if !wallet.on_enrolled_serial() {
        enroll(wallet, bank).await?;
    }
    refresh(wallet, bank, false).await.map(|_| ())
}

fn refresh_allowed(wallet: &Wallet, force: bool) -> Result<(), ClientError> {
    match wallet.pending() {
        Some(pending @ Pending::Enroll { .. }) => Err(ClientError::pending_blocks(pending)),
        Some(pending @ (Pending::Pay { .. } | Pending::Request { .. })) if !force => {
            Err(ClientError::refresh_blocked(pending))
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refreshed {
    Moved,
    FinishedSettledPayment,
}

async fn settled_before_refresh(
    wallet: &Wallet,
    bank: &BankClient,
    serial: &Bytes32,
) -> Result<bool, ClientError> {
    let spent_by = bank.lookup(serial).await?;
    let Some(pending @ (Pending::Pay { .. } | Pending::Request { .. })) = wallet.pending() else {
        return Ok(false);
    };
    match spent_by {
        Some(entry) if entry.kind == OpKind::Enroll => Ok(false),
        None => Ok(false),
        Some(entry) => match pending {
            Pending::Pay { digest, .. } if *digest == entry.digest => Ok(true),
            _ => Err(ClientError::Behind {
                serial: hex::encode(serial),
            }),
        },
    }
}

pub async fn refresh(
    wallet: &mut Wallet,
    bank: &BankClient,
    force: bool,
) -> Result<Refreshed, ClientError> {
    let signed = wallet.signed_state()?;
    refresh_allowed(wallet, force)?;
    let pk = wallet.current_pk()?;
    if settled_before_refresh(wallet, bank, &pk).await? {
        finish(wallet, bank, None).await?;
        return Ok(Refreshed::FinishedSettledPayment);
    }
    let abandoned = wallet.pending().copied();
    match move_to_next_serial(wallet, bank, signed.state.balance).await {
        Err(err @ ClientError::Behind { .. }) => {
            wallet.set_pending(abandoned)?;
            Err(err)
        }
        moved => moved.map(|()| Refreshed::Moved),
    }
}

async fn move_to_next_serial(
    wallet: &mut Wallet,
    bank: &BankClient,
    balance: u64,
) -> Result<(), ClientError> {
    let key = wallet.current_key()?;
    let pk = key.public_key();
    let com_next = commitment(balance, &wallet.next_pk()?, &wallet.next_r()?);
    let digest = refresh_digest(&pk, &com_next);
    wallet.set_pending(Some(Pending::Refresh { com_next, digest }))?;
    let attested = bank.attest(&pk).await?;
    check_manifest(wallet, &attested)?;
    let sealed = seal_to(
        &attested.channel_pk,
        &RefreshSecret {
            opening: wallet.opening()?,
        },
    )?;
    let request = BankRequest::Refresh(Box::new(RefreshRequest {
        channel_pk: attested.channel_pk,
        pk,
        com_next,
        sig: sign_digest(&key, &digest),
        sealed,
    }));
    match bank.call(&request).await? {
        BankResponse::Refreshed { sig } => {
            wallet.verify_new_state(&com_next, &sig)?;
            wallet.advance(balance, sig)
        }
        BankResponse::Unavailable => Err(ClientError::Unavailable {
            retry: RETRY_REFRESH,
        }),
        BankResponse::Refused => Err(refusal_of(bank, &pk).await),
        _ => Err(ClientError::UnexpectedResponse { step: "refresh" }),
    }
}

async fn refusal_of(bank: &BankClient, serial: &Bytes32) -> ClientError {
    match bank.lookup(serial).await {
        Ok(Some(entry)) if entry.kind != OpKind::Enroll => ClientError::Behind {
            serial: hex::encode(serial),
        },
        Ok(_) => ClientError::RefreshRefused,
        Err(err) => {
            warn!(error = %err, "could not look up the refused serial");
            ClientError::RefreshRefused
        }
    }
}

async fn lookup_sig(
    bank: &BankClient,
    kind: OpKind,
    serial: &Bytes32,
    digest: &Bytes32,
    com: &Bytes32,
) -> Result<Signature, ClientError> {
    let next = match kind {
        OpKind::Pay => PAY_NOT_SETTLED,
        OpKind::Enroll => RETRY_ENROLL,
        OpKind::Refresh => RETRY_REFRESH,
    };
    let entry = bank
        .lookup(serial)
        .await?
        .filter(|entry| entry.kind != OpKind::Enroll || kind == OpKind::Enroll)
        .ok_or(ClientError::NotSettled { next })?;
    if entry.digest != *digest {
        return Err(ClientError::Behind {
            serial: hex::encode(serial),
        });
    }
    entry
        .sig_for(com)
        .ok_or(ClientError::Mismatch { what: "log entry" })
}

pub async fn finish(
    wallet: &mut Wallet,
    bank: &BankClient,
    receipt: Option<&ReceiptFile>,
) -> Result<(), ClientError> {
    let pending = wallet
        .pending()
        .copied()
        .ok_or(ClientError::NoPending { what: "operation" })?;
    let pk = wallet.current_pk()?;
    match pending {
        Pending::Pay {
            v,
            com_a_next,
            digest,
            ..
        } => {
            let sig = match receipt {
                Some(r) if r.digest == digest && r.com_a_next == com_a_next => r.sig_a_next,
                Some(_) => return Err(ClientError::Mismatch { what: "receipt" }),
                None => lookup_sig(bank, OpKind::Pay, &pk, &digest, &com_a_next).await?,
            };
            wallet.verify_new_state(&com_a_next, &sig)?;
            let balance = wallet
                .balance()
                .checked_sub(v)
                .ok_or(ClientError::Insufficient {
                    balance: wallet.balance(),
                    amount: v,
                })?;
            wallet.advance(balance, sig)
        }
        Pending::Refresh { com_next, digest } => {
            let sig = lookup_sig(bank, OpKind::Refresh, &pk, &digest, &com_next).await?;
            wallet.verify_new_state(&com_next, &sig)?;
            wallet.advance(wallet.balance(), sig)
        }
        Pending::Enroll { com0, digest } => {
            let sig = lookup_sig(bank, OpKind::Enroll, &pk, &digest, &com0).await?;
            wallet.verify_new_state(&com0, &sig)?;
            let r = wallet.r_at(wallet.index())?;
            wallet.set_enrolled(State { balance: 0, pk, r }, sig)
        }
        Pending::Request { .. } => Err(ClientError::NoPending {
            what: "payer-side operation",
        }),
    }
}
