use pt_tee::attestation::AttestationVerifier;
use tv_core::{
    B_MAX, BankRequest, BankResponse, Bytes32, PayPublic, PaySecret, Receive, Signature,
    commitment, pay_digest, sign_digest,
};

use crate::attest::verify_bundle;
use crate::bank::{BankClient, seal_to};
use crate::error::{ClientError, RETRY_RECEIVE};
use crate::files::{OfferFile, ReceiptFile, RequestFile};
use crate::flows::check_manifest;
use crate::wallet::{Pending, Wallet};

fn payee_balance(balance: u64, v: u64) -> Result<u64, ClientError> {
    balance
        .checked_add(v)
        .ok_or(ClientError::ExceedsCap { balance, amount: v })
}

fn request_commitment(wallet: &Wallet, v: u64) -> Result<Bytes32, ClientError> {
    if v == 0 {
        return Err(ClientError::ZeroAmount);
    }
    let balance = wallet.balance();
    let next = payee_balance(balance, v)?;
    if !wallet.is_bank_state() && next > B_MAX {
        return Err(ClientError::ExceedsCap { balance, amount: v });
    }
    Ok(commitment(next, &wallet.next_pk()?, &wallet.next_r()?))
}

pub async fn request(
    wallet: &mut Wallet,
    bank: &BankClient,
    amount: Option<u64>,
) -> Result<RequestFile, ClientError> {
    wallet.signed_state()?;
    if wallet.on_enrolled_serial() {
        return Err(ClientError::EnrolledSerial);
    }
    let (v, com_next) = match (wallet.pending().copied(), amount) {
        (Some(Pending::Request { v, com_next, .. }), None) => (v, com_next),
        (Some(Pending::Request { v, com_next, .. }), Some(a)) if a == v => (v, com_next),
        (Some(pending), _) => return Err(ClientError::pending_blocks(&pending)),
        (None, None) => return Err(ClientError::NoPending { what: "request" }),
        (None, Some(v)) => (v, request_commitment(wallet, v)?),
    };
    let pk_b = wallet.current_pk()?;
    let attested = bank.attest(&pk_b).await?;
    check_manifest(wallet, &attested)?;
    wallet.set_pending(Some(Pending::Request {
        v,
        com_next,
        channel_pk: attested.channel_pk,
        result_pk: attested.bundle.manifest.result_pk,
    }))?;
    Ok(RequestFile {
        v,
        pk_b,
        com_b_next: com_next,
        attestation: attested.bundle,
    })
}

fn payer_commitment(wallet: &Wallet, request: &RequestFile) -> Result<Bytes32, ClientError> {
    match wallet.pending().copied() {
        Some(Pending::Pay {
            v,
            pk_b,
            com_b_next,
            com_a_next,
            ..
        }) => {
            if v != request.v || pk_b != request.pk_b || com_b_next != request.com_b_next {
                return Err(ClientError::PayRequestMismatch);
            }
            Ok(com_a_next)
        }
        Some(pending) => Err(ClientError::pending_blocks(&pending)),
        None => {
            let balance = wallet.balance();
            let next = balance
                .checked_sub(request.v)
                .ok_or(ClientError::Insufficient {
                    balance,
                    amount: request.v,
                })?;
            Ok(commitment(next, &wallet.next_pk()?, &wallet.next_r()?))
        }
    }
}

pub struct PreparedPay {
    pub offer: OfferFile,
    pending: Pending,
}

pub fn commit_pay(wallet: &mut Wallet, prepared: PreparedPay) -> Result<OfferFile, ClientError> {
    wallet.set_pending(Some(prepared.pending))?;
    Ok(prepared.offer)
}

pub fn pay(
    wallet: &mut Wallet,
    verifier: &AttestationVerifier,
    request: &RequestFile,
) -> Result<OfferFile, ClientError> {
    let prepared = prepare_pay(wallet, verifier, request)?;
    commit_pay(wallet, prepared)
}

pub fn prepare_pay(
    wallet: &Wallet,
    verifier: &AttestationVerifier,
    request: &RequestFile,
) -> Result<PreparedPay, ClientError> {
    wallet.signed_state()?;
    let channel_pk = verify_bundle(verifier, &request.attestation)?;
    if request.attestation.manifest.bank != wallet.bank() {
        return Err(ClientError::BankKeyMismatch);
    }
    if request.v == 0 {
        return Err(ClientError::ZeroAmount);
    }
    let com_a_next = payer_commitment(wallet, request)?;
    let key = wallet.current_key()?;
    let pk_a = key.public_key();
    if pk_a == request.pk_b {
        return Err(ClientError::SelfPayment);
    }
    let digest = pay_digest(&pk_a, &com_a_next, &request.pk_b, &request.com_b_next);
    let sig_a = sign_digest(&key, &digest);
    let payer = seal_to(
        &channel_pk,
        &PaySecret {
            v: request.v,
            opening: wallet.opening()?,
        },
    )?;
    Ok(PreparedPay {
        offer: OfferFile {
            channel_pk,
            pk_a,
            com_a_next,
            sig_a,
            payer,
            pk_b: request.pk_b,
            com_b_next: request.com_b_next,
        },
        pending: Pending::Pay {
            v: request.v,
            pk_b: request.pk_b,
            com_b_next: request.com_b_next,
            com_a_next,
            digest,
        },
    })
}

pub struct PreparedReceive {
    request: BankRequest,
    digest: Bytes32,
    pk_a: Bytes32,
    com_a_next: Bytes32,
    com_b_next: Bytes32,
    balance_next: u64,
    result_pk: Bytes32,
}

pub struct Settlement {
    pub receipt: ReceiptFile,
    com_b_next: Bytes32,
    balance_next: u64,
    sig_b_next: Signature,
}

fn check_offer(
    offer: &OfferFile,
    pk_b: &Bytes32,
    com_b_next: &Bytes32,
    channel_pk: &Bytes32,
) -> Result<(), ClientError> {
    if offer.pk_b != *pk_b || offer.com_b_next != *com_b_next {
        return Err(ClientError::OfferForOtherRequest);
    }
    if offer.channel_pk != *channel_pk {
        return Err(ClientError::OfferForEarlierRequest);
    }
    Ok(())
}

pub fn prepare_receive(wallet: &Wallet, offer: &OfferFile) -> Result<PreparedReceive, ClientError> {
    let signed = wallet.signed_state()?;
    let Some(Pending::Request {
        v,
        com_next,
        channel_pk,
        result_pk,
    }) = wallet.pending().copied()
    else {
        return Err(ClientError::NoPending { what: "request" });
    };
    let key = wallet.current_key()?;
    let pk_b = key.public_key();
    check_offer(offer, &pk_b, &com_next, &channel_pk)?;
    let digest = pay_digest(&offer.pk_a, &offer.com_a_next, &pk_b, &com_next);
    let payee = seal_to(
        &channel_pk,
        &PaySecret {
            v,
            opening: wallet.opening()?,
        },
    )?;
    let request = BankRequest::Receive(Box::new(Receive {
        channel_pk,
        public: PayPublic {
            pk_a: offer.pk_a,
            com_a_next: offer.com_a_next,
            sig_a: offer.sig_a,
            pk_b,
            com_b_next: com_next,
            sig_b: sign_digest(&key, &digest),
        },
        payer: offer.payer.clone(),
        payee,
    }));
    Ok(PreparedReceive {
        request,
        digest,
        pk_a: offer.pk_a,
        com_a_next: offer.com_a_next,
        com_b_next: com_next,
        balance_next: payee_balance(signed.state.balance, v)?,
        result_pk,
    })
}

pub async fn submit_receive(
    wallet: &Wallet,
    bank: &BankClient,
    prepared: &PreparedReceive,
) -> Result<Settlement, ClientError> {
    match bank.call(&prepared.request).await? {
        BankResponse::Settled {
            sig_a_next,
            sig_b_next,
        } => {
            wallet.verify_new_state(&prepared.com_b_next, &sig_b_next)?;
            Ok(Settlement {
                receipt: ReceiptFile {
                    digest: prepared.digest,
                    pk_a: prepared.pk_a,
                    com_a_next: prepared.com_a_next,
                    sig_a_next,
                },
                com_b_next: prepared.com_b_next,
                balance_next: prepared.balance_next,
                sig_b_next,
            })
        }
        BankResponse::Unavailable => Err(ClientError::Unavailable {
            retry: RETRY_RECEIVE,
        }),
        BankResponse::Refused => {
            let again = bank.attest(&wallet.current_pk()?).await?;
            if again.bundle.manifest.result_pk != prepared.result_pk {
                return Err(ClientError::EnclaveRestarted);
            }
            Err(ClientError::ReceiveRefused)
        }
        _ => Err(ClientError::UnexpectedResponse { step: "receive" }),
    }
}

pub fn commit_receive(wallet: &mut Wallet, settled: &Settlement) -> Result<(), ClientError> {
    wallet.verify_new_state(&settled.com_b_next, &settled.sig_b_next)?;
    wallet.advance(settled.balance_next, settled.sig_b_next)
}

pub async fn receive(
    wallet: &mut Wallet,
    bank: &BankClient,
    offer: &OfferFile,
) -> Result<ReceiptFile, ClientError> {
    let prepared = prepare_receive(wallet, offer)?;
    let settled = submit_receive(wallet, bank, &prepared).await?;
    commit_receive(wallet, &settled)?;
    Ok(settled.receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payee_balance_never_wraps() {
        assert_eq!(payee_balance(10, 5).unwrap(), 15);
        assert_eq!(payee_balance(u64::MAX - 1, 1).unwrap(), u64::MAX);
        assert!(matches!(
            payee_balance(u64::MAX, 1),
            Err(ClientError::ExceedsCap {
                balance: u64::MAX,
                amount: 1
            })
        ));
        assert!(matches!(
            payee_balance(u64::MAX - 1, 2),
            Err(ClientError::ExceedsCap { .. })
        ));
    }
}
