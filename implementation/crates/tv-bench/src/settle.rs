use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pt_tee::attestation::AttestationVerifier;
use tokio::task::JoinSet;
use tv_bank::{Bank, EnclaveLink, bank_wallet_path};
use tv_client::WalletData;
use tv_core::BankRequest;

use crate::party::{Party, payment, settle};
use crate::setup::{attest_bank, in_process_bank, verifier};

pub struct SettleRun {
    pub pairs: usize,
    pub payments: usize,
    pub elapsed: Duration,
}

async fn enroll<L: EnclaveLink>(bank: &Bank<L>, verifier: &AttestationVerifier) -> Result<Party> {
    let mut party = Party::new();
    let channel_pk = attest_bank(bank, verifier, &party.pk()?).await?;
    let request = party.enroll_request(&channel_pk)?;
    let outcome = bank.handle(&BankRequest::Enroll(Box::new(request))).await;
    party.enrolled(outcome.response)?;
    Ok(party)
}

async fn pay<L: EnclaveLink>(
    bank: &Bank<L>,
    verifier: &AttestationVerifier,
    payer: &mut Party,
    payee: &mut Party,
    v: u64,
) -> Result<()> {
    let channel_pk = attest_bank(bank, verifier, &payee.pk()?).await?;
    let payment = payment(payer, payee, v, &channel_pk)?;
    let request = BankRequest::Receive(Box::new(payment.receive.clone()));
    let outcome = bank.handle(&request).await;
    settle(payer, payee, &payment, outcome.response)
}

pub async fn settle_throughput(root: &Path, pairs: usize, per_pair: usize) -> Result<SettleRun> {
    let (bank, dir) = in_process_bank(root, &format!("settle-{pairs}")).await?;
    let verifier = Arc::new(verifier()?);
    let mut bank_party = Party::from_wallet(&WalletData::read(&bank_wallet_path(&dir))?);
    let mut lanes = Vec::with_capacity(pairs);
    for _ in 0..pairs {
        let mut payer = enroll(&bank, &verifier).await?;
        let payee = enroll(&bank, &verifier).await?;
        pay(
            &bank,
            &verifier,
            &mut bank_party,
            &mut payer,
            per_pair as u64,
        )
        .await?;
        lanes.push((payer, payee));
    }
    let start = Instant::now();
    let mut tasks = JoinSet::new();
    for (mut payer, mut payee) in lanes {
        let bank = Arc::clone(&bank);
        let verifier = Arc::clone(&verifier);
        tasks.spawn(async move {
            for _ in 0..per_pair {
                pay(&bank, &verifier, &mut payer, &mut payee, 1).await?;
            }
            Ok::<(), anyhow::Error>(())
        });
    }
    while let Some(joined) = tasks.join_next().await {
        joined.context("settle task")??;
    }
    Ok(SettleRun {
        pairs,
        payments: pairs * per_pair,
        elapsed: start.elapsed(),
    })
}
