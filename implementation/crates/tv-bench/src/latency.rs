use std::time::{Duration, Instant};

use anyhow::Result;
use tv_bank::bank_wallet_path;
use tv_client::{BankClient, Wallet, WalletData, flows, payment as wallet_payment};
use tv_core::{BankRequest, Seed};

use crate::party::{Party, payment, settle};
use crate::setup::Loopback;

pub struct PaymentLatency {
    pub attest: Vec<Duration>,
    pub build: Vec<Duration>,
    pub receive: Vec<Duration>,
    pub total: Vec<Duration>,
}

pub async fn enroll_over_tcp(client: &BankClient) -> Result<Party> {
    let mut party = Party::new();
    let attested = client.attest(&party.pk()?).await?;
    let request = party.enroll_request(&attested.channel_pk)?;
    let response = client.call(&BankRequest::Enroll(Box::new(request))).await?;
    party.enrolled(response)?;
    Ok(party)
}

pub async fn pay_over_tcp(
    client: &BankClient,
    payer: &mut Party,
    payee: &mut Party,
    v: u64,
) -> Result<()> {
    let attested = client.attest(&payee.pk()?).await?;
    let payment = payment(payer, payee, v, &attested.channel_pk)?;
    let request = BankRequest::Receive(Box::new(payment.receive.clone()));
    let response = client.call(&request).await?;
    settle(payer, payee, &payment, response)
}

pub fn bank_party(lb: &Loopback) -> Result<Party> {
    Ok(Party::from_wallet(&WalletData::read(&bank_wallet_path(
        &lb.dir,
    ))?))
}

pub async fn payment_latency(lb: &Loopback, count: usize) -> Result<PaymentLatency> {
    let client = &lb.client;
    let mut bank = bank_party(lb)?;
    let mut payer = enroll_over_tcp(client).await?;
    let mut payee = enroll_over_tcp(client).await?;
    pay_over_tcp(client, &mut bank, &mut payer, count as u64).await?;
    let mut out = PaymentLatency {
        attest: Vec::with_capacity(count),
        build: Vec::with_capacity(count),
        receive: Vec::with_capacity(count),
        total: Vec::with_capacity(count),
    };
    for _ in 0..count {
        let t0 = Instant::now();
        let attested = client.attest(&payee.pk()?).await?;
        let t1 = Instant::now();
        let payment = payment(&payer, &payee, 1, &attested.channel_pk)?;
        let request = BankRequest::Receive(Box::new(payment.receive.clone()));
        let t2 = Instant::now();
        let response = client.call(&request).await?;
        let t3 = Instant::now();
        settle(&mut payer, &mut payee, &payment, response)?;
        out.attest.push(t1 - t0);
        out.build.push(t2 - t1);
        out.receive.push(t3 - t2);
        out.total.push(t3 - t0);
    }
    Ok(out)
}

pub async fn transfer(
    client: &BankClient,
    payer: &mut Wallet,
    payee: &mut Wallet,
    v: u64,
) -> Result<()> {
    let request = wallet_payment::request(payee, client, Some(v)).await?;
    let offer = wallet_payment::pay(payer, client.verifier(), &request)?;
    let receipt = wallet_payment::receive(payee, client, &offer).await?;
    flows::finish(payer, client, Some(&receipt)).await?;
    Ok(())
}

pub async fn funded_wallets(lb: &Loopback, tag: &str, balance: u64) -> Result<(Wallet, Wallet)> {
    let client = &lb.client;
    let mut alice = Wallet::create(
        &lb.dir.join(format!("{tag}-alice.json")),
        Seed::generate(),
        lb.keys,
    )?;
    let mut bob = Wallet::create(
        &lb.dir.join(format!("{tag}-bob.json")),
        Seed::generate(),
        lb.keys,
    )?;
    flows::enroll_and_refresh(&mut alice, client).await?;
    flows::enroll_and_refresh(&mut bob, client).await?;
    let mut bank_wallet = Wallet::load(&bank_wallet_path(&lb.dir))?;
    transfer(client, &mut bank_wallet, &mut alice, balance).await?;
    Ok((alice, bob))
}

pub async fn wallet_flow_latency(lb: &Loopback, count: usize) -> Result<Vec<Duration>> {
    let (mut alice, mut bob) = funded_wallets(lb, "flow", count as u64).await?;
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let start = Instant::now();
        transfer(&lb.client, &mut alice, &mut bob, 1).await?;
        samples.push(start.elapsed());
    }
    Ok(samples)
}
