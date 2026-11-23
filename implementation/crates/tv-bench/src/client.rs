use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use pt_tee::framing::LEN_PREFIX;
use serde::Serialize;
use tv_client::proof::{Mode, check, prove};
use tv_client::{
    Attested, OfferFile, ReceiptFile, RequestFile, Wallet, payment as wallet_payment, seal_to,
    verify_bundle,
};
use tv_core::{
    BankRequest, BankResponse, CheckOp, EnclaveRequest, EnclaveResponse, LogEntry, PaySecret,
    RefreshRequest, RefreshSecret, SideKind, SigningKey, encode_cbor, random_bytes32,
    refresh_digest, sign_digest, sign_result,
};

use crate::latency::{bank_party, enroll_over_tcp, funded_wallets, pay_over_tcp};
use crate::party::{Party, Payment, payment};
use crate::setup::Loopback;

const COST_FUNDING: u64 = 10;

pub struct ClientCost {
    pub verify: Vec<Duration>,
    pub seal: Vec<Duration>,
    pub offer: Vec<Duration>,
    pub prove: Vec<Duration>,
    pub verify_proof: Vec<Duration>,
    pub log_entries: usize,
}

const PROOF_CHALLENGE: [u8; 32] = [9u8; 32];

fn proof_cost(alice: &Wallet, bob: &Wallet, log: &[LogEntry], cost: &mut ClientCost) -> Result<()> {
    let seq = alice
        .head()
        .context("the funded wallet saw no receipt")?
        .seq;
    let start = Instant::now();
    let proof = prove(alice, log, seq, Mode::Payee, PROOF_CHALLENGE)?;
    cost.prove.push(start.elapsed());
    let start = Instant::now();
    check(bob, &proof, &PROOF_CHALLENGE, None)?;
    cost.verify_proof.push(start.elapsed());
    Ok(())
}

pub async fn client_cost(lb: &Loopback, iterations: usize) -> Result<ClientCost> {
    let client = &lb.client;
    let (alice, mut bob) = funded_wallets(lb, "cost", COST_FUNDING).await?;
    let request = wallet_payment::request(&mut bob, client, Some(1)).await?;
    let verifier = client.verifier();
    let log = client.full_log().await?;
    let mut cost = ClientCost {
        verify: Vec::with_capacity(iterations),
        seal: Vec::with_capacity(iterations),
        offer: Vec::with_capacity(iterations),
        prove: Vec::with_capacity(iterations),
        verify_proof: Vec::with_capacity(iterations),
        log_entries: log.len(),
    };
    for _ in 0..iterations {
        let start = Instant::now();
        let channel_pk = verify_bundle(verifier, &request.attestation)?;
        cost.verify.push(start.elapsed());
        let secret = PaySecret {
            v: 1,
            opening: alice.opening()?,
        };
        let start = Instant::now();
        seal_to(&channel_pk, &secret)?;
        cost.seal.push(start.elapsed());
        let start = Instant::now();
        wallet_payment::prepare_pay(&alice, verifier, &request)?;
        cost.offer.push(start.elapsed());
        proof_cost(&alice, &bob, &log, &mut cost)?;
    }
    Ok(cost)
}

fn frame<T: Serialize>(value: &T) -> Result<usize> {
    Ok(LEN_PREFIX + encode_cbor(value)?.len())
}

fn file<T: Serialize>(value: &T) -> Result<usize> {
    Ok(serde_json::to_vec_pretty(value)?.len())
}

struct Sample {
    attested: Attested,
    payee: Party,
    payment: Payment,
    settled: BankResponse,
    entry: LogEntry,
    attest_request: BankRequest,
    attest_response: BankResponse,
}

async fn sample(lb: &Loopback) -> Result<Sample> {
    let client = &lb.client;
    let mut bank = bank_party(lb)?;
    let mut payer = enroll_over_tcp(client).await?;
    let payee = enroll_over_tcp(client).await?;
    pay_over_tcp(client, &mut bank, &mut payer, COST_FUNDING).await?;
    let attest_request = BankRequest::Attest {
        nonce: random_bytes32(),
        owner: payee.pk()?,
    };
    let attest_response = client.call(&attest_request).await?;
    let attested = client.attest(&payee.pk()?).await?;
    let payment = payment(&payer, &payee, 1, &attested.channel_pk)?;
    let receive = BankRequest::Receive(Box::new(payment.receive.clone()));
    let settled = client.call(&receive).await?;
    if !matches!(settled, BankResponse::Settled { .. }) {
        bail!("payment not settled: {settled:?}");
    }
    let Some(entry) = client.lookup(&payment.receive.public.pk_a).await? else {
        bail!("the settled payment is not in the log");
    };
    Ok(Sample {
        attested,
        payee,
        payment,
        settled,
        entry,
        attest_request,
        attest_response,
    })
}

fn user_wire_sizes(s: &Sample) -> Result<Vec<(String, usize)>> {
    let channel_pk = s.attested.channel_pk;
    let enroll = BankRequest::Enroll(Box::new(s.payee.enroll_request(&channel_pk)?));
    let refresh_com = random_bytes32();
    let refresh = BankRequest::Refresh(Box::new(RefreshRequest {
        channel_pk,
        pk: s.payee.pk()?,
        com_next: refresh_com,
        sig: sign_digest(
            &s.payee.key()?,
            &refresh_digest(&s.payee.pk()?, &refresh_com),
        ),
        sealed: seal_to(
            &channel_pk,
            &RefreshSecret {
                opening: s.payee.opening()?,
            },
        )?,
    }));
    let receive = BankRequest::Receive(Box::new(s.payment.receive.clone()));
    Ok(vec![
        (
            "wire user->bank Attest".to_owned(),
            frame(&s.attest_request)?,
        ),
        (
            "wire bank->user Attestation (mock doc + manifest)".to_owned(),
            frame(&s.attest_response)?,
        ),
        ("wire user->bank Enroll".to_owned(), frame(&enroll)?),
        ("wire user->bank Refresh".to_owned(), frame(&refresh)?),
        ("wire user->bank Receive".to_owned(), frame(&receive)?),
        ("wire bank->user Settled".to_owned(), frame(&s.settled)?),
    ])
}

fn enclave_and_log_sizes(s: &Sample) -> Result<Vec<(String, usize)>> {
    let public = s.payment.receive.public;
    let digest = public.digest();
    let check = EnclaveRequest::Check {
        bank_nonce: random_bytes32(),
        op: CheckOp::Pay(Box::new(s.payment.receive.clone())),
    };
    let result = EnclaveResponse::Result(sign_result(
        &SigningKey::generate(),
        random_bytes32(),
        digest,
        vec![SideKind::User, SideKind::User],
    ));
    Ok(vec![
        ("wire bank->enclave Check(Pay)".to_owned(), frame(&check)?),
        ("wire enclave->bank Result".to_owned(), frame(&result)?),
        (
            "log.jsonl line (Pay)".to_owned(),
            serde_json::to_vec(&s.entry)?.len() + 1,
        ),
    ])
}

fn enclave_attest_sizes(s: &Sample) -> Result<Vec<(String, usize)>> {
    let attest = EnclaveRequest::Attest {
        nonce: s.attested.bundle.nonce,
        owner: Some(s.payee.pk()?),
    };
    let attestation = EnclaveResponse::Attestation {
        doc: s.attested.bundle.doc.clone(),
        manifest: s.attested.bundle.manifest,
        channel_pk: s.attested.channel_pk,
    };
    let cancel = EnclaveRequest::Cancel {
        channel_pk: s.attested.channel_pk,
    };
    Ok(vec![
        ("wire bank->enclave Attest".to_owned(), frame(&attest)?),
        (
            "wire enclave->bank Attestation (mock doc + manifest + channel pk)".to_owned(),
            frame(&attestation)?,
        ),
        ("wire bank->enclave Cancel".to_owned(), frame(&cancel)?),
    ])
}

fn file_sizes(s: &Sample) -> Result<Vec<(String, usize)>> {
    let public = s.payment.receive.public;
    let request_file = RequestFile {
        v: 1,
        pk_b: public.pk_b,
        com_b_next: public.com_b_next,
        memo: String::new(),
        attestation: s.attested.bundle.clone(),
    };
    let offer_file = OfferFile {
        channel_pk: s.attested.channel_pk,
        pk_a: public.pk_a,
        com_a_next: public.com_a_next,
        sig_a: public.sig_a,
        payer: s.payment.receive.payer.clone(),
        pk_b: public.pk_b,
        com_b_next: public.com_b_next,
        c_v: public.c_v,
        h_ctx: public.h_ctx,
    };
    let receipt_file = ReceiptFile {
        entry: s.entry.clone(),
        memo: String::new(),
    };
    Ok(vec![
        ("file request.json".to_owned(), file(&request_file)?),
        ("file offer.json".to_owned(), file(&offer_file)?),
        ("file receipt.json".to_owned(), file(&receipt_file)?),
    ])
}

pub async fn message_sizes(lb: &Loopback) -> Result<Vec<(String, usize)>> {
    let s = sample(lb).await?;
    let mut out = user_wire_sizes(&s)?;
    out.extend(enclave_attest_sizes(&s)?);
    out.extend(enclave_and_log_sizes(&s)?);
    out.extend(file_sizes(&s)?);
    Ok(out)
}
