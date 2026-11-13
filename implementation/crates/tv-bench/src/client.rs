use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use pt_tee::framing::LEN_PREFIX;
use serde::Serialize;
use tv_client::{
    Attested, OfferFile, ReceiptFile, RequestFile, payment as wallet_payment, seal_to,
    verify_bundle,
};
use tv_core::{
    BankRequest, BankResponse, CheckOp, EnclaveRequest, EnclaveResponse, LogEntry, OpKind,
    PaySecret, RefreshRequest, RefreshSecret, SideKind, SigningKey, encode_cbor, pay_digest,
    random_bytes32, refresh_digest, sign_digest, sign_result,
};

use crate::latency::{bank_party, enroll_over_tcp, funded_wallets, pay_over_tcp};
use crate::party::{Party, Payment, payment};
use crate::setup::Loopback;

const COST_FUNDING: u64 = 10;

pub struct ClientCost {
    pub verify: Vec<Duration>,
    pub seal: Vec<Duration>,
    pub offer: Vec<Duration>,
}

pub async fn client_cost(lb: &Loopback, iterations: usize) -> Result<ClientCost> {
    let client = &lb.client;
    let (alice, mut bob) = funded_wallets(lb, "cost", COST_FUNDING).await?;
    let request = wallet_payment::request(&mut bob, client, Some(1)).await?;
    let verifier = client.verifier();
    let mut cost = ClientCost {
        verify: Vec::with_capacity(iterations),
        seal: Vec::with_capacity(iterations),
        offer: Vec::with_capacity(iterations),
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
    Ok(Sample {
        attested,
        payee,
        payment,
        settled,
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
    let digest = pay_digest(
        &public.pk_a,
        &public.com_a_next,
        &public.pk_b,
        &public.com_b_next,
    );
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
    let BankResponse::Settled {
        sig_a_next,
        sig_b_next,
    } = s.settled
    else {
        bail!("payment not settled: {:?}", s.settled);
    };
    let entry = LogEntry {
        seq: 0,
        kind: OpKind::Pay,
        serials: vec![public.pk_a, public.pk_b],
        commitments: vec![public.com_a_next, public.com_b_next],
        sigs: vec![sig_a_next, sig_b_next],
        digest,
    };
    Ok(vec![
        ("wire bank->enclave Check(Pay)".to_owned(), frame(&check)?),
        ("wire enclave->bank Result".to_owned(), frame(&result)?),
        (
            "log.jsonl line (Pay)".to_owned(),
            serde_json::to_vec(&entry)?.len() + 1,
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
    let BankResponse::Settled { sig_a_next, .. } = s.settled else {
        bail!("payment not settled: {:?}", s.settled);
    };
    let request_file = RequestFile {
        v: 1,
        pk_b: public.pk_b,
        com_b_next: public.com_b_next,
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
    };
    let receipt_file = ReceiptFile {
        digest: pay_digest(
            &public.pk_a,
            &public.com_a_next,
            &public.pk_b,
            &public.com_b_next,
        ),
        pk_a: public.pk_a,
        com_a_next: public.com_a_next,
        sig_a_next,
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
