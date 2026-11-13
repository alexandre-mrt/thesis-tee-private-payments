use std::time::Duration;

use tokio::task::JoinSet;
use tv_bank::Outcome;
use tv_client::{ClientError, OfferFile, Wallet, flows, payment};
use tv_core::{BankRequest, BankResponse, Bytes32, SigningKey, commitment};
use tv_tests::{Harness, Mode, RESERVE, enroll_request};

const ENCLAVE_DELAY: Duration = Duration::from_millis(200);

async fn race(h: &Harness, mode: Mode, requests: Vec<BankRequest>) -> Vec<Outcome> {
    h.link.set_mode(mode);
    let mut tasks = JoinSet::new();
    for (i, request) in requests.into_iter().enumerate() {
        let bank = h.bank_arc();
        tasks.spawn(async move { (i, bank.handle(&request).await) });
    }
    let mut outcomes = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        outcomes.push(joined.unwrap());
    }
    h.link.set_mode(Mode::Normal);
    outcomes.sort_by_key(|(i, _)| *i);
    assert_eq!(h.bank().in_flight(), 0);
    outcomes.into_iter().map(|(_, outcome)| outcome).collect()
}

fn assert_exactly_one_settled(outcomes: &[Outcome], settled: impl Fn(&BankResponse) -> bool) {
    let settled_count = outcomes.iter().filter(|o| settled(&o.response)).count();
    let refused = outcomes
        .iter()
        .filter(|o| o.response == BankResponse::Refused)
        .count();
    let appended = outcomes.iter().filter(|o| o.appended).count();
    assert_eq!(
        (settled_count, refused, appended),
        (1, outcomes.len() - 1, 1),
        "{outcomes:?}"
    );
}

fn copy_of(h: &Harness, wallet: &Wallet, name: &str) -> Wallet {
    Wallet::create_with(&h.dir().join(format!("{name}.json")), wallet.data().clone()).unwrap()
}

async fn settle_after_race(h: &Harness, payer: &mut Wallet, payee: &mut Wallet, offer: &OfferFile) {
    payment::receive(payee, &h.client, offer).await.unwrap();
    flows::finish(payer, &h.client, None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn two_in_flight_spends_of_one_serial_settle_exactly_once() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    let mut carol = h.wallet("carol");
    for w in [&mut alice, &mut bob, &mut carol] {
        h.enroll(w).await;
    }
    h.issue(&mut alice, 500).await.unwrap();
    let entries = h.bank().entries().len();
    let mut to_bob = copy_of(&h, &alice, "alice-to-bob");
    let mut to_carol = copy_of(&h, &alice, "alice-to-carol");
    let bob_request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let carol_request = payment::request(&mut carol, &h.client, Some(200))
        .await
        .unwrap();
    let bob_offer = payment::pay(&mut to_bob, h.client.verifier(), &bob_request).unwrap();
    let carol_offer = payment::pay(&mut to_carol, h.client.verifier(), &carol_request).unwrap();
    let requests = vec![
        BankRequest::Receive(Box::new(h.build_receive(&bob, &bob_offer))),
        BankRequest::Receive(Box::new(h.build_receive(&carol, &carol_offer))),
    ];

    let outcomes = race(&h, Mode::Delay(ENCLAVE_DELAY), requests).await;

    assert_exactly_one_settled(&outcomes, |r| matches!(r, BankResponse::Settled { .. }));
    assert_eq!(h.bank().entries().len(), entries + 1);
    let bob_won = matches!(outcomes[0].response, BankResponse::Settled { .. });
    let (winner, payee, offer, loser, loser_offer) = if bob_won {
        (&mut to_bob, &mut bob, &bob_offer, &mut carol, &carol_offer)
    } else {
        (
            &mut to_carol,
            &mut carol,
            &carol_offer,
            &mut bob,
            &bob_offer,
        )
    };
    settle_after_race(&h, winner, payee, offer).await;
    assert!(matches!(
        payment::receive(loser, &h.client, loser_offer).await,
        Err(ClientError::ReceiveRefused)
    ));
    assert_eq!(h.bank().entries().len(), entries + 1);
    assert_eq!(h.total_supply(&[winner, &bob, &carol]), RESERVE);
}

async fn attested_enroll(
    h: &Harness,
    key: &SigningKey,
    r0: Bytes32,
    com0: Option<Bytes32>,
) -> BankRequest {
    let pk0 = key.public_key();
    let channel_pk = h.client.attest(&pk0).await.unwrap().channel_pk;
    let com0 = com0.unwrap_or_else(|| commitment(0, &pk0, &r0));
    BankRequest::Enroll(Box::new(enroll_request(key, channel_pk, r0, com0)))
}

#[tokio::test(flavor = "multi_thread")]
async fn two_in_flight_enrolls_of_one_serial_settle_exactly_once() {
    let h = Harness::new().await;
    let entries = h.bank().entries().len();
    let key = SigningKey::generate();
    let requests = vec![
        attested_enroll(&h, &key, [1u8; 32], None).await,
        attested_enroll(&h, &key, [2u8; 32], None).await,
    ];

    let outcomes = race(&h, Mode::Delay(ENCLAVE_DELAY), requests).await;

    assert_exactly_one_settled(&outcomes, |r| matches!(r, BankResponse::Enrolled { .. }));
    assert_eq!(h.bank().entries().len(), entries + 1);
    assert_eq!(h.bank().entries()[entries].serials, vec![key.public_key()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_in_flight_enrolls_of_one_commitment_settle_exactly_once() {
    let h = Harness::new().await;
    let entries = h.bank().entries().len();
    let alice = SigningKey::generate();
    let bob = SigningKey::generate();
    let shared = commitment(0, &alice.public_key(), &[1u8; 32]);
    let requests = vec![
        attested_enroll(&h, &alice, [1u8; 32], Some(shared)).await,
        attested_enroll(&h, &bob, [1u8; 32], Some(shared)).await,
    ];

    let outcomes = race(
        &h,
        Mode::LenientAfter(h.result_key.clone(), ENCLAVE_DELAY),
        requests,
    )
    .await;

    assert_exactly_one_settled(&outcomes, |r| matches!(r, BankResponse::Enrolled { .. }));
    assert_eq!(h.bank().entries().len(), entries + 1);
    assert_eq!(h.bank().entries()[entries].commitments, vec![shared]);
}
