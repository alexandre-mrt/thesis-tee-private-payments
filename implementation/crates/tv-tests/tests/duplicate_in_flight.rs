use std::time::Duration;

use tokio::task::JoinSet;
use tv_client::{flows, payment};
use tv_core::{BankRequest, BankResponse};
use tv_tests::{Harness, Mode, RESERVE};

const COPIES: usize = 8;
const ENCLAVE_DELAY: Duration = Duration::from_millis(200);

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_copies_of_one_receive_all_read_the_single_settlement() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let entries = h.bank().entries().len();

    let request = payment::request(&mut bob, &h.client, Some(120))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receive = BankRequest::Receive(Box::new(h.build_receive(&bob, &offer)));
    h.link.set_mode(Mode::Delay(ENCLAVE_DELAY));
    let mut copies = JoinSet::new();
    for _ in 0..COPIES {
        let bank = h.bank_arc();
        let receive = receive.clone();
        copies.spawn(async move { bank.handle(&receive).await });
    }
    let mut responses = Vec::new();
    let mut appended = 0;
    while let Some(joined) = copies.join_next().await {
        let outcome = joined.unwrap();
        appended += usize::from(outcome.appended);
        responses.push(outcome.response);
    }
    h.link.set_mode(Mode::Normal);

    assert!(
        responses
            .iter()
            .all(|r| matches!(r, BankResponse::Settled { .. })),
        "{responses:?}"
    );
    assert!(responses.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(appended, 1);
    assert_eq!(h.bank().entries().len(), entries + 1);
    assert_eq!(h.bank().in_flight(), 0);

    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(alice.balance(), 380);
    assert_eq!(bob.balance(), 120);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_operation_releases_its_digest_for_the_next_copy() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let forged = h.forge(&alice, &bob, 600);
    let receive = BankRequest::Receive(Box::new(h.forge_receive(&forged).await));
    h.link.set_mode(Mode::Delay(ENCLAVE_DELAY));
    let mut copies = JoinSet::new();
    for _ in 0..3 {
        let bank = h.bank_arc();
        let receive = receive.clone();
        copies.spawn(async move { bank.handle(&receive).await.response });
    }
    while let Some(joined) = copies.join_next().await {
        assert_eq!(joined.unwrap(), BankResponse::Refused);
    }
    assert_eq!(h.bank().in_flight(), 0);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}
