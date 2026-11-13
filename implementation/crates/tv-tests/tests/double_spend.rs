use tv_client::{ClientError, Wallet, flows, payment, recover};
use tv_core::BankResponse;
use tv_tests::{Harness, Mode};

async fn assert_behind_everywhere(rolled_back: &mut Wallet, h: &Harness, entries: usize) {
    let finish = flows::finish(rolled_back, &h.client, None)
        .await
        .unwrap_err();
    assert!(matches!(finish, ClientError::Behind { .. }));
    assert!(finish.to_string().contains("tv-cli recover"));
    let blocked = flows::refresh(rolled_back, &h.client, false)
        .await
        .unwrap_err();
    assert!(matches!(blocked, ClientError::RefreshBlocked { .. }));
    assert!(blocked.to_string().contains("tv-cli recover"));
    let refresh = flows::refresh(rolled_back, &h.client, true)
        .await
        .unwrap_err();
    assert!(matches!(refresh, ClientError::Behind { .. }));
    assert!(matches!(
        rolled_back.pending(),
        Some(tv_client::Pending::Pay { .. })
    ));
    assert!(refresh.to_string().contains("tv-cli recover"));
    assert_eq!(h.bank().entries().len(), entries);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_serial_spends_once_even_from_a_rolled_back_wallet() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    let mut carol = h.wallet("carol");
    for w in [&mut alice, &mut bob, &mut carol] {
        h.enroll(w).await;
    }
    h.issue(&mut alice, 500).await.unwrap();
    let snapshot = alice.data().clone();

    h.transfer(&mut alice, &mut bob, 200).await.unwrap();
    assert_eq!(alice.balance(), 300);
    let entries = h.bank().entries().len();

    let mut rolled_back =
        Wallet::create_with(&h.dir().join("alice-rolled-back.json"), snapshot).unwrap();
    assert_eq!(rolled_back.balance(), 500);
    let request = payment::request(&mut carol, &h.client, Some(150))
        .await
        .unwrap();
    let offer = payment::pay(&mut rolled_back, h.client.verifier(), &request).unwrap();
    assert!(matches!(
        payment::receive(&mut carol, &h.client, &offer).await,
        Err(ClientError::ReceiveRefused)
    ));
    assert_eq!(carol.balance(), 0);
    assert_eq!(h.bank().entries().len(), entries);
    assert_behind_everywhere(&mut rolled_back, &h, entries).await;
    recover::recover(&mut rolled_back, &h.client).await.unwrap();
    assert_eq!(rolled_back.state(), alice.state());
    assert_eq!(rolled_back.balance(), 300);
    assert_eq!(h.total_supply(&[&alice, &bob, &carol]), tv_tests::RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bank_refuses_one_serial_on_both_sides_even_from_a_lenient_enclave() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    h.enroll(&mut alice).await;
    h.issue(&mut alice, 500).await.unwrap();
    let entries = h.bank().entries().len();
    let same_serial = h.forge(&alice, &alice, 10);
    assert_eq!(
        h.submit(h.forge_receive(&same_serial).await).await,
        BankResponse::Refused
    );
    h.link.set_mode(Mode::Lenient(h.result_key.clone()));
    assert_eq!(
        h.submit(h.forge_receive(&same_serial).await).await,
        BankResponse::Refused
    );
    h.link.set_mode(Mode::Normal);
    assert_eq!(h.bank().entries().len(), entries);
    assert!(!h.spent_serials().contains(&alice.current_pk().unwrap()));
    assert_eq!(h.total_supply(&[&alice]), tv_tests::RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn replaying_a_settled_request_returns_the_same_answer_without_a_new_entry() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receive = h.build_receive(&bob, &offer);
    let first = h.submit(receive.clone()).await;
    assert!(matches!(first, BankResponse::Settled { .. }));
    let entries = h.bank().entries().len();
    assert_eq!(h.submit(receive).await, first);
    assert_eq!(h.bank().entries().len(), entries);
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(h.bank().entries().len(), entries);
    assert_eq!(alice.balance(), 400);
    assert_eq!(bob.balance(), 100);
}
