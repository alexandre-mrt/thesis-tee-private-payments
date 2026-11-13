use tv_client::{ClientError, Wallet, flows, payment, recover};
use tv_core::OpKind;
use tv_tests::{Harness, RESERVE};

async fn issued_and_paid(h: &Harness) -> (Wallet, Wallet) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request(&mut bob, &h.client, Some(120))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, None).await.unwrap();
    (alice, bob)
}

#[tokio::test(flavor = "multi_thread")]
async fn issue_pay_and_finish() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);

    h.issue(&mut alice, 500).await.unwrap();
    assert_eq!(alice.balance(), 500);
    assert_eq!(h.bank_wallet().balance(), RESERVE - 500);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);

    let request = payment::request(&mut bob, &h.client, Some(120))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    assert_eq!(bob.balance(), 120);
    assert!(alice.pending().is_some());
    flows::finish(&mut alice, &h.client, None).await.unwrap();
    assert_eq!(alice.balance(), 380);
    assert!(alice.pending().is_none());
    assert!(matches!(
        flows::enroll(&mut alice, &h.client).await,
        Err(ClientError::AlreadyEnrolled)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_redeem_and_the_public_log() {
    let h = Harness::new().await;
    let (alice, mut bob) = issued_and_paid(&h).await;

    let before = bob.current_pk().unwrap();
    flows::refresh(&mut bob, &h.client, false).await.unwrap();
    assert_ne!(before, bob.current_pk().unwrap());
    assert_eq!(bob.balance(), 120);

    let mut bank_wallet = h.bank_wallet();
    h.transfer(&mut bob, &mut bank_wallet, 50).await.unwrap();
    assert_eq!(bob.balance(), 70);
    assert_eq!(bank_wallet.balance(), RESERVE - 450);
    assert!(bank_wallet.is_bank_state());
    drop(bank_wallet);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);

    let entries = h.bank().entries();
    let kinds: Vec<OpKind> = entries.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            OpKind::Enroll,
            OpKind::Refresh,
            OpKind::Enroll,
            OpKind::Refresh,
            OpKind::Pay,
            OpKind::Pay,
            OpKind::Refresh,
            OpKind::Pay
        ]
    );
    let spent = h.spent_serials();
    let mut unique = spent.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(spent.len(), unique.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn recover_from_the_seed_alone() {
    let h = Harness::new().await;
    let (alice, mut bob) = issued_and_paid(&h).await;
    flows::refresh(&mut bob, &h.client, false).await.unwrap();
    let mut bank_wallet = h.bank_wallet();
    h.transfer(&mut bob, &mut bank_wallet, 50).await.unwrap();
    drop(bank_wallet);

    let mut alice2 = h.wallet_from_seed("alice-recovered", alice.seed());
    assert_eq!(recover::recover(&mut alice2, &h.client).await.unwrap(), 3);
    assert_eq!(alice2.balance(), 380);
    assert_eq!(alice2.index(), alice.index());
    assert_eq!(alice2.state(), alice.state());

    let mut bob2 = h.wallet_from_seed("bob-recovered", bob.seed());
    assert_eq!(recover::recover(&mut bob2, &h.client).await.unwrap(), 4);
    assert_eq!(bob2.state(), bob.state());

    let mut nobody = h.wallet("nobody");
    assert_eq!(recover::recover(&mut nobody, &h.client).await.unwrap(), 0);
    assert!(nobody.state().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_recovered_wallet_keeps_working() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 300).await.unwrap();
    let seed = alice.seed();
    drop(alice);
    let mut alice = h.wallet_from_seed("alice-again", seed);
    recover::recover(&mut alice, &h.client).await.unwrap();
    h.transfer(&mut alice, &mut bob, 100).await.unwrap();
    assert_eq!(alice.balance(), 200);
    assert_eq!(bob.balance(), 100);
}
