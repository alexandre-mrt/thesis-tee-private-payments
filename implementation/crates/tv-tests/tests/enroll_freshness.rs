use tv_client::{ClientError, flows, payment, recover};
use tv_core::{BankRequest, BankResponse, Bytes32, SigningKey, commitment};
use tv_tests::{Harness, enroll_request};

async fn submit_enroll(h: &Harness, key: &SigningKey, r0: Bytes32) -> BankResponse {
    let pk0 = key.public_key();
    let channel_pk = h.client.attest(&pk0).await.unwrap().channel_pk;
    let com0 = commitment(0, &pk0, &r0);
    let request = BankRequest::Enroll(Box::new(enroll_request(key, channel_pk, r0, com0)));
    h.client.call(&request).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bank_refuses_a_non_fresh_enroll_before_asking_the_enclave() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 100).await.unwrap();
    let entries = h.bank().entries().len();
    let pending = h.link.enclave().pending_keys();

    let bob_key = bob.key_at(0).unwrap();
    let response = submit_enroll(&h, &bob_key, [9u8; 32]).await;
    assert_eq!(response, BankResponse::Refused);
    assert_eq!(h.link.enclave().pending_keys(), pending + 1);

    let carol = h.wallet("carol");
    let carol_key = carol.key_at(0).unwrap();
    let bob_com0 = bob.state().unwrap().state.commitment();
    let channel_pk = h
        .client
        .attest(&carol_key.public_key())
        .await
        .unwrap()
        .channel_pk;
    let reused = enroll_request(&carol_key, channel_pk, carol.r_at(0).unwrap(), bob_com0);
    let response = h
        .client
        .call(&BankRequest::Enroll(Box::new(reused)))
        .await
        .unwrap();
    assert_eq!(response, BankResponse::Refused);
    assert_eq!(h.link.enclave().pending_keys(), pending + 2);

    let spent_key = alice.key_at(alice.index() - 1).unwrap();
    assert!(h.spent_serials().contains(&spent_key.public_key()));
    let response = submit_enroll(&h, &spent_key, [8u8; 32]).await;
    assert_eq!(response, BankResponse::Refused);
    assert_eq!(h.link.enclave().pending_keys(), pending + 3);

    assert_eq!(h.bank().entries().len(), entries);
    let response = submit_enroll(&h, &carol_key, carol.r_at(0).unwrap()).await;
    assert!(matches!(response, BankResponse::Enrolled { .. }));
    assert_eq!(h.bank().entries().len(), entries + 1);
    assert_eq!(h.link.enclave().pending_keys(), pending + 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn recover_walks_past_an_enroll_of_a_serial_that_already_holds_a_state() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 100).await.unwrap();
    assert_eq!(alice.index(), 2);
    let live_key = alice.current_key().unwrap();
    let response = submit_enroll(&h, &live_key, [7u8; 32]).await;
    assert!(matches!(response, BankResponse::Enrolled { .. }));

    let mut again = h.wallet_from_seed("alice-again", alice.seed());
    assert_eq!(recover::recover(&mut again, &h.client).await.unwrap(), 2);
    assert_eq!(again.balance(), 100);
    assert_eq!(again.state(), alice.state());
    drop(alice);

    h.transfer(&mut again, &mut bob, 30).await.unwrap();
    assert_eq!(again.balance(), 70);
    let mut third = h.wallet_from_seed("alice-third", again.seed());
    assert_eq!(recover::recover(&mut third, &h.client).await.unwrap(), 3);
    assert_eq!(third.state(), again.state());
    let request = payment::request(&mut bob, &h.client, Some(5))
        .await
        .unwrap();
    let offer = payment::pay(&mut third, h.client.verifier(), &request).unwrap();
    payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    assert_eq!(bob.balance(), 35);
}

#[tokio::test(flavor = "multi_thread")]
async fn enroll_resumes_an_interrupted_enroll_by_moving_off_pk_0() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    flows::enroll(&mut alice, &h.client).await.unwrap();
    assert!(alice.on_enrolled_serial());
    let entries = h.bank().entries().len();

    flows::enroll_and_refresh(&mut alice, &h.client)
        .await
        .unwrap();
    assert!(!alice.on_enrolled_serial());
    assert_eq!(alice.index(), 1);
    assert!(alice.pending().is_none());
    assert_eq!(h.bank().entries().len(), entries + 1);
    assert!(matches!(
        flows::enroll_and_refresh(&mut alice, &h.client).await,
        Err(ClientError::AlreadyEnrolled)
    ));
}
