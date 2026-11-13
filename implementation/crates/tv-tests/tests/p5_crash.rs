use tv_client::{ClientError, flows, payment};
use tv_core::BankRequest;
use tv_tests::{Harness, Mode, RESERVE, RecordingProxy};

#[tokio::test(flavor = "multi_thread")]
async fn an_enclave_crash_before_the_answer_loses_nothing() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let entries = h.bank().entries().len();

    let request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let keys_before = h.link.enclave().pending_keys();
    h.link.set_mode(Mode::DropNextAnswer);
    assert!(matches!(
        payment::receive(&mut bob, &h.client, &offer).await,
        Err(ClientError::Unavailable { .. })
    ));
    assert_eq!(h.bank().entries().len(), entries);
    assert_eq!(h.link.enclave().pending_keys(), keys_before - 1);

    assert!(matches!(
        payment::receive(&mut bob, &h.client, &offer).await,
        Err(ClientError::ReceiveRefused)
    ));

    h.restart_enclave().await;
    assert!(matches!(
        payment::receive(&mut bob, &h.client, &offer).await,
        Err(ClientError::EnclaveRestarted)
    ));
    let request = payment::request(&mut bob, &h.client, None).await.unwrap();
    assert_eq!(request.v, 100);
    assert!(matches!(
        payment::receive(&mut bob, &h.client, &offer).await,
        Err(ClientError::OfferForEarlierRequest)
    ));
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(alice.balance(), 400);
    assert_eq!(bob.balance(), 100);
    assert_eq!(h.bank().entries().len(), entries + 1);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bank_crash_after_the_append_replays_the_stored_answer() {
    let mut h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let entries = h.bank().entries().len();

    let request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receive = h.build_receive(&bob, &offer);
    let outcome = h
        .bank()
        .handle(&BankRequest::Receive(Box::new(receive)))
        .await;
    assert!(outcome.appended);
    let lost = outcome.response;
    assert_eq!(bob.balance(), 0);

    h.restart_bank().await;
    assert_eq!(h.bank().entries().len(), entries + 1);
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    assert_eq!(bob.balance(), 100);
    assert_eq!(h.bank().entries().len(), entries + 1);
    let again = h.bank().entries();
    assert_eq!(
        tv_bank::store::answer_for(again.last().unwrap()).unwrap(),
        lost
    );
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(alice.balance(), 400);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);

    h.restart_bank().await;
    assert_eq!(h.bank().entries().len(), entries + 1);
    h.transfer(&mut bob, &mut alice, 30).await.unwrap();
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_interrupted_before_the_answer_finishes_from_the_log() {
    let mut h = Harness::new().await;
    let mut alice = h.wallet("alice");
    h.enroll(&mut alice).await;
    h.issue(&mut alice, 50).await.unwrap();
    let pk = alice.current_pk().unwrap();
    h.link.set_mode(Mode::DropNextAnswer);
    let err = flows::refresh(&mut alice, &h.client, false)
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::Unavailable { .. }), "{err}");
    assert!(err.to_string().contains("rerun `tv-cli refresh`"), "{err}");
    assert!(!err.to_string().contains("reseal"), "{err}");
    flows::refresh(&mut alice, &h.client, false).await.unwrap();
    assert_ne!(alice.current_pk().unwrap(), pk);
    assert_eq!(alice.balance(), 50);
    h.restart_bank().await;
    assert!(h.spent_serials().contains(&pk));
}

#[tokio::test(flavor = "multi_thread")]
async fn finishing_an_interrupted_refresh_of_the_enrolled_serial_is_not_settled_not_behind() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    h.enroll(&mut alice).await;
    let pk0 = alice.current_pk().unwrap();
    let entries = h.bank().entries().len();
    h.link.set_mode(Mode::DropNextAnswer);
    assert!(matches!(
        flows::refresh(&mut alice, &h.client, false).await,
        Err(ClientError::Unavailable { .. })
    ));
    let err = flows::finish(&mut alice, &h.client, None)
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::NotSettled { .. }), "{err}");
    assert!(err.to_string().contains("rerun `tv-cli refresh`"), "{err}");
    assert!(!err.to_string().contains("recover"));
    assert_eq!(h.bank().entries().len(), entries);
    assert_eq!(alice.current_pk().unwrap(), pk0);
    assert!(alice.pending().is_some());

    flows::refresh(&mut alice, &h.client, false).await.unwrap();
    assert_ne!(alice.current_pk().unwrap(), pk0);
    assert!(alice.pending().is_none());
    assert!(h.spent_serials().contains(&pk0));
    assert_eq!(h.bank().entries().len(), entries + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retry_refused_after_its_first_answer_was_lost_reads_as_unavailable() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let entries = h.bank().entries().len();
    let request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();

    let proxy = RecordingProxy::start(h.addr()).await;
    proxy.drop_next_reply();
    h.link.set_mode(Mode::DropNextAnswer);
    let err = payment::receive(&mut bob, &proxy.client(), &offer)
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::Unavailable { .. }), "{err}");
    assert!(err.to_string().contains("re-attest and reseal"));
    assert_eq!(proxy.count("Receive"), 2);
    assert_eq!(h.bank().entries().len(), entries);

    let request = payment::request(&mut bob, &h.client, None).await.unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(bob.balance(), 100);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}
