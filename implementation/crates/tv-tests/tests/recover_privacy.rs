use tv_client::{flows, payment, recover};
use tv_core::BankRequest;
use tv_tests::{Harness, RecordingProxy};

#[tokio::test(flavor = "multi_thread")]
async fn recover_downloads_the_log_and_never_asks_the_bank_about_one_serial() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    h.transfer(&mut alice, &mut bob, 120).await.unwrap();
    flows::refresh(&mut alice, &h.client, false).await.unwrap();

    let proxy = RecordingProxy::start(h.addr()).await;
    let client = proxy.client();
    let mut again = h.wallet_from_seed("alice-again", alice.seed());
    assert_eq!(recover::recover(&mut again, &client).await.unwrap(), 4);
    assert_eq!(again.state(), alice.state());
    assert_eq!(proxy.count("Lookup"), 0);
    assert!(proxy.count("LogRange") >= 1);
    assert_eq!(proxy.requests().len(), proxy.count("LogRange"));
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_without_a_receipt_looks_up_only_the_serial_already_spent() {
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
    payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    let spent = alice.current_pk().unwrap();

    let proxy = RecordingProxy::start(h.addr()).await;
    let client = proxy.client();
    flows::finish(&mut alice, &client, None).await.unwrap();
    assert_eq!(alice.balance(), 400);
    assert_ne!(alice.current_pk().unwrap(), spent);
    assert!(
        matches!(
            proxy.recorded().as_slice(),
            [BankRequest::Lookup { serial }] if *serial == spent
        ),
        "{:?}",
        proxy.requests()
    );
    assert!(h.spent_serials().contains(&spent));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_refresh_has_one_wire_shape_whatever_is_pending() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    let mut carol = h.wallet("carol");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.enroll(&mut carol).await;
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request(&mut bob, &h.client, Some(120))
        .await
        .unwrap();
    payment::pay(&mut alice, h.client.verifier(), &request).unwrap();

    let mut shapes = Vec::new();
    for (wallet, force) in [(&mut carol, false), (&mut alice, true), (&mut bob, true)] {
        let proxy = RecordingProxy::start(h.addr()).await;
        let client = proxy.client();
        assert_eq!(
            flows::refresh(wallet, &client, force).await.unwrap(),
            flows::Refreshed::Moved
        );
        shapes.push(proxy.requests());
    }
    assert_eq!(shapes[0], ["Lookup", "Attest", "Refresh"]);
    assert_eq!(shapes[1], shapes[0]);
    assert_eq!(shapes[2], shapes[0]);
}
