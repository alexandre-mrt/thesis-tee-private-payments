use tv_client::ops::Session;
use tv_client::{
    ClientError, Pending, ReceiptFile, RequestFile, Wallet, flows, payment, read_json, write_json,
};
use tv_tests::{Harness, RESERVE, client_trust};

async fn offer_from(h: &Harness, alice: &mut Wallet, session: &Session) -> std::path::PathBuf {
    let request_path = h.dir().join("request.json");
    let offer_path = h.dir().join("offer.json");
    session.request(Some(10), &request_path).await.unwrap();
    let request: RequestFile = read_json(&request_path, "request").unwrap();
    let offer = payment::pay(alice, h.client.verifier(), &request).unwrap();
    write_json(&offer_path, "offer", &offer).unwrap();
    offer_path
}

#[tokio::test(flavor = "multi_thread")]
async fn a_receipt_that_cannot_be_written_leaves_the_wallet_pending_and_the_retry_settles() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let bob = h.wallet("bob");
    let bob_path = bob.path().to_path_buf();
    drop(bob);
    h.enroll(&mut alice).await;
    h.issue(&mut alice, 100).await.unwrap();
    let session = Session::open(&bob_path, h.addr(), &client_trust()).unwrap();
    session.enroll().await.unwrap();
    let offer_path = offer_from(&h, &mut alice, &session).await;
    let entries = h.bank().entries().len();

    let occupied = h.dir().join("receipt-dir");
    std::fs::create_dir(&occupied).unwrap();
    let err = session.receive(&offer_path, &occupied).await.unwrap_err();
    assert!(
        matches!(
            err,
            ClientError::File {
                what: "receipt",
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(h.bank().entries().len(), entries + 1);
    let bob = Wallet::load(&bob_path).unwrap();
    assert!(matches!(bob.pending(), Some(Pending::Request { .. })));
    assert_eq!(bob.balance(), 0);
    assert_eq!(bob.index(), 1);
    drop(bob);

    let receipt_path = h.dir().join("receipt.json");
    session.receive(&offer_path, &receipt_path).await.unwrap();
    assert_eq!(h.bank().entries().len(), entries + 1);
    let bob = Wallet::load(&bob_path).unwrap();
    assert_eq!(bob.pending(), None);
    assert_eq!(bob.balance(), 10);
    assert_eq!(bob.index(), 2);
    let receipt: ReceiptFile = read_json(&receipt_path, "receipt").unwrap();
    assert_eq!(receipt.pk_a, alice.current_pk().unwrap());
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(alice.balance(), 90);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}
