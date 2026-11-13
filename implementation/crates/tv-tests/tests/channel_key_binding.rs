use tv_client::{Pending, Wallet, flows, payment, seal_to};
use tv_core::{
    BankRequest, BankResponse, EnrollRequest, EnrollSecret, commitment, enroll_digest, sign_digest,
};
use tv_tests::{Harness, RESERVE};

fn enroll_request(w: &Wallet, channel_pk: [u8; 32]) -> EnrollRequest {
    let key = w.current_key().unwrap();
    let pk0 = key.public_key();
    let r0 = w.r_at(0).unwrap();
    let com0 = commitment(0, &pk0, &r0);
    EnrollRequest {
        channel_pk,
        pk0,
        com0,
        sig: sign_digest(&key, &enroll_digest(&pk0, &com0)),
        sealed: seal_to(&channel_pk, &EnrollSecret { r0 }).unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_channel_key_from_a_request_file_serves_only_the_serial_it_was_attested_for() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    let mallory = h.wallet("mallory");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 100).await.unwrap();
    let request = payment::request(&mut bob, &h.client, Some(10))
        .await
        .unwrap();
    let Some(Pending::Request { channel_pk, .. }) = bob.pending().copied() else {
        panic!("bob has no pending request");
    };
    let entries = h.bank().entries().len();
    let pending_keys = h.link.enclave().pending_keys();

    let hijack = BankRequest::Enroll(Box::new(enroll_request(&mallory, channel_pk)));
    assert_eq!(h.client.call(&hijack).await.unwrap(), BankResponse::Refused);
    assert_eq!(h.bank().entries().len(), entries);
    assert_eq!(h.link.enclave().pending_keys(), pending_keys);

    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(alice.balance(), 90);
    assert_eq!(bob.balance(), 10);
    assert_eq!(h.link.enclave().pending_keys(), pending_keys - 1);
    assert_eq!(h.total_supply(&[&alice, &bob, &mallory]), RESERVE);
}
