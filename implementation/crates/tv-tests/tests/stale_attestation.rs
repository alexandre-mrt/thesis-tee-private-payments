use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pt_tee::attestation::mock::MockAttestation;
use tv_client::{ClientError, RequestFile, Wallet, payment};
use tv_core::{ATTEST_CLOCK_SKEW, MAX_KEY_AGE, PaySecret, decode_cbor};
use tv_tests::Harness;

fn redated(request: &RequestFile, timestamp: SystemTime) -> RequestFile {
    let mut doc = MockAttestation::decode(&request.attestation.doc).unwrap();
    doc.timestamp_ms =
        u64::try_from(timestamp.duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap();
    let mut replayed = request.clone();
    replayed.attestation.doc = doc.encode().unwrap();
    replayed
}

async fn payer_and_request(h: &Harness) -> (Wallet, RequestFile) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    (alice, request)
}

#[tokio::test(flavor = "multi_thread")]
async fn payer_refuses_an_attestation_older_than_the_channel_key_lifetime() {
    let h = Harness::new().await;
    let (mut alice, request) = payer_and_request(&h).await;
    let leaked = h.link.enclave().leak_memory();

    let stale = redated(
        &request,
        SystemTime::now() - MAX_KEY_AGE - Duration::from_secs(1),
    );
    assert!(matches!(
        payment::pay(&mut alice, h.client.verifier(), &stale),
        Err(ClientError::StaleAttestation { .. })
    ));
    let ahead = redated(
        &request,
        SystemTime::now() + ATTEST_CLOCK_SKEW + Duration::from_secs(60),
    );
    assert!(matches!(
        payment::pay(&mut alice, h.client.verifier(), &ahead),
        Err(ClientError::FutureAttestation { .. })
    ));
    assert!(alice.pending().is_none());

    let fresh = redated(&request, SystemTime::now() - Duration::from_secs(60));
    let offer = payment::pay(&mut alice, h.client.verifier(), &fresh).unwrap();
    let secret: PaySecret = decode_cbor(&leaked.open_blob(&offer.payer).unwrap()).unwrap();
    assert_eq!(secret.v, 100);
}
