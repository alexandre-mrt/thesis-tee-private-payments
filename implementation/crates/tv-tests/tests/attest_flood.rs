use tv_bank::MAX_PENDING_KEYS_PER_SOURCE;
use tv_client::payment;
use tv_core::BankRequest;
use tv_enclave::MAX_PENDING_KEYS;
use tv_tests::Harness;

const FLOOD_SOURCES: usize = 128;

const LOOPBACK: &str = "127.0.0.1";

fn source(n: usize) -> String {
    format!("198.51.100.{n}")
}

async fn flood(bank: &tv_bank::Bank<tv_tests::TestLink>) {
    for i in 0..MAX_PENDING_KEYS {
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let outcome = bank
            .handle_from(
                &source(i % FLOOD_SOURCES),
                &BankRequest::Attest {
                    nonce,
                    owner: nonce,
                },
            )
            .await;
        assert!(matches!(
            outcome.response,
            tv_core::BankResponse::Attestation { .. }
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attest_flood_from_other_sources_leaves_an_in_flight_payment_alive() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 100).await.unwrap();
    let request = payment::request(&mut bob, &h.client, Some(10))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let pending_before = h.link.enclave().pending_keys();
    const { assert!(MAX_PENDING_KEYS / FLOOD_SOURCES > MAX_PENDING_KEYS_PER_SOURCE) };
    flood(&h.bank_arc()).await;
    let enclave = h.link.enclave();
    for i in 0..FLOOD_SOURCES {
        assert_eq!(
            h.bank().pending_attestations_for(&source(i)),
            MAX_PENDING_KEYS_PER_SOURCE
        );
    }
    assert_eq!(h.bank().pending_attestations_for(LOOPBACK), 1);
    assert_eq!(
        enclave.pending_keys(),
        pending_before + FLOOD_SOURCES * MAX_PENDING_KEYS_PER_SOURCE
    );
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    tv_client::flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(alice.balance(), 90);
    assert_eq!(bob.balance(), 10);
    assert_eq!(
        enclave.pending_keys(),
        pending_before - 1 + FLOOD_SOURCES * MAX_PENDING_KEYS_PER_SOURCE
    );
    assert_eq!(h.bank().pending_attestations_for(LOOPBACK), 0);
}
