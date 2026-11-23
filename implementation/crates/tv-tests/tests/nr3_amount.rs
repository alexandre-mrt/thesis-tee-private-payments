use tv_client::{ClientError, OfferFile, Wallet, payment};
use tv_core::{PairSecret, amount_commitment};
use tv_tests::Harness;

async fn funded(h: &Harness) -> (Wallet, Wallet) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    (alice, bob)
}

fn resigned(alice: &Wallet, offer: &OfferFile, c_v: [u8; 32], h_ctx: [u8; 32]) -> OfferFile {
    let changed = OfferFile {
        c_v,
        h_ctx,
        ..offer.clone()
    };
    let sig_a = alice.current_key().unwrap().sign(&changed.digest());
    OfferFile { sig_a, ..changed }
}

#[tokio::test(flavor = "multi_thread")]
async fn nr3_the_payee_refuses_an_offer_whose_evidence_does_not_match_its_request() {
    let h = Harness::new().await;
    let (mut alice, mut bob) = funded(&h).await;
    let request = payment::request_with_memo(&mut bob, &h.client, Some(100), Some("invoice 7"))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let key = alice.current_key().unwrap();
    let pair = PairSecret::derive(&key, &offer.pk_a, &offer.pk_b).unwrap();
    let entries = h.bank().entries().len();

    let other_amount = resigned(
        &alice,
        &offer,
        pair.amount_commitment(99).unwrap(),
        offer.h_ctx,
    );
    let err = payment::receive(&mut bob, &h.client, &other_amount)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ClientError::OfferEvidence {
                what: "amount commitment"
            }
        ),
        "{err}"
    );

    let other_blind = resigned(
        &alice,
        &offer,
        amount_commitment(100, &[7u8; 32]),
        offer.h_ctx,
    );
    assert!(matches!(
        payment::receive(&mut bob, &h.client, &other_blind).await,
        Err(ClientError::OfferEvidence { .. })
    ));

    let other_memo = resigned(
        &alice,
        &offer,
        offer.c_v,
        pair.context_hash(b"invoice 8").unwrap(),
    );
    let err = payment::receive(&mut bob, &h.client, &other_memo)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ClientError::OfferEvidence {
                what: "context hash"
            }
        ),
        "{err}"
    );
    assert_eq!(h.bank().entries().len(), entries);

    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    tv_client::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!((alice.balance(), bob.balance()), (400, 100));
    let settled = h.bank().entries().last().cloned().unwrap();
    assert_eq!(settled.digest, offer.digest());
}

#[tokio::test(flavor = "multi_thread")]
async fn nr3_a_request_with_an_oversized_memo_is_refused_before_attesting() {
    let h = Harness::new().await;
    let (_, mut bob) = funded(&h).await;
    let memo = "m".repeat(tv_core::MAX_MEMO_LEN + 1);
    let err = payment::request_with_memo(&mut bob, &h.client, Some(1), Some(&memo))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ClientError::Core(tv_core::CoreError::MemoTooLong { .. })
        ),
        "{err}"
    );
    assert!(bob.pending().is_none());
}
