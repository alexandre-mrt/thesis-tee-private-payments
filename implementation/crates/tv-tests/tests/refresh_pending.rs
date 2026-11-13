use tv_client::{ClientError, flows, payment};
use tv_tests::{Harness, RESERVE};

#[tokio::test(flavor = "multi_thread")]
async fn refresh_refuses_to_abandon_a_pending_payment_unless_forced() {
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
    let before = alice.data().clone();
    let err = flows::refresh(&mut alice, &h.client, false)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ClientError::RefreshBlocked {
            what: "payment",
            ..
        }
    ));
    let message = err.to_string();
    assert!(message.contains("tv-cli recover"));
    assert!(message.contains("--force"));
    assert!(message.contains("finish"));
    assert_eq!(alice.data(), &before);
    let entries = h.bank().entries().len();

    flows::refresh(&mut alice, &h.client, true).await.unwrap();
    assert!(alice.pending().is_none());
    assert_eq!(alice.balance(), 500);
    assert_ne!(alice.current_pk().unwrap(), offer.pk_a);
    assert_eq!(h.bank().entries().len(), entries + 1);
    let refused = payment::receive(&mut bob, &h.client, &offer)
        .await
        .unwrap_err();
    assert!(matches!(refused, ClientError::ReceiveRefused), "{refused}");
    assert!(refused.to_string().contains("`tv-cli refresh --force`"));
    assert_eq!(bob.balance(), 0);
    let exposed = bob.current_pk().unwrap();
    flows::refresh(&mut bob, &h.client, true).await.unwrap();
    assert!(bob.pending().is_none());
    assert_ne!(bob.current_pk().unwrap(), exposed);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_refuses_to_abandon_a_pending_request_unless_forced() {
    let h = Harness::new().await;
    let mut bob = h.wallet("bob");
    h.enroll(&mut bob).await;
    payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let pk = bob.current_pk().unwrap();
    let blocked = flows::refresh(&mut bob, &h.client, false)
        .await
        .unwrap_err();
    assert!(matches!(
        blocked,
        ClientError::RefreshBlocked {
            what: "request",
            ..
        }
    ));
    assert!(blocked.to_string().contains("tv-cli receive --offer"));
    assert!(!blocked.to_string().contains("finish"));
    assert_eq!(bob.current_pk().unwrap(), pk);
    assert!(bob.pending().is_some());
    flows::refresh(&mut bob, &h.client, true).await.unwrap();
    assert!(bob.pending().is_none());
    assert_ne!(bob.current_pk().unwrap(), pk);
    assert!(h.spent_serials().contains(&pk));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payer_whose_request_was_abandoned_is_told_to_force_refresh() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();

    let abandoned = payment::request(&mut bob, &h.client, Some(3))
        .await
        .unwrap();
    payment::pay(&mut alice, h.client.verifier(), &abandoned).unwrap();
    flows::refresh(&mut bob, &h.client, true).await.unwrap();
    let fresh = payment::request(&mut bob, &h.client, Some(9))
        .await
        .unwrap();
    let mismatch = payment::pay(&mut alice, h.client.verifier(), &fresh).unwrap_err();
    assert!(
        matches!(mismatch, ClientError::PayRequestMismatch),
        "{mismatch}"
    );
    let text = mismatch.to_string();
    assert!(text.contains("another payee serial or amount"), "{text}");
    assert!(
        text.contains("`tv-cli refresh --force`, then `tv-cli pay`"),
        "{text}"
    );
    let unsettled = flows::finish(&mut alice, &h.client, None)
        .await
        .unwrap_err();
    assert!(
        matches!(unsettled, ClientError::NotSettled { .. }),
        "{unsettled}"
    );
    let text = unsettled.to_string();
    assert!(text.contains("tv-cli receive"), "{text}");
    assert!(text.contains("`tv-cli refresh --force`"), "{text}");

    flows::refresh(&mut alice, &h.client, true).await.unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &fresh).unwrap();
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!((alice.balance(), bob.balance()), (491, 9));
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payee_given_an_offer_for_another_request_is_told_how_to_proceed() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();

    let earlier = payment::request(&mut bob, &h.client, Some(4))
        .await
        .unwrap();
    let latest = payment::request(&mut bob, &h.client, None).await.unwrap();
    let stale = payment::pay(&mut alice, h.client.verifier(), &earlier).unwrap();
    let err = payment::receive(&mut bob, &h.client, &stale)
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::OfferForEarlierRequest), "{err}");
    assert!(
        err.to_string()
            .contains("`tv-cli reseal --request <latest request.json>`")
    );
    let resealed = payment::pay(&mut alice, h.client.verifier(), &latest).unwrap();
    let receipt = payment::receive(&mut bob, &h.client, &resealed)
        .await
        .unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(bob.balance(), 4);

    let abandoned = payment::request(&mut bob, &h.client, Some(3))
        .await
        .unwrap();
    let orphan = payment::pay(&mut alice, h.client.verifier(), &abandoned).unwrap();
    flows::refresh(&mut bob, &h.client, true).await.unwrap();
    payment::request(&mut bob, &h.client, Some(9))
        .await
        .unwrap();
    let err = payment::receive(&mut bob, &h.client, &orphan)
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::OfferForOtherRequest), "{err}");
    let text = err.to_string();
    assert!(text.contains("answers another request"), "{text}");
    assert!(text.contains("`tv-cli refresh --force`"), "{text}");
    assert_eq!(bob.balance(), 4);
}
