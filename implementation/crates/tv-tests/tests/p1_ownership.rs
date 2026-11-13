use tv_client::{BankClient, ClientError, Wallet, flows, payment, seal_to};
use tv_core::{
    BankRequest, BankResponse, RefreshRequest, RefreshSecret, Signature, SigningKey, commitment,
    refresh_digest, sign_digest,
};
use tv_tests::{Harness, Mode, flip};

async fn refused(h: &Harness, receive: tv_core::Receive) {
    assert_eq!(h.submit(receive).await, BankResponse::Refused);
}

async fn funded_trio(h: &Harness) -> (Wallet, Wallet, Wallet) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    let mut carol = h.wallet("carol");
    for w in [&mut alice, &mut bob, &mut carol] {
        h.enroll(w).await;
    }
    h.issue(&mut alice, 500).await.unwrap();
    (alice, bob, carol)
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_or_reused_payer_signature_is_refused_even_by_a_lenient_enclave() {
    let h = Harness::new().await;
    let (mut alice, mut bob, mut carol) = funded_trio(&h).await;
    h.link.set_mode(Mode::Lenient(h.result_key.clone()));

    let request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();

    payment::request(&mut carol, &h.client, Some(100))
        .await
        .unwrap();
    refused(&h, h.build_receive(&carol, &offer)).await;

    let mut redirected = h.build_receive(&bob, &offer);
    redirected.public.com_b_next = flip(&redirected.public.com_b_next);
    let digest = tv_core::pay_digest(
        &redirected.public.pk_a,
        &redirected.public.com_a_next,
        &redirected.public.pk_b,
        &redirected.public.com_b_next,
    );
    redirected.public.sig_b = sign_digest(&bob.current_key().unwrap(), &digest);
    refused(&h, redirected).await;

    let mut forged = h.build_receive(&bob, &offer);
    forged.public.sig_a = Signature([3u8; 64]);
    refused(&h, forged).await;
    let mut other_key = h.build_receive(&bob, &offer);
    other_key.public.sig_a = sign_digest(&SigningKey::generate(), &digest);
    refused(&h, other_key).await;

    let mut amount_changed = h.build_receive(&bob, &offer);
    amount_changed.public.com_a_next = flip(&amount_changed.public.com_a_next);
    refused(&h, amount_changed).await;

    assert_eq!(h.bank().entries().len(), 7);
    h.link.set_mode(Mode::Normal);
    let request = payment::request(&mut bob, &h.client, None).await.unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, None).await.unwrap();
    assert_eq!(alice.balance(), 400);
    assert_eq!(bob.balance(), 100);
}

async fn forged_refresh(
    client: &BankClient,
    victim: &Wallet,
    attacker: &SigningKey,
) -> BankResponse {
    let pk = victim.current_pk().unwrap();
    let attested = client.attest(&pk).await.unwrap();
    let opening = victim.opening().unwrap();
    let com_next = commitment(opening.balance, &opening.next_pk, &opening.next_r);
    let request = RefreshRequest {
        channel_pk: attested.channel_pk,
        pk,
        com_next,
        sig: sign_digest(attacker, &refresh_digest(&pk, &com_next)),
        sealed: seal_to(&attested.channel_pk, &RefreshSecret { opening }).unwrap(),
    };
    client
        .call(&BankRequest::Refresh(Box::new(request)))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_owner_key_nobody_refreshes_or_burns_a_state() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut mallory = h.wallet("mallory");
    h.enroll(&mut alice).await;
    h.enroll(&mut mallory).await;
    h.issue(&mut alice, 500).await.unwrap();
    let mallory_key = SigningKey::generate();

    assert_eq!(
        forged_refresh(&h.client, &alice, &mallory_key).await,
        BankResponse::Refused
    );
    h.link.set_mode(Mode::Lenient(h.result_key.clone()));
    assert_eq!(
        forged_refresh(&h.client, &alice, &mallory_key).await,
        BankResponse::Refused
    );

    let mut burn = h.forge(&alice, &mallory, 500);
    burn.payer_signer = mallory_key.clone();
    let receive = h.forge_receive(&burn).await;
    refused(&h, receive).await;
    let mut burn_with_own_key = h.forge(&alice, &mallory, 500);
    burn_with_own_key.payer_signer = mallory.current_key().unwrap();
    let receive = h.forge_receive(&burn_with_own_key).await;
    refused(&h, receive).await;
    h.link.set_mode(Mode::Normal);

    assert_eq!(h.bank().entries().len(), 5);
    assert!(!h.spent_serials().contains(&alice.current_pk().unwrap()));
    flows::refresh(&mut alice, &h.client, false).await.unwrap();
    assert_eq!(alice.balance(), 500);
    assert!(matches!(
        payment::pay(
            &mut mallory,
            h.client.verifier(),
            &payment::request(&mut alice, &h.client, Some(10))
                .await
                .unwrap()
        ),
        Err(ClientError::Insufficient { .. })
    ));
}
