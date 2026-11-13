use pt_tee::framing::{read_cbor_bounded, write_frame};
use pt_tee::transport::{Endpoint, connect};
use tv_core::{
    B_MAX, BankRequest, BankResponse, SideKind, Signature, SigningKey, encode_cbor, sign_result,
    sign_state,
};
use tv_tests::{Harness, Mode, RESERVE};

async fn setup() -> (Harness, tv_client::Wallet, tv_client::Wallet) {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    (h, alice, bob)
}

#[tokio::test(flavor = "multi_thread")]
async fn amounts_outside_the_rules_are_refused() {
    let (h, alice, bob) = setup().await;
    let entries = h.bank().entries().len();

    let mut wrong_amount = h.forge(&alice, &bob, 100);
    wrong_amount.payee_secret.v = 50;
    assert_eq!(
        h.submit(h.forge_receive(&wrong_amount).await).await,
        BankResponse::Refused
    );
    let mut both_wrong = h.forge(&alice, &bob, 100);
    both_wrong.payer_secret.v = 60;
    both_wrong.payee_secret.v = 60;
    assert_eq!(
        h.submit(h.forge_receive(&both_wrong).await).await,
        BankResponse::Refused
    );

    let zero = h.forge(&alice, &bob, 0);
    assert_eq!(
        h.submit(h.forge_receive(&zero).await).await,
        BankResponse::Refused
    );

    let too_much = h.forge(&alice, &bob, 501);
    assert_eq!(
        h.submit(h.forge_receive(&too_much).await).await,
        BankResponse::Refused
    );

    let honest = h.forge(&alice, &bob, 500);
    assert!(matches!(
        h.submit(h.forge_receive(&honest).await).await,
        BankResponse::Settled { .. }
    ));
    assert_eq!(h.bank().entries().len(), entries + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_balance_cap_binds_users_but_not_the_bank() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut bob, B_MAX - 10).await.unwrap();
    h.issue(&mut alice, 100).await.unwrap();
    let over = h.forge(&alice, &bob, 20);
    assert_eq!(
        h.submit(h.forge_receive(&over).await).await,
        BankResponse::Refused
    );
    let fits = h.forge(&alice, &bob, 10);
    assert!(matches!(
        h.submit(h.forge_receive(&fits).await).await,
        BankResponse::Settled { .. }
    ));
    assert!(h.bank_wallet().balance() > B_MAX);
    let mut bank_wallet = h.bank_wallet();
    let mut bob = tv_client::Wallet::create_with(
        &h.dir().join("bob-synced.json"),
        tv_client::WalletData {
            seed: bob.seed(),
            bank: h.keys,
            index: 0,
            state: None,
            pending: None,
        },
    )
    .unwrap();
    tv_client::recover::recover(&mut bob, &h.client)
        .await
        .unwrap();
    assert_eq!(bob.balance(), B_MAX);
    h.transfer(&mut bob, &mut bank_wallet, 5).await.unwrap();
    assert_eq!(bank_wallet.balance(), RESERVE - (B_MAX - 10) - 100 + 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn unsigned_forged_or_foreign_states_are_refused() {
    let (h, alice, bob) = setup().await;
    let com_a = alice.state().unwrap().state.commitment();

    let mut unsigned = h.forge(&alice, &bob, 100);
    unsigned.payer_secret.opening.sig = Signature([0u8; 64]);
    assert_eq!(
        h.submit(h.forge_receive(&unsigned).await).await,
        BankResponse::Refused
    );

    let mut richer = h.forge(&alice, &bob, 100);
    richer.payer_secret.opening.balance = 5_000;
    richer.a_next = 4_900;
    assert_eq!(
        h.submit(h.forge_receive(&richer).await).await,
        BankResponse::Refused
    );

    let mut foreign = h.forge(&alice, &bob, 100);
    foreign.payer_secret.opening.sig = sign_state(&SigningKey::generate(), &com_a);
    assert_eq!(
        h.submit(h.forge_receive(&foreign).await).await,
        BankResponse::Refused
    );

    let mut payee_forged = h.forge(&alice, &bob, 100);
    payee_forged.payee_secret.opening.balance = 1_000;
    payee_forged.b_next = 1_100;
    assert_eq!(
        h.submit(h.forge_receive(&payee_forged).await).await,
        BankResponse::Refused
    );
    assert_eq!(h.bank().entries().len(), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn results_over_another_nonce_or_digest_are_rejected_by_the_bank() {
    let (h, mut alice, mut bob) = setup().await;
    for mode in [
        Mode::ForgeNonce(h.result_key.clone()),
        Mode::ForgeDigest(h.result_key.clone()),
    ] {
        h.link.set_mode(mode);
        let honest = h.forge(&alice, &bob, 100);
        assert_eq!(
            h.submit(h.forge_receive(&honest).await).await,
            BankResponse::Refused
        );
    }
    h.link.set_mode(Mode::Normal);
    assert_eq!(h.bank().entries().len(), 5);
    h.transfer(&mut alice, &mut bob, 100).await.unwrap();
    assert_eq!(bob.balance(), 100);
}

fn every_bank_request_variant_is_result_free_at_compile_time(request: &BankRequest) {
    match request {
        BankRequest::Attest { .. }
        | BankRequest::Receive(_)
        | BankRequest::Enroll(_)
        | BankRequest::Refresh(_)
        | BankRequest::Lookup { .. }
        | BankRequest::LogRange { .. }
        | BankRequest::RegisterEnclave => {}
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn there_is_no_path_for_a_user_to_submit_a_signed_result() {
    let (h, alice, bob) = setup().await;
    let mint = h.forge(&alice, &bob, 100);
    let receive = h.forge_receive(&mint).await;
    let digest = tv_core::pay_digest(
        &receive.public.pk_a,
        &receive.public.com_a_next,
        &receive.public.pk_b,
        &receive.public.com_b_next,
    );
    let forged = sign_result(
        &h.result_key,
        [0u8; 32],
        digest,
        vec![SideKind::User, SideKind::User],
    );
    assert!(
        tv_core::verify_result(&h.result_key.public_key(), &forged, &[0u8; 32], &digest).is_ok()
    );
    let mut stream = connect(&Endpoint::tcp(h.addr()).unwrap()).await.unwrap();
    write_frame(&mut stream, &encode_cbor(&forged).unwrap())
        .await
        .unwrap();
    let response: BankResponse = read_cbor_bounded(&mut stream, 1024).await.unwrap();
    assert_eq!(response, BankResponse::Refused);
    every_bank_request_variant_is_result_free_at_compile_time(&BankRequest::Lookup {
        serial: [0u8; 32],
    });
    assert_eq!(h.bank().entries().len(), 5);
}
