use pt_tee::framing::{read_cbor_bounded, write_frame};
use pt_tee::transport::{Endpoint, connect};
use tv_client::{OfferFile, Wallet, flows, payment};
use tv_core::{
    BankResponse, PaySecret, Receive, SideKind, SigningKey, commitment, decode_cbor, encode_cbor,
    pay_digest, sign_digest, sign_result,
};
use tv_enclave::LeakedMemory;
use tv_tests::{Harness, RESERVE, flip};

struct Scene {
    h: Harness,
    alice: Wallet,
    bob: Wallet,
    mallory: Wallet,
    offer: OfferFile,
    leaked: LeakedMemory,
    secret: PaySecret,
}

async fn scene() -> Scene {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    let mut mallory = h.wallet("mallory");
    for w in [&mut alice, &mut bob, &mut mallory] {
        h.enroll(w).await;
    }
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let leaked = h.link.enclave().leak_memory();
    let plaintext = leaked.open_blob(&offer.payer).unwrap();
    let secret: PaySecret = decode_cbor(&plaintext).unwrap();
    Scene {
        h,
        alice,
        bob,
        mallory,
        offer,
        leaked,
        secret,
    }
}

async fn theft_with_leaked_opening(s: &Scene) -> Receive {
    let mallory_key = s.mallory.current_key().unwrap();
    let steal =
        s.h.client
            .attest(&mallory_key.public_key())
            .await
            .unwrap()
            .channel_pk;
    let com_a_next = commitment(0, &s.secret.opening.next_pk, &s.secret.opening.next_r);
    let mallory_opening = s.mallory.opening().unwrap();
    let com_m_next = commitment(500, &mallory_opening.next_pk, &mallory_opening.next_r);
    let digest = pay_digest(
        &s.offer.pk_a,
        &com_a_next,
        &mallory_key.public_key(),
        &com_m_next,
    );
    let payer = PaySecret {
        v: 500,
        opening: s.secret.opening,
    };
    let payee = PaySecret {
        v: 500,
        opening: mallory_opening,
    };
    Receive {
        channel_pk: steal,
        public: tv_core::PayPublic {
            pk_a: s.offer.pk_a,
            com_a_next,
            sig_a: sign_digest(&SigningKey::generate(), &digest),
            pk_b: mallory_key.public_key(),
            com_b_next: com_m_next,
            sig_b: sign_digest(&mallory_key, &digest),
        },
        payer: tv_client::seal_to(&steal, &payer).unwrap(),
        payee: tv_client::seal_to(&steal, &payee).unwrap(),
    }
}

async fn finish_honestly(s: &mut Scene) {
    let receipt = payment::receive(&mut s.bob, &s.h.client, &s.offer)
        .await
        .unwrap();
    flows::finish(&mut s.alice, &s.h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(s.alice.balance(), 400);
    assert_eq!(s.bob.balance(), 100);
    assert_eq!(s.mallory.balance(), 0);
    assert_eq!(s.h.total_supply(&[&s.alice, &s.bob, &s.mallory]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn leaked_enclave_memory_opens_the_sealed_opening() {
    let s = scene().await;
    assert_eq!(
        s.leaked.result_key.public_key(),
        s.h.result_key.public_key()
    );
    assert!(s.leaked.channel_count() >= 1);
    assert_eq!(s.secret.v, 100);
    assert_eq!(s.secret.opening.balance, 500);
    assert_eq!(s.secret.opening, s.alice.opening().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn leaked_channel_keys_do_not_spend_alice_s_state() {
    let mut s = scene().await;
    let entries = s.h.bank().entries().len();
    let theft = theft_with_leaked_opening(&s).await;
    assert_eq!(s.h.submit(theft).await, BankResponse::Refused);
    assert_eq!(s.h.bank().entries().len(), entries);
    finish_honestly(&mut s).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_leaked_result_key_has_no_path_into_the_bank() {
    let mut s = scene().await;
    let entries = s.h.bank().entries().len();
    let digest = pay_digest(
        &s.offer.pk_a,
        &s.offer.com_a_next,
        &s.offer.pk_b,
        &s.offer.com_b_next,
    );
    let minted = sign_result(
        &s.leaked.result_key,
        [0u8; 32],
        flip(&digest),
        vec![SideKind::User, SideKind::User],
    );
    let mut stream = connect(&Endpoint::tcp(s.h.addr()).unwrap()).await.unwrap();
    write_frame(&mut stream, &encode_cbor(&minted).unwrap())
        .await
        .unwrap();
    let response: BankResponse = read_cbor_bounded(&mut stream, 1024).await.unwrap();
    assert_eq!(response, BankResponse::Refused);
    assert_eq!(s.h.bank().entries().len(), entries);
    finish_honestly(&mut s).await;
}
