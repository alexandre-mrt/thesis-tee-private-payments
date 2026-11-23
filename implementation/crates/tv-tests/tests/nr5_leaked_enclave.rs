use tv_client::proof::{Mode, check, prove};
use tv_client::{OfferFile, Wallet, flows, payment};
use tv_core::{
    AmountOpening, BankRequest, PairSecret, PaySecret, Presentation, Proof, Receive, Role,
    chain_genesis, decode_cbor, encode_cbor, sign_presentation,
};
use tv_enclave::LeakedMemory;
use tv_tests::Harness;

const MEMO: &str = "contract 5150, private terms";
const CHALLENGE: [u8; 32] = [8u8; 32];

struct Scene {
    h: Harness,
    alice: Wallet,
    bob: Wallet,
    offer: OfferFile,
    receive: Receive,
    leaked: LeakedMemory,
    pair: PairSecret,
}

async fn scene() -> Scene {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request_with_memo(&mut bob, &h.client, Some(100), Some(MEMO))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receive = h.build_receive(&bob, &offer);
    let leaked = h.link.enclave().leak_memory();
    let key = alice.current_key().unwrap();
    let pair = PairSecret::derive(&key, &offer.pk_a, &offer.pk_b).unwrap();
    Scene {
        h,
        alice,
        bob,
        offer,
        receive,
        leaked,
        pair,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn holds(haystack: &[u8], value: &[u8; 32]) -> bool {
    contains(haystack, value) || contains(haystack, &encode_cbor(value).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn nr5_nothing_the_enclave_receives_or_holds_carries_the_blind_the_context_or_the_memo() {
    let s = scene().await;
    let (r_v, n_ctx) = (s.pair.r_v().unwrap(), s.pair.n_ctx().unwrap());
    let check = encode_cbor(&BankRequest::Receive(Box::new(s.receive.clone()))).unwrap();
    let opened: Vec<Vec<u8>> = [&s.receive.payer, &s.receive.payee]
        .into_iter()
        .map(|blob| s.leaked.open_blob(blob).unwrap())
        .collect();
    for secret in &opened {
        let decoded: PaySecret = decode_cbor(secret).unwrap();
        assert_eq!(decoded.v, 100);
    }
    for seen in opened.iter().chain([&check]) {
        assert!(!holds(seen, &r_v));
        assert!(!holds(seen, &n_ctx));
        assert!(!contains(seen, MEMO.as_bytes()));
    }
    assert!(holds(&check, &s.offer.c_v));
    assert!(holds(&check, &s.offer.h_ctx));
}

#[tokio::test(flavor = "multi_thread")]
async fn nr5_leaked_enclave_keys_forge_no_receipt_and_no_proof() {
    let mut s = scene().await;
    let receipt = payment::receive(&mut s.bob, &s.h.client, &s.offer)
        .await
        .unwrap();
    flows::finish(&mut s.alice, &s.h.client, Some(&receipt))
        .await
        .unwrap();
    let log = s.h.client.full_log().await.unwrap();
    let honest = prove(&s.alice, &log, receipt.entry.seq, Mode::Payer, CHALLENGE).unwrap();
    assert!(check(&s.bob, &honest, &CHALLENGE, None).is_ok());

    let forged_entry = tv_core::LogEntry {
        seq: receipt.entry.seq + 1,
        ..receipt.entry.clone()
    }
    .sealed(&receipt.entry.chain, &s.leaked.result_key);
    let receipt_key = tv_core::VerifyingKey::parse(&s.h.receipt_pk).unwrap();
    assert!(forged_entry.verify_receipt(&receipt_key).is_err());
    let resealed = receipt
        .entry
        .clone()
        .sealed(&chain_genesis(&s.h.receipt_pk), &s.leaked.result_key);
    assert!(resealed.verify_receipt(&receipt_key).is_err());

    let inflated = Proof {
        amount: AmountOpening {
            v: 1_000,
            ..honest.amount
        },
        ..honest.clone()
    };
    assert!(check(&s.bob, &inflated, &CHALLENGE, None).is_err());
    let leaked_signer = Proof {
        presentation: Presentation::Signed {
            role: Role::Payer,
            sig: sign_presentation(&s.leaked.result_key, Role::Payer, &honest.entry, &CHALLENGE),
        },
        ..honest.clone()
    };
    assert!(check(&s.bob, &leaked_signer, &CHALLENGE, None).is_err());
    let rewritten = Proof {
        entry: forged_entry,
        ..honest
    };
    assert!(check(&s.bob, &rewritten, &CHALLENGE, None).is_err());
}
