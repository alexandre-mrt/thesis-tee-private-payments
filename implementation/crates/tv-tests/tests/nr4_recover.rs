use tv_client::proof::{Mode, check, prove};
use tv_client::{ClientError, Wallet, flows, payment, recover};
use tv_core::{Proof, Role, SigningKey};
use tv_tests::Harness;

const CHALLENGE: [u8; 32] = [5u8; 32];

async fn paid(h: &Harness) -> (Wallet, Wallet, u64) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request_with_memo(&mut bob, &h.client, Some(130), Some("order 77"))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    (alice, bob, receipt.entry.seq)
}

fn without_memo(proof: &Proof) -> Proof {
    Proof {
        context: None,
        ..proof.clone()
    }
}

async fn rebuilt(h: &Harness, name: &str, from: &Wallet, digest: &[u8; 32]) -> Wallet {
    let mut fresh = h.wallet_from_seed(name, from.seed());
    recover(&mut fresh, &h.client).await.unwrap();
    assert_eq!(fresh.balance(), from.balance());
    assert_eq!(from.memo_for(digest), Some("order 77"));
    assert_eq!(fresh.memo_for(digest), None);
    fresh
}

#[tokio::test(flavor = "multi_thread")]
async fn nr4_proofs_rebuilt_from_the_seed_and_the_log_match_the_originals_but_for_the_memo() {
    let h = Harness::new().await;
    let (alice, bob, seq) = paid(&h).await;
    let log = h.client.full_log().await.unwrap();
    let payer = prove(&alice, &log, seq, Mode::Payer, CHALLENGE).unwrap();
    let payee = prove(&bob, &log, seq, Mode::Payee, CHALLENGE).unwrap();
    for (proof, role) in [(&payer, Role::Payer), (&payee, Role::Payee)] {
        let facts = check(&alice, proof, &CHALLENGE, None).unwrap();
        assert_eq!((facts.seq, facts.v), (seq, 130));
        assert_eq!(facts.memo.as_deref(), Some("order 77"));
        assert_eq!(facts.holder.map(|(r, _)| r), Some(role));
    }

    let digest = payer.entry.digest;
    let alice_again = rebuilt(&h, "alice-again", &alice, &digest).await;
    let bob_again = rebuilt(&h, "bob-again", &bob, &digest).await;
    let log = h.client.full_log().await.unwrap();
    let payer_again = prove(&alice_again, &log, seq, Mode::Payer, CHALLENGE).unwrap();
    let payee_again = prove(&bob_again, &log, seq, Mode::Payee, CHALLENGE).unwrap();
    assert_eq!(payer_again, without_memo(&payer));
    assert_eq!(payee_again, without_memo(&payee));
    assert_eq!(check(&bob, &payer_again, &CHALLENGE, None).unwrap().v, 130);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_proves_only_its_own_side_and_designated_proofs_need_the_verifier_key() {
    let h = Harness::new().await;
    let (alice, bob, seq) = paid(&h).await;
    let log = h.client.full_log().await.unwrap();
    assert!(matches!(
        prove(&bob, &log, seq, Mode::Payer, CHALLENGE),
        Err(ClientError::Prove { .. })
    ));
    let carol = h.wallet("carol");
    assert!(matches!(
        prove(&carol, &log, seq, Mode::Amount, CHALLENGE),
        Err(ClientError::Prove { .. })
    ));
    assert!(prove(&alice, &log, 0, Mode::Amount, CHALLENGE).is_err());

    let verifier = SigningKey::generate();
    let designated = Mode::Designated {
        verifier_pk: verifier.public_key(),
    };
    let proof = prove(&bob, &log, seq, designated, CHALLENGE).unwrap();
    let facts = check(&carol, &proof, &CHALLENGE, Some(&verifier)).unwrap();
    assert!(!facts.transferable);
    assert!(check(&carol, &proof, &CHALLENGE, None).is_err());
    assert!(check(&carol, &proof, &CHALLENGE, Some(&SigningKey::generate())).is_err());
    let amount = prove(&alice, &log, seq, Mode::Amount, CHALLENGE).unwrap();
    let amount_facts = check(&carol, &amount, &CHALLENGE, None).unwrap();
    assert_eq!(amount_facts.holder, None);
    assert!(amount_facts.transferable);
}
