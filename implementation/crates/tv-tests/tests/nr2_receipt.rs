use tv_bank::read_receipt_pk;
use tv_client::{Wallet, flows, payment};
use tv_core::{
    BankRequest, BankResponse, LogEntry, OpKind, VerifyingKey, chain_genesis, encode_cbor,
};
use tv_tests::Harness;

async fn funded(h: &Harness) -> (Wallet, Wallet) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    (alice, bob)
}

fn assert_chained_and_signed(entries: &[LogEntry], key: &VerifyingKey, receipt_pk: &[u8; 32]) {
    let mut head = chain_genesis(receipt_pk);
    for entry in entries {
        entry.verify_owners().unwrap();
        entry.verify_link(&head).unwrap();
        entry.verify_receipt(key).unwrap();
        head = entry.chain;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nr2_every_entry_carries_owner_signatures_and_a_receipt_on_a_chain() {
    let h = Harness::new().await;
    let (mut alice, mut bob) = funded(&h).await;
    h.transfer(&mut alice, &mut bob, 70).await.unwrap();
    flows::refresh(&mut alice, &h.client, false).await.unwrap();
    let entries = h.bank().entries();
    let kinds: Vec<OpKind> = entries.iter().map(|e| e.kind).collect();
    for kind in [OpKind::Enroll, OpKind::Refresh, OpKind::Pay] {
        assert!(kinds.contains(&kind), "{kind:?}");
    }
    let receipt_pk = read_receipt_pk(h.dir()).unwrap();
    let key = VerifyingKey::parse(&receipt_pk).unwrap();
    assert_ne!(receipt_pk, h.keys.state_pk);
    assert_ne!(receipt_pk, h.keys.issuance_pk);
    assert_chained_and_signed(&entries, &key, &receipt_pk);
}

#[tokio::test(flavor = "multi_thread")]
async fn nr2_settled_carries_the_entry_receipt_and_a_retry_after_a_bank_crash_is_byte_identical() {
    let mut h = Harness::new().await;
    let (mut alice, mut bob) = funded(&h).await;
    let request = payment::request(&mut bob, &h.client, Some(60))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receive = BankRequest::Receive(Box::new(h.build_receive(&bob, &offer)));
    let first = h.client.call(&receive).await.unwrap();
    let BankResponse::Settled { receipt, .. } = first else {
        panic!("not settled: {first:?}");
    };
    let entry = h.bank().entries().last().cloned().unwrap();
    assert_eq!(entry.receipt(), receipt);
    assert_eq!(entry.digest, offer.digest());

    h.restart_bank().await;
    let again = h.client.call(&receive).await.unwrap();
    assert_eq!(encode_cbor(&again).unwrap(), encode_cbor(&first).unwrap());
    assert_eq!(h.bank().entries().last(), Some(&entry));
}
