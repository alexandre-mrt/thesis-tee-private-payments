use tv_client::{ChainHead, ClientError, Wallet, WalletData, payment, recover};
use tv_tests::Harness;

async fn paid_with_memo(h: &Harness) -> (Wallet, Wallet) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request_with_memo(&mut bob, &h.client, Some(25), Some("invoice 9"))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    tv_client::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    (alice, bob)
}

#[tokio::test(flavor = "multi_thread")]
async fn both_wallets_keep_the_memo_and_the_latest_chain_head_they_saw() {
    let h = Harness::new().await;
    let (alice, bob) = paid_with_memo(&h).await;
    let entries = h.bank().entries();
    let payment = entries.last().unwrap();
    for wallet in [&alice, &bob] {
        assert_eq!(wallet.memo_for(&payment.digest), Some("invoice 9"));
        assert_eq!(
            wallet.head(),
            Some(ChainHead {
                seq: payment.seq,
                chain: payment.chain
            })
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn c4_recovery_refuses_a_log_that_does_not_hold_a_head_the_wallet_saw() {
    let h = Harness::new().await;
    let (mut alice, _) = paid_with_memo(&h).await;
    let head = alice.head().unwrap();
    assert_eq!(recover(&mut alice, &h.client).await.unwrap(), alice.index());
    assert_eq!(alice.head(), Some(head));

    let forked = WalletData {
        head: Some(ChainHead {
            seq: head.seq,
            chain: [7u8; 32],
        }),
        ..alice.data().clone()
    };
    let mut mallory_view = Wallet::create_with(&h.dir().join("forked.json"), forked).unwrap();
    assert!(matches!(
        recover(&mut mallory_view, &h.client).await,
        Err(ClientError::ChainMismatch { seq }) if seq == head.seq
    ));
    let ahead = WalletData {
        head: Some(ChainHead {
            seq: head.seq + 100,
            chain: head.chain,
        }),
        ..alice.data().clone()
    };
    let mut rolled_back = Wallet::create_with(&h.dir().join("ahead.json"), ahead).unwrap();
    assert!(matches!(
        recover(&mut rolled_back, &h.client).await,
        Err(ClientError::ChainMismatch { .. })
    ));
}
