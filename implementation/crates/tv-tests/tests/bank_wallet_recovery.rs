use std::path::PathBuf;

use tv_bank::bank_wallet_path;
use tv_client::ops::Session;
use tv_client::{
    ClientError, OfferFile, Refreshed, RequestFile, Wallet, WalletData, flows, payment, read_json,
    write_json,
};
use tv_tests::{Harness, RESERVE, client_trust};

fn session(h: &Harness) -> Session {
    Session::open(&bank_wallet_path(h.dir()), h.addr(), &client_trust()).unwrap()
}

fn path(h: &Harness, name: &str) -> PathBuf {
    h.dir().join(name)
}

async fn issue_unfinished(h: &Harness, session: &Session, wallet: &mut Wallet, v: u64) {
    let request = payment::request(wallet, &h.client, Some(v)).await.unwrap();
    let request_path = path(h, &format!("request-{v}.json"));
    let offer_path = path(h, &format!("offer-{v}.json"));
    write_json(&request_path, "request", &request).unwrap();
    tv_bank::issue(h.dir(), session, &request_path, &offer_path, v).unwrap();
    let offer: OfferFile = read_json(&offer_path, "offer").unwrap();
    payment::receive(wallet, &h.client, &offer).await.unwrap();
}

async fn issue(h: &Harness, session: &Session, wallet: &mut Wallet, v: u64) {
    issue_unfinished(h, session, wallet, v).await;
    session.finish(None).await.unwrap();
}

async fn redeem(h: &Harness, session: &Session, wallet: &mut Wallet, v: u64) {
    let request_path = path(h, &format!("redeem-{v}.json"));
    let offer_path = path(h, &format!("redeem-offer-{v}.json"));
    let receipt_path = path(h, &format!("redeem-receipt-{v}.json"));
    session.request(Some(v), &request_path).await.unwrap();
    let request: RequestFile = read_json(&request_path, "request").unwrap();
    let offer = payment::pay(wallet, h.client.verifier(), &request).unwrap();
    write_json(&offer_path, "offer", &offer).unwrap();
    session.receive(&offer_path, &receipt_path).await.unwrap();
    let receipt = read_json(&receipt_path, "receipt").unwrap();
    flows::finish(wallet, &h.client, Some(&receipt))
        .await
        .unwrap();
}

async fn recover_bank(h: &Harness, session: &Session) -> String {
    tv_bank::genesis::recover(h.dir(), session).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forced_refresh_after_a_settled_issue_finishes_it_and_issuance_continues() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut carol = h.wallet("carol");
    h.enroll(&mut alice).await;
    h.enroll(&mut carol).await;
    let session = session(&h);
    issue_unfinished(&h, &session, &mut alice, 100).await;
    assert_eq!(alice.balance(), 100);

    let mut bank_wallet = h.bank_wallet();
    assert_eq!(
        flows::refresh(&mut bank_wallet, &h.client, true)
            .await
            .unwrap(),
        Refreshed::FinishedSettledPayment
    );
    assert!(bank_wallet.pending().is_none());
    assert_eq!(bank_wallet.balance(), RESERVE - 100);
    drop(bank_wallet);

    issue(&h, &session, &mut carol, 5).await;
    assert_eq!(carol.balance(), 5);
    assert_eq!(h.total_supply(&[&alice, &carol]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bank_wallet_restored_from_before_an_issue_is_behind_until_recover_rebuilds_it() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut carol = h.wallet("carol");
    h.enroll(&mut alice).await;
    h.enroll(&mut carol).await;
    let session = session(&h);
    let before_issue: WalletData = h.bank_wallet().data().clone();
    issue(&h, &session, &mut alice, 100).await;

    let restored = path(&h, "restored-bank-wallet.json");
    drop(Wallet::create_with(&restored, before_issue.clone()).unwrap());
    std::fs::rename(&restored, bank_wallet_path(h.dir())).unwrap();
    let mut bank_wallet = h.bank_wallet();
    assert!(matches!(
        flows::refresh(&mut bank_wallet, &h.client, false).await,
        Err(ClientError::Behind { .. })
    ));
    drop(bank_wallet);

    let line = recover_bank(&h, &session).await;
    assert!(
        line.contains(&format!("balance={}", RESERVE - 100)),
        "{line}"
    );
    issue(&h, &session, &mut carol, 5).await;
    assert_eq!(carol.balance(), 5);
    assert_eq!(h.total_supply(&[&alice, &carol]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn recover_rebuilds_the_bank_wallet_across_issues_redeems_and_refreshes() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    let session = session(&h);
    issue(&h, &session, &mut alice, 900_000).await;
    issue(&h, &session, &mut bob, 70).await;
    redeem(&h, &session, &mut alice, 300_000).await;
    session.refresh(false).await.unwrap();
    let expected = h.bank_wallet().data().clone();

    let line = recover_bank(&h, &session).await;
    assert!(
        line.starts_with("recovered 4 state transition(s)"),
        "{line}"
    );
    assert_eq!(h.bank_wallet().data(), &expected);
    assert_eq!(h.bank_wallet().balance(), RESERVE - 900_000 - 70 + 300_000);

    issue_unfinished(&h, &session, &mut bob, 30).await;
    let mut bank_wallet = h.bank_wallet();
    assert_eq!(
        flows::refresh(&mut bank_wallet, &h.client, true)
            .await
            .unwrap(),
        Refreshed::FinishedSettledPayment
    );
    drop(bank_wallet);
    recover_bank(&h, &session).await;
    assert_eq!(h.bank_wallet().balance(), RESERVE - 900_000 - 100 + 300_000);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}
