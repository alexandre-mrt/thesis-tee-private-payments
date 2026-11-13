use tv_bank::{IssuanceRecord, bank_wallet_path, read_issuances};
use tv_client::ops::Session;
use tv_client::{OfferFile, flows, payment, read_json, write_json};
use tv_tests::{Harness, RESERVE, client_trust};

const ISSUED: u64 = 123_457;

#[tokio::test(flavor = "multi_thread")]
async fn issue_records_the_amount_in_a_private_ledger_and_not_in_the_public_log() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    h.enroll(&mut alice).await;
    let request_path = h.dir().join("request.json");
    let offer_path = h.dir().join("offer.json");
    let request = payment::request(&mut alice, &h.client, Some(ISSUED))
        .await
        .unwrap();
    write_json(&request_path, "request", &request).unwrap();
    let payee = alice.current_pk().unwrap();

    let session = Session::open(&bank_wallet_path(h.dir()), h.addr(), &client_trust()).unwrap();
    let line = tv_bank::issue(h.dir(), &session, &request_path, &offer_path, ISSUED).unwrap();
    assert!(line.contains(&ISSUED.to_string()));

    let offer: OfferFile = read_json(&offer_path, "offer").unwrap();
    let receipt = payment::receive(&mut alice, &h.client, &offer)
        .await
        .unwrap();
    let receipt_path = h.dir().join("receipt.json");
    write_json(&receipt_path, "receipt", &receipt).unwrap();
    session.finish(Some(&receipt_path)).await.unwrap();
    assert_eq!(alice.balance(), ISSUED);
    assert_eq!(h.total_supply(&[&alice]), RESERVE);

    let ledger = read_issuances(h.dir()).unwrap();
    assert_eq!(ledger.len(), 1);
    let record = &ledger[0];
    assert_eq!(record.amount, ISSUED);
    assert_eq!(record.payee, payee);
    assert_eq!(record.digest, receipt.digest);
    assert!(record.unix_secs > 0);

    let view = String::from_utf8(h.bank().view_bytes().unwrap()).unwrap();
    assert!(!view.contains(&ISSUED.to_string()));
    let log = std::fs::read_to_string(h.dir().join(tv_bank::LOG_FILE)).unwrap();
    assert!(!log.contains(&ISSUED.to_string()));

    let mut bank_wallet = h.bank_wallet();
    flows::refresh(&mut bank_wallet, &h.client, false)
        .await
        .unwrap();
    assert_eq!(read_issuances(h.dir()).unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn issue_writes_no_offer_and_commits_nothing_when_the_ledger_cannot_be_written() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    h.enroll(&mut alice).await;
    let request_path = h.dir().join("request.json");
    let offer_path = h.dir().join("offer.json");
    let request = payment::request(&mut alice, &h.client, Some(ISSUED))
        .await
        .unwrap();
    write_json(&request_path, "request", &request).unwrap();
    let ledger = tv_bank::ledger_path(h.dir());
    std::fs::create_dir(&ledger).unwrap();

    let session = Session::open(&bank_wallet_path(h.dir()), h.addr(), &client_trust()).unwrap();
    let err = tv_bank::issue(h.dir(), &session, &request_path, &offer_path, ISSUED).unwrap_err();
    assert!(matches!(err, tv_bank::BankError::File { .. }), "{err}");
    assert!(
        err.to_string().contains(tv_bank::ISSUANCE_LEDGER_FILE),
        "{err}"
    );
    assert!(!offer_path.exists());
    assert_eq!(h.bank_wallet().pending(), None);
    assert_eq!(h.bank_wallet().balance(), RESERVE);

    std::fs::remove_dir(&ledger).unwrap();
    tv_bank::issue(h.dir(), &session, &request_path, &offer_path, ISSUED).unwrap();
    assert!(offer_path.exists());
    assert!(matches!(
        h.bank_wallet().pending(),
        Some(tv_client::Pending::Pay { v, .. }) if *v == ISSUED
    ));
    let offer: OfferFile = read_json(&offer_path, "offer").unwrap();
    let receipt = payment::receive(&mut alice, &h.client, &offer)
        .await
        .unwrap();
    let ledger = read_issuances(h.dir()).unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].amount, ISSUED);
    assert_eq!(ledger[0].digest, receipt.digest);
}

#[tokio::test(flavor = "multi_thread")]
async fn issue_refuses_a_request_whose_amount_differs_from_the_agreed_one() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    h.enroll(&mut alice).await;
    let request_path = h.dir().join("request.json");
    let offer_path = h.dir().join("offer.json");
    let request = payment::request(&mut alice, &h.client, Some(ISSUED))
        .await
        .unwrap();
    write_json(&request_path, "request", &request).unwrap();

    let session = Session::open(&bank_wallet_path(h.dir()), h.addr(), &client_trust()).unwrap();
    let err =
        tv_bank::issue(h.dir(), &session, &request_path, &offer_path, ISSUED - 1).unwrap_err();
    assert!(
        matches!(
            err,
            tv_bank::BankError::IssueAmount { agreed, requested } if agreed == ISSUED - 1 && requested == ISSUED
        ),
        "{err}"
    );
    assert!(!offer_path.exists());
    assert!(read_issuances(h.dir()).unwrap().is_empty());
    assert_eq!(h.bank_wallet().pending(), None);
    assert_eq!(h.bank_wallet().balance(), RESERVE);

    tv_bank::issue(h.dir(), &session, &request_path, &offer_path, ISSUED).unwrap();
    let offer: OfferFile = read_json(&offer_path, "offer").unwrap();
    payment::receive(&mut alice, &h.client, &offer)
        .await
        .unwrap();
    assert_eq!(alice.balance(), ISSUED);
    assert_eq!(read_issuances(h.dir()).unwrap()[0].amount, ISSUED);
}

async fn issue_and_receive(
    h: &Harness,
    session: &Session,
    wallet: &mut tv_client::Wallet,
    v: u64,
    times: usize,
) {
    let request_path = h.dir().join(format!("request-{v}.json"));
    let offer_path = h.dir().join(format!("offer-{v}.json"));
    let request = payment::request(wallet, &h.client, Some(v)).await.unwrap();
    write_json(&request_path, "request", &request).unwrap();
    for _ in 0..times {
        tv_bank::issue(h.dir(), session, &request_path, &offer_path, v).unwrap();
    }
    let offer: OfferFile = read_json(&offer_path, "offer").unwrap();
    payment::receive(wallet, &h.client, &offer).await.unwrap();
    session.finish(None).await.unwrap();
}

fn tear_tail(path: &std::path::Path) {
    let whole = std::fs::read(path).unwrap();
    let mut torn = whole.clone();
    torn.extend_from_slice(&whole[..40]);
    std::fs::write(path, &torn).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_torn_ledger_tail_and_a_repeated_issue_leave_one_parseable_line_per_issuance() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    let session = Session::open(&bank_wallet_path(h.dir()), h.addr(), &client_trust()).unwrap();
    issue_and_receive(&h, &session, &mut alice, 50, 2).await;
    assert_eq!(read_issuances(h.dir()).unwrap().len(), 1);
    let ledger = tv_bank::ledger_path(h.dir());
    tear_tail(&ledger);
    issue_and_receive(&h, &session, &mut bob, 7, 1).await;
    assert_eq!(bob.balance(), 7);

    let text = std::fs::read_to_string(&ledger).unwrap();
    assert_eq!(text.lines().count(), 2);
    let amounts: Vec<u64> = text
        .lines()
        .map(|line| serde_json::from_str::<IssuanceRecord>(line).unwrap().amount)
        .collect();
    assert_eq!(amounts, vec![50, 7]);
    let records = read_issuances(h.dir()).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records.iter().map(|r| r.amount).sum::<u64>(), 57);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}
