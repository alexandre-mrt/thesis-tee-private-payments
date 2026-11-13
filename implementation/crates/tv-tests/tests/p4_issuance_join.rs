use std::collections::BTreeMap;

use tv_bank::{IssuanceRecord, bank_wallet_path, read_issuances, record_issuance};
use tv_client::ops::Session;
use tv_client::{ClientError, OfferFile, flows, payment, read_json, write_json};
use tv_core::{BankResponse, Bytes32, LogEntry, OpKind};
use tv_tests::{Harness, client_trust};

const ISSUED: u64 = 4_321;

fn named_balances(entries: &[LogEntry], ledger: &[IssuanceRecord]) -> Vec<(Bytes32, u64)> {
    let issued: BTreeMap<Bytes32, u64> = ledger.iter().map(|r| (r.digest, r.amount)).collect();
    let mut known: BTreeMap<Bytes32, u64> = BTreeMap::new();
    let mut named = Vec::new();
    for entry in entries {
        match entry.kind {
            OpKind::Enroll => {
                known.insert(entry.serials[0], 0);
            }
            OpKind::Refresh => {
                if let Some(balance) = known.remove(&entry.serials[0]) {
                    named.push((entry.commitments[0], balance));
                }
            }
            OpKind::Pay => {
                let payee = known.remove(&entry.serials[1]);
                if let (Some(balance), Some(amount)) = (payee, issued.get(&entry.digest)) {
                    named.push((entry.commitments[1], balance + amount));
                }
            }
        }
    }
    named.retain(|(_, balance)| *balance != 0);
    named
}

async fn issue_through_the_ledger(h: &Harness, wallet: &mut tv_client::Wallet) {
    let session = Session::open(&bank_wallet_path(h.dir()), h.addr(), &client_trust()).unwrap();
    let request_path = h.dir().join("request.json");
    let offer_path = h.dir().join("offer.json");
    let request = payment::request(wallet, &h.client, Some(ISSUED))
        .await
        .unwrap();
    write_json(&request_path, "request", &request).unwrap();
    tv_bank::issue(h.dir(), &session, &request_path, &offer_path, ISSUED).unwrap();
    let offer: OfferFile = read_json(&offer_path, "offer").unwrap();
    payment::receive(wallet, &h.client, &offer).await.unwrap();
    session.finish(None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_on_its_enrolled_serial_refuses_to_request_a_payment() {
    let h = Harness::new().await;
    let mut dave = h.wallet("dave");
    flows::enroll(&mut dave, &h.client).await.unwrap();
    let err = payment::request(&mut dave, &h.client, Some(ISSUED))
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::EnrolledSerial), "{err}");
    assert!(err.to_string().contains("tv-cli refresh"));
    assert!(dave.pending().is_none());
    flows::refresh(&mut dave, &h.client, false).await.unwrap();
    payment::request(&mut dave, &h.client, Some(ISSUED))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn joining_the_issuance_ledger_with_enroll_entries_names_no_balance() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    issue_through_the_ledger(&h, &mut alice).await;
    issue_through_the_ledger(&h, &mut bob).await;
    assert_eq!(read_issuances(h.dir()).unwrap().len(), 2);
    assert_eq!(alice.balance(), ISSUED);

    let named = named_balances(&h.bank().entries(), &read_issuances(h.dir()).unwrap());
    assert!(named.is_empty(), "the bank names balances: {named:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_join_names_the_balance_of_a_payment_to_an_enrolled_serial() {
    let h = Harness::new().await;
    let mut dave = h.wallet("dave");
    flows::enroll(&mut dave, &h.client).await.unwrap();
    let bank_wallet = h.bank_wallet();
    let forged = h.forge(&bank_wallet, &dave, ISSUED);
    drop(bank_wallet);
    let response = h.submit(h.forge_receive(&forged).await).await;
    assert!(
        matches!(response, BankResponse::Settled { .. }),
        "{response:?}"
    );
    let entries = h.bank().entries();
    let pay = entries.last().unwrap();
    record_issuance(
        h.dir(),
        &IssuanceRecord {
            unix_secs: 1,
            amount: ISSUED,
            payee: dave.current_pk().unwrap(),
            digest: pay.digest,
        },
    )
    .unwrap();

    let named = named_balances(&entries, &read_issuances(h.dir()).unwrap());
    assert_eq!(named, vec![(pay.commitments[1], ISSUED)]);
}
