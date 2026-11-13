use std::path::{Path, PathBuf};

use tv_client::ops::Session;
use tv_client::{ClientError, Pending, RequestFile, Wallet, payment, read_json, write_json};
use tv_tests::{Harness, client_trust};

struct Payer {
    path: PathBuf,
    session: Session,
}

impl Payer {
    fn wallet(&self) -> Wallet {
        Wallet::load(&self.path).unwrap()
    }
}

async fn funded_payer(h: &Harness, name: &str, amount: u64) -> Payer {
    let mut wallet = h.wallet(name);
    h.enroll(&mut wallet).await;
    h.issue(&mut wallet, amount).await.unwrap();
    let path = wallet.path().to_path_buf();
    drop(wallet);
    let session = Session::open(&path, h.addr(), &client_trust()).unwrap();
    Payer { path, session }
}

async fn request_file(h: &Harness, payee: &mut Wallet, amount: Option<u64>, name: &str) -> PathBuf {
    let request = payment::request(payee, &h.client, amount).await.unwrap();
    let path = h.dir().join(name);
    write_json(&path, "request", &request).unwrap();
    path
}

fn with_amount(path: &Path, v: u64) -> PathBuf {
    let mut request: RequestFile = read_json(path, "request").unwrap();
    request.v = v;
    let tampered = path.with_extension("tampered.json");
    write_json(&tampered, "request", &request).unwrap();
    tampered
}

#[tokio::test(flavor = "multi_thread")]
async fn pay_refuses_a_request_for_another_amount_before_anything_is_written() {
    let h = Harness::new().await;
    let mut bob = h.wallet("bob");
    h.enroll(&mut bob).await;
    let alice = funded_payer(&h, "alice", 500).await;
    let request = request_file(&h, &mut bob, Some(500), "request.json").await;
    let offer = h.dir().join("offer.json");

    let err = alice.session.pay(&request, &offer, 10).unwrap_err();
    assert!(matches!(
        err,
        ClientError::PayAmount {
            agreed: 10,
            requested: 500
        }
    ));
    assert!(err.to_string().contains("500"));
    assert!(err.to_string().contains("--amount states 10"));
    assert!(!offer.exists());
    let wallet = alice.wallet();
    assert!(wallet.pending().is_none());
    assert_eq!(wallet.balance(), 500);
    drop(wallet);

    let line = alice.session.pay(&request, &offer, 500).unwrap();
    assert!(line.starts_with("offer of 500 to "));
    assert!(offer.exists());
    assert!(matches!(
        alice.wallet().pending(),
        Some(Pending::Pay { v: 500, .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn reseal_keeps_the_pending_amount_and_refuses_a_request_for_another_one() {
    let h = Harness::new().await;
    let mut bob = h.wallet("bob");
    h.enroll(&mut bob).await;
    let alice = funded_payer(&h, "alice", 500).await;
    let first = request_file(&h, &mut bob, Some(120), "request-1.json").await;
    let offer = h.dir().join("offer.json");
    alice.session.pay(&first, &offer, 120).unwrap();

    let fresh = request_file(&h, &mut bob, None, "request-2.json").await;
    let inflated = with_amount(&fresh, 480);
    let resealed = h.dir().join("offer-2.json");
    assert!(matches!(
        alice.session.reseal(&inflated, &resealed).unwrap_err(),
        ClientError::PayRequestMismatch
    ));
    assert!(!resealed.exists());

    let line = alice.session.reseal(&fresh, &resealed).unwrap();
    assert!(line.starts_with("offer of 120 to "));
    assert!(matches!(
        alice.wallet().pending(),
        Some(Pending::Pay { v: 120, .. })
    ));
    let receipt = h.dir().join("receipt.json");
    let bob_path = bob.path().to_path_buf();
    drop(bob);
    let bob_session = Session::open(&bob_path, h.addr(), &client_trust()).unwrap();
    bob_session.receive(&resealed, &receipt).await.unwrap();
    alice.session.finish(Some(&receipt)).await.unwrap();
    assert_eq!(alice.wallet().balance(), 380);
    assert_eq!(Wallet::load(&bob_path).unwrap().balance(), 120);
}

#[tokio::test(flavor = "multi_thread")]
async fn pay_to_a_request_naming_the_payers_own_serial_is_a_self_payment() {
    let h = Harness::new().await;
    let mut bob = h.wallet("bob");
    h.enroll(&mut bob).await;
    let alice = funded_payer(&h, "alice", 500).await;
    let mut wallet = alice.wallet();
    let mut request = payment::request(&mut bob, &h.client, Some(60))
        .await
        .unwrap();
    request.pk_b = wallet.current_pk().unwrap();
    let err = payment::pay(&mut wallet, h.client.verifier(), &request).unwrap_err();
    assert!(matches!(err, ClientError::SelfPayment), "{err}");
    assert!(!err.to_string().contains("pending"), "{err}");
    assert!(wallet.pending().is_none());
    assert_eq!(wallet.balance(), 500);
}
