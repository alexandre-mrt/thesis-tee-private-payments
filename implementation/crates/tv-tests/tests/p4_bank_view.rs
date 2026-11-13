use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tv_core::{BankResponse, Bytes32, Opening};
use tv_tests::{Harness, RESERVE};

const ISSUED: u64 = 123_457;
const PAID: u64 = 54_321;

fn renderings(bytes: &Bytes32) -> Vec<String> {
    vec![
        serde_json::to_string(bytes).unwrap(),
        hex::encode(bytes),
        hex::encode_upper(bytes),
    ]
}

fn assert_absent(view: &str, label: &str, needles: &[String]) {
    for needle in needles {
        assert!(
            !view.contains(needle.as_str()),
            "{label} leaked into the bank view as {needle}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bank_view_holds_no_amount_balance_opening_or_next_serial() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, ISSUED).await.unwrap();
    let alice_opening: Opening = alice.opening().unwrap();
    let bob_opening: Opening = bob.opening().unwrap();
    let alice_next_pk = alice.next_pk().unwrap();
    let bob_next_pk = bob.next_pk().unwrap();
    h.transfer(&mut alice, &mut bob, PAID).await.unwrap();
    assert_eq!(alice.balance(), ISSUED - PAID);
    assert_eq!(bob.balance(), PAID);

    let view = String::from_utf8(h.bank().view_bytes().unwrap()).unwrap();
    assert!(!view.contains(&serde_json::to_string(&alice.current_pk().unwrap()).unwrap()));
    for amount in [ISSUED, PAID, ISSUED - PAID, RESERVE - ISSUED] {
        assert_absent(&view, "amount or balance", &[amount.to_string()]);
    }
    assert_absent(&view, "alice r", &renderings(&alice_opening.r));
    assert_absent(&view, "alice next r", &renderings(&alice_opening.next_r));
    assert_absent(&view, "bob r", &renderings(&bob_opening.r));
    assert_absent(&view, "bob next r", &renderings(&bob_opening.next_r));
    assert_absent(&view, "alice next serial", &renderings(&alice_next_pk));
    assert_absent(&view, "bob next serial", &renderings(&bob_next_pk));
    assert_absent(&view, "alice seed", &renderings(&alice.seed().0));
    assert_absent(&view, "bob seed", &renderings(&bob.seed().0));
    assert_absent(
        &view,
        "bank wallet seed",
        &renderings(&h.bank_wallet().seed().0),
    );

    let spent_pk = alice_opening_pk(&alice);
    assert!(view.contains(&serde_json::to_string(&spent_pk).unwrap()));
    assert!(
        view.contains(&serde_json::to_string(&alice.state().unwrap().state.commitment()).unwrap())
    );
}

fn alice_opening_pk(alice: &tv_client::Wallet) -> Bytes32 {
    alice.key_at(alice.index() - 1).unwrap().public_key()
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

const REFUSAL_VARIANTS: [&str; 8] = [
    "Opening",
    "ChannelKey",
    "OwnerSignature",
    "Amount",
    "Bounds",
    "NextCommitment",
    "SameSerial",
    "NextSerial",
];
const REFUSED_CHECKS: usize = 4;

fn capture_logs() -> Capture {
    let capture = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("trace"))
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish(),
    )
    .unwrap();
    capture
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bank_and_enclave_logs_name_no_refusal_reason_and_no_amount() {
    let capture = capture_logs();
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, ISSUED).await.unwrap();
    let mut richer = h.forge(&alice, &bob, PAID);
    richer.payer_secret.opening.balance = ISSUED + 1;
    richer.a_next = ISSUED + 1 - PAID;
    assert_eq!(
        h.submit(h.forge_receive(&richer).await).await,
        BankResponse::Refused
    );
    let too_much = h.forge(&alice, &bob, ISSUED + 1);
    let consumed_key = h.forge_receive(&too_much).await;
    assert_eq!(h.submit(consumed_key.clone()).await, BankResponse::Refused);
    assert_eq!(h.submit(consumed_key).await, BankResponse::Refused);
    let mut other_owner = h.forge_receive(&h.forge(&alice, &bob, PAID)).await;
    other_owner.channel_pk = h
        .client
        .attest(&alice.current_pk().unwrap())
        .await
        .unwrap()
        .channel_pk;
    assert_eq!(h.submit(other_owner).await, BankResponse::Refused);
    let logs = capture.text();
    let refusals: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("check refused"))
        .collect();
    assert_eq!(refusals.len(), REFUSED_CHECKS, "{logs}");
    for line in refusals {
        assert!(line.ends_with("check refused"), "{line}");
    }
    for variant in REFUSAL_VARIANTS {
        assert!(!logs.contains(variant), "{variant} leaked into the logs");
    }
    for amount in [ISSUED, PAID, ISSUED + 1, RESERVE - ISSUED] {
        assert_absent(&logs, "amount or balance", &[amount.to_string()]);
    }
}
