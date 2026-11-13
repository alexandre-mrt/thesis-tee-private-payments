use std::time::{Duration, Instant};

use tv_bank::MAX_PENDING_KEYS_PER_SOURCE;
use tv_client::Wallet;
use tv_core::{
    BankVerifiers, CheckOp, EnclaveResponse, Receive, SigningKey, commitment, random_bytes32,
    sign_state,
};
use tv_enclave::{Refusal, check_pay};
use tv_tests::{Forge, Harness};

const ROUNDS: usize = 6;
const SAMPLES_PER_ROUND: usize = MAX_PENDING_KEYS_PER_SOURCE / CLASSES.len();
const MAX_MEDIAN_SPREAD: f64 = 1.08;

#[derive(Debug, Clone, Copy)]
enum Class {
    Honest,
    AmountMismatch,
    BadStateSignature,
    BalancePlusOne,
    ZeroAmount,
    OverBalance,
    WrongNextCommitment,
    SharedNextSerial,
    ForeignOwnerSignature,
    SameSerial,
}

const CLASSES: [Class; 10] = [
    Class::Honest,
    Class::AmountMismatch,
    Class::BadStateSignature,
    Class::BalancePlusOne,
    Class::ZeroAmount,
    Class::OverBalance,
    Class::WrongNextCommitment,
    Class::SharedNextSerial,
    Class::ForeignOwnerSignature,
    Class::SameSerial,
];

fn first_refusal(class: Class) -> Option<Refusal> {
    match class {
        Class::Honest => None,
        Class::AmountMismatch => Some(Refusal::Amount),
        Class::BadStateSignature | Class::BalancePlusOne => Some(Refusal::Opening),
        Class::ZeroAmount | Class::OverBalance => Some(Refusal::Bounds),
        Class::WrongNextCommitment => Some(Refusal::NextCommitment),
        Class::SharedNextSerial => Some(Refusal::NextSerial),
        Class::ForeignOwnerSignature => Some(Refusal::OwnerSignature),
        Class::SameSerial => Some(Refusal::SameSerial),
    }
}

fn forge_for(h: &Harness, alice: &Wallet, bob: &Wallet, class: Class) -> Forge {
    let mut forge = h.forge(alice, bob, 10);
    match class {
        Class::Honest => {}
        Class::AmountMismatch => forge.payee_secret.v = 11,
        Class::BadStateSignature => {
            let opening = &mut forge.payer_secret.opening;
            let com = commitment(opening.balance, &forge.pk_a, &opening.r);
            opening.sig = sign_state(&SigningKey::generate(), &com);
        }
        Class::BalancePlusOne => {
            forge.payer_secret.opening.balance += 1;
            forge.a_next += 1;
        }
        Class::ZeroAmount => forge = h.forge(alice, bob, 0),
        Class::OverBalance => forge = h.forge(alice, bob, alice.balance() + 1),
        Class::WrongNextCommitment => forge.a_next += 1,
        Class::SharedNextSerial => {
            forge.payer_secret.opening.next_pk = forge.payee_secret.opening.next_pk;
        }
        Class::ForeignOwnerSignature => forge.payer_signer = SigningKey::generate(),
        Class::SameSerial => forge.pk_b = forge.pk_a,
    }
    forge
}

async fn build_round(h: &Harness, alice: &Wallet, bob: &Wallet) -> Vec<Vec<Receive>> {
    let mut round = Vec::new();
    for _ in 0..SAMPLES_PER_ROUND {
        let mut sample = Vec::new();
        for class in CLASSES {
            sample.push(h.forge_receive(&forge_for(h, alice, bob, class)).await);
        }
        round.push(sample);
    }
    round
}

fn time_check(h: &Harness, class: Class, receive: Receive) -> Duration {
    let enclave = h.link.enclave();
    let op = CheckOp::Pay(Box::new(receive));
    let nonce = random_bytes32();
    let started = Instant::now();
    let response = enclave.check(nonce, &op);
    let elapsed = started.elapsed();
    match class {
        Class::Honest => assert!(matches!(response, EnclaveResponse::Result(_)), "{class:?}"),
        _ => assert_eq!(response, EnclaveResponse::Refused, "{class:?}"),
    }
    elapsed
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

#[tokio::test(flavor = "multi_thread")]
async fn each_forged_class_fails_on_its_own_refusal_and_together_they_cover_every_pay_refusal() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let bank = BankVerifiers::parse(&h.keys).unwrap();
    let mut covered = Vec::new();
    for class in CLASSES {
        let forge = forge_for(&h, &alice, &bob, class);
        let receive = h.forge_receive(&forge).await;
        let outcome = check_pay(
            &bank,
            &receive.public,
            &forge.payer_secret,
            &forge.payee_secret,
        );
        assert_eq!(outcome.err(), first_refusal(class), "{class:?}");
        covered.extend(first_refusal(class));
    }
    covered.sort_by_key(|refusal| format!("{refusal:?}"));
    covered.dedup();
    assert_eq!(
        covered,
        [
            Refusal::Amount,
            Refusal::Bounds,
            Refusal::NextCommitment,
            Refusal::NextSerial,
            Refusal::Opening,
            Refusal::OwnerSignature,
            Refusal::SameSerial,
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_refusal_class_costs_the_enclave_the_same_time_as_a_settlement() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let mut timings: Vec<Vec<Duration>> = CLASSES.iter().map(|_| Vec::new()).collect();
    for _ in 0..ROUNDS {
        for sample in build_round(&h, &alice, &bob).await {
            for (i, (class, receive)) in CLASSES.into_iter().zip(sample).enumerate() {
                timings[i].push(time_check(&h, class, receive));
            }
        }
    }
    let medians: Vec<(Class, Duration)> = CLASSES
        .into_iter()
        .zip(timings.iter_mut())
        .map(|(class, samples)| (class, median(samples)))
        .collect();
    let slowest = medians.iter().map(|(_, d)| *d).max().unwrap();
    let fastest = medians.iter().map(|(_, d)| *d).min().unwrap();
    let spread = slowest.as_secs_f64() / fastest.as_secs_f64();
    println!("enclave check medians: {medians:?}, spread {spread:.3}");
    assert!(
        spread <= MAX_MEDIAN_SPREAD,
        "refusal classes are distinguishable by time, spread {spread:.2}: {medians:?}"
    );
}
