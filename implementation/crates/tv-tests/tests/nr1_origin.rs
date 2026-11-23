use tv_client::{Wallet, flows, payment};
use tv_core::{BankResponse, PayPublic, Receive, sign_digest};
use tv_tests::{Harness, Mode, flip};

async fn funded(h: &Harness) -> (Wallet, Wallet) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    (alice, bob)
}

fn tampered(receive: &Receive, field: usize, bob: &Wallet) -> Receive {
    let p = receive.public;
    let changed = match field {
        0 => PayPublic {
            c_v: flip(&p.c_v),
            ..p
        },
        1 => PayPublic {
            h_ctx: flip(&p.h_ctx),
            ..p
        },
        _ => PayPublic {
            com_b_next: flip(&p.com_b_next),
            ..p
        },
    };
    let sig_b = sign_digest(&bob.current_key().unwrap(), &changed.digest());
    Receive {
        public: PayPublic { sig_b, ..changed },
        ..receive.clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nr1_a_payee_cannot_change_amount_context_or_its_state_under_the_payer_signature() {
    let h = Harness::new().await;
    let (mut alice, mut bob) = funded(&h).await;
    h.link.set_mode(Mode::Lenient(h.result_key.clone()));
    let request = payment::request_with_memo(&mut bob, &h.client, Some(100), Some("order 1"))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let honest = h.build_receive(&bob, &offer);
    let entries = h.bank().entries().len();
    for field in 0..3 {
        let response = h.submit(tampered(&honest, field, &bob)).await;
        assert_eq!(response, BankResponse::Refused, "field {field}");
    }
    assert_eq!(h.bank().entries().len(), entries);
    h.link.set_mode(Mode::Normal);
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!((alice.balance(), bob.balance()), (400, 100));
}
