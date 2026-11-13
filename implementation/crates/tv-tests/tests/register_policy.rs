use pt_tee::transport::Endpoint;
use tv_bank::EnclaveTrust;
use tv_client::BankClient;
use tv_core::{BankRequest, BankResponse};
use tv_tests::{Harness, client_trust};

#[tokio::test(flavor = "multi_thread")]
async fn the_trust_policy_comes_from_the_bank_not_from_the_request() {
    let h = Harness::new().await;
    let expected = h.result_key.public_key();
    assert_eq!(h.link.enclave().pending_keys(), 0);

    assert_eq!(
        h.client.call(&BankRequest::RegisterEnclave).await.unwrap(),
        BankResponse::Registered {
            result_pk: expected
        }
    );
    assert_eq!(h.link.enclave().pending_keys(), 0);

    let (strict_addr, shutdown) = h.serve_with_trust(EnclaveTrust::default()).await;
    let strict = BankClient::new(Endpoint::tcp(&strict_addr).unwrap(), &client_trust()).unwrap();
    assert_eq!(
        strict.call(&BankRequest::RegisterEnclave).await.unwrap(),
        BankResponse::Refused
    );
    assert_eq!(h.bank().registered_result_pk(), Some(expected));
    let _ = shutdown.send(true);

    let (pinned_addr, shutdown) = h
        .serve_with_trust(EnclaveTrust {
            pcr0_hex: Some("ab".repeat(48)),
            allow_mock: false,
        })
        .await;
    let pinned = BankClient::new(Endpoint::tcp(&pinned_addr).unwrap(), &client_trust()).unwrap();
    assert_eq!(
        pinned.call(&BankRequest::RegisterEnclave).await.unwrap(),
        BankResponse::Refused
    );
    let _ = shutdown.send(true);
    assert_eq!(h.bank().registered_result_pk(), Some(expected));
    assert_eq!(h.link.enclave().pending_keys(), 0);
}
