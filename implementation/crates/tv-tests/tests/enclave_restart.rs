use pt_tee::attestation::MockProvider;
use pt_tee::transport::Endpoint;
use tv_client::{BankClient, ClientError, flows, payment};
use tv_core::{BankKeys, BankRequest, BankResponse, SigningKey};
use tv_enclave::Enclave;
use tv_tests::{Harness, Mode, RESERVE, client_trust};

#[tokio::test(flavor = "multi_thread")]
async fn after_an_enclave_restart_the_bank_re_attests_under_its_policy_and_settles() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let stale = h.bank().registered_result_pk().unwrap();

    let fresh = h.restart_enclave_unregistered();
    assert_ne!(fresh, stale);
    assert_eq!(h.bank().registered_result_pk(), Some(stale));

    flows::refresh(&mut bob, &h.client, false).await.unwrap();
    assert_eq!(h.bank().registered_result_pk(), Some(fresh));
    assert_eq!(
        tv_bank::read_keys(h.dir()).map(|_| ()).unwrap(),
        (),
        "data dir still readable"
    );

    h.transfer(&mut alice, &mut bob, 120).await.unwrap();
    assert_eq!(alice.balance(), 380);
    assert_eq!(bob.balance(), 120);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_operations_after_an_enclave_restart_share_one_re_attestation_and_all_settle() {
    const USERS: usize = 16;
    let h = Harness::new().await;
    let mut wallets = Vec::with_capacity(USERS);
    for n in 0..USERS {
        let mut wallet = h.wallet(&format!("user-{n}"));
        h.enroll(&mut wallet).await;
        wallets.push(wallet);
    }
    let entries = h.bank().entries().len();
    let fresh = h.restart_enclave_unregistered();

    let mut tasks = tokio::task::JoinSet::new();
    for mut wallet in wallets {
        let client = BankClient::new(Endpoint::tcp(h.addr()).unwrap(), &client_trust()).unwrap();
        tasks.spawn(async move {
            let refreshed = flows::refresh(&mut wallet, &client, false).await;
            (wallet, refreshed)
        });
    }
    let mut settled = 0;
    while let Some(joined) = tasks.join_next().await {
        let (wallet, refreshed) = joined.unwrap();
        refreshed.unwrap();
        assert!(wallet.pending().is_none());
        settled += 1;
    }
    assert_eq!(settled, USERS);
    assert_eq!(h.bank().registered_result_pk(), Some(fresh));
    assert_eq!(h.bank().entries().len(), entries + USERS);
    let leftovers = std::fs::read_dir(h.dir())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("tmp")
        })
        .count();
    assert_eq!(leftovers, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_request_from_before_the_restart_still_reads_as_an_enclave_restart() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let request = payment::request(&mut bob, &h.client, Some(100))
        .await
        .unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let fresh = h.restart_enclave_unregistered();

    assert!(matches!(
        payment::receive(&mut bob, &h.client, &offer).await,
        Err(ClientError::EnclaveRestarted)
    ));
    let request = payment::request(&mut bob, &h.client, None).await.unwrap();
    let offer = payment::pay(&mut alice, h.client.verifier(), &request).unwrap();
    let receipt = payment::receive(&mut bob, &h.client, &offer).await.unwrap();
    flows::finish(&mut alice, &h.client, Some(&receipt))
        .await
        .unwrap();
    assert_eq!(h.bank().registered_result_pk(), Some(fresh));
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
    assert!(matches!(
        h.client
            .call(&BankRequest::Lookup { serial: [0u8; 32] })
            .await,
        Ok(tv_core::BankResponse::Entry(None))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_result_under_an_unknown_key_is_refused_and_re_attestation_keeps_the_registered_key() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let stale = h.bank().registered_result_pk().unwrap();
    let entries = h.bank().entries().len();

    h.link.set_mode(Mode::Lenient(SigningKey::generate()));
    let honest = h.forge(&alice, &bob, 100);
    assert_eq!(
        h.submit(h.forge_receive(&honest).await).await,
        BankResponse::Refused
    );
    assert_eq!(h.bank().registered_result_pk(), Some(stale));
    assert_eq!(h.bank().entries().len(), entries);

    h.link.set_mode(Mode::Normal);
    h.transfer(&mut alice, &mut bob, 100).await.unwrap();
    assert_eq!(bob.balance(), 100);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replaced_enclave_enforcing_other_bank_keys_is_not_re_registered() {
    let h = Harness::new().await;
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    let stale = h.bank().registered_result_pk().unwrap();
    let entries = h.bank().entries().len();

    let foreign = BankKeys {
        state_pk: SigningKey::generate().public_key(),
        issuance_pk: SigningKey::generate().public_key(),
    };
    let impostor_key = SigningKey::generate();
    let impostor =
        Enclave::boot_with_result_key(foreign, Box::new(MockProvider::new()), impostor_key.clone())
            .unwrap();
    let honest = h.forge(&alice, &bob, 100);
    let receive = h.forge_receive(&honest).await;
    h.replace_enclave(impostor);
    h.link.set_mode(Mode::Lenient(impostor_key));
    assert_eq!(h.submit(receive).await, BankResponse::Refused);
    assert_eq!(h.bank().registered_result_pk(), Some(stale));
    assert_eq!(h.bank().entries().len(), entries);

    h.link.set_mode(Mode::Normal);
    let fresh = h.restart_enclave_unregistered();
    h.transfer(&mut alice, &mut bob, 100).await.unwrap();
    assert_eq!(h.bank().registered_result_pk(), Some(fresh));
    assert_eq!(bob.balance(), 100);
    assert_eq!(h.total_supply(&[&alice, &bob]), RESERVE);
}
