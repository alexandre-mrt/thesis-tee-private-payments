use tv_core::{
    BankRequest, BankResponse, Bytes32, CheckOp, EnclaveResponse, EnrollRequest, SealedBlob,
    SideKind, SigningKey, commitment, enroll_digest, sign_digest, sign_result,
};

use super::Bank;
use crate::error::{BankError, LinkError};
use crate::init::{ENCLAVE_PK_FILE, init};
use crate::journal::testing::{Fault, faulty, set_fault, temp_dir};
use crate::keys::write_public;
use crate::link::{EnclaveLink, TcpLink};
use crate::registry::EnclaveTrust;
use crate::store::{LOG_FILE, Store};

struct LenientLink(SigningKey);

impl EnclaveLink for LenientLink {
    async fn attest(
        &self,
        _nonce: Bytes32,
        _owner: Option<Bytes32>,
    ) -> Result<EnclaveResponse, LinkError> {
        Ok(EnclaveResponse::Refused)
    }

    async fn cancel(&self, _channel_pk: [u8; 32]) -> Result<EnclaveResponse, LinkError> {
        Ok(EnclaveResponse::Refused)
    }

    async fn check(&self, bank_nonce: Bytes32, op: CheckOp) -> Result<EnclaveResponse, LinkError> {
        let CheckOp::Enroll(request) = op else {
            return Ok(EnclaveResponse::Refused);
        };
        Ok(EnclaveResponse::Result(sign_result(
            &self.0,
            bank_nonce,
            enroll_digest(&request.pk0, &request.com0),
            vec![SideKind::User],
        )))
    }
}

fn enroll_request() -> BankRequest {
    let owner = SigningKey::generate();
    let pk0 = owner.public_key();
    let com0 = commitment(0, &pk0, &[7u8; 32]);
    BankRequest::Enroll(Box::new(EnrollRequest {
        channel_pk: [0u8; 32],
        pk0,
        com0,
        sig: sign_digest(&owner, &enroll_digest(&pk0, &com0)),
        sealed: SealedBlob {
            client_pk: [0u8; 32],
            nonce: [0u8; 12],
            ciphertext: vec![],
        },
    }))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rolled_back_append_answers_unavailable_and_the_retry_settles() {
    let dir = temp_dir("bank-rollback");
    init(&dir, 1).unwrap();
    let result_key = SigningKey::generate();
    write_public(&dir.join(ENCLAVE_PK_FILE), &result_key.public_key()).unwrap();
    let store = faulty(&dir, Fault::WriteThenFail);
    let bank = Bank::from_store(&dir, LenientLink(result_key), store).unwrap();
    let request = enroll_request();

    let outcome = bank.handle(&request).await;
    assert_eq!(outcome.response, BankResponse::Unavailable);
    assert!(!outcome.appended);
    assert!(bank.entries().is_empty());
    let outcome = bank.handle(&request).await;
    assert_eq!(outcome.response, BankResponse::Unavailable);

    set_fault(&bank.store(), Fault::None);
    let outcome = bank.handle(&request).await;
    assert!(matches!(outcome.response, BankResponse::Enrolled { .. }));
    assert!(outcome.appended);
    assert_eq!(bank.entries().len(), 1);
    let again = bank.handle(&request).await;
    assert_eq!(again.response, outcome.response);
    assert!(!again.appended);
    drop(bank);
    assert_eq!(Store::open(&dir).unwrap().entries().len(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_lost_log_on_an_initialised_dir_is_refused_not_recreated_empty() {
    let dir = temp_dir("bank-lost-log");
    init(&dir, 1).unwrap();
    let mut store = Store::open(&dir).unwrap();
    store
        .append(crate::journal::testing::entry(
            0,
            tv_core::OpKind::Enroll,
            1,
        ))
        .unwrap();
    drop(store);
    std::fs::remove_file(dir.join(LOG_FILE)).unwrap();
    let refused = Bank::open(&dir, LenientLink(SigningKey::generate()));
    assert!(matches!(
        refused,
        Err(BankError::DataDirIncomplete {
            missing: LOG_FILE,
            ..
        })
    ));
    assert!(!dir.join(LOG_FILE).exists());
    assert!(matches!(Store::open(&dir), Err(BankError::File { .. })));
    assert!(!dir.join(LOG_FILE).exists());
    std::fs::remove_dir_all(dir).unwrap();
}

const STALL_BOUND: std::time::Duration = std::time::Duration::from_millis(300);

async fn stalled_enclave() -> pt_tee::transport::Endpoint {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    pt_tee::transport::Endpoint::tcp(&addr).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_enclave_answers_unavailable_within_the_call_bound() {
    let dir = temp_dir("bank-stalled");
    init(&dir, 1).unwrap();
    write_public(
        &dir.join(ENCLAVE_PK_FILE),
        &SigningKey::generate().public_key(),
    )
    .unwrap();
    let endpoint = stalled_enclave().await;
    let link = TcpLink::new(endpoint.clone()).with_call_timeout(STALL_BOUND);
    let bank = Bank::open(&dir, link).unwrap();
    let bound = STALL_BOUND * 10;

    let attest = BankRequest::Attest {
        nonce: [1u8; 32],
        owner: [2u8; 32],
    };
    let started = std::time::Instant::now();
    let outcome = bank.handle(&attest).await;
    assert_eq!(outcome.response, BankResponse::Unavailable);
    let outcome = bank.handle(&enroll_request()).await;
    assert_eq!(outcome.response, BankResponse::Unavailable);
    assert!(!outcome.appended);
    let trust = EnclaveTrust {
        pcr0_hex: None,
        allow_mock: true,
    };
    let registered = bank.register(&trust, Some(&endpoint)).await;
    assert!(
        matches!(registered, Err(BankError::Link(LinkError::TimedOut { .. }))),
        "{registered:?}"
    );
    assert!(started.elapsed() < bound, "{:?}", started.elapsed());
    assert!(bank.entries().is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}
