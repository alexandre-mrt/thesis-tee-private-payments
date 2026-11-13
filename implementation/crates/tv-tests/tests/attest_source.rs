use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use ciborium::Value;
use pt_tee::attestation::MockProvider;
use pt_tee::framing::{decode_cbor, read_frame_bounded, write_cbor};
use pt_tee::transport::{Endpoint, Listener};
use tokio::sync::watch;
use tv_bank::{Bank, MAX_PENDING_KEYS_PER_SOURCE, ServerConfig, TcpLink, bind, serve};
use tv_client::BankClient;
use tv_core::{BankRequest, BankResponse, EnclaveRequest};
use tv_enclave::Enclave;
use tv_tests::{RESERVE, client_trust, mock_trust};

const MAX_FRAME: usize = 64 * 1024;
const FLOODER: &str = "198.51.100.7";

type Frames = Arc<Mutex<Vec<Vec<u8>>>>;

async fn recording_enclave(enclave: Arc<Enclave>) -> (Endpoint, Frames) {
    let listener = Listener::bind(&Endpoint::tcp("127.0.0.1:0").unwrap())
        .await
        .unwrap();
    let endpoint = listener.local_endpoint().unwrap();
    let frames: Frames = Arc::default();
    let recorded = Arc::clone(&frames);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let frame = read_frame_bounded(&mut stream, MAX_FRAME).await.unwrap();
            let request: EnclaveRequest = decode_cbor(&frame).unwrap();
            recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(frame);
            write_cbor(&mut stream, &enclave.handle(&request))
                .await
                .unwrap();
        }
    });
    (endpoint, frames)
}

fn attest_fields(frame: &[u8]) -> Option<Vec<String>> {
    let Value::Map(outer) = decode_cbor::<Value>(frame).unwrap() else {
        return None;
    };
    let [(Value::Text(tag), Value::Map(fields))] = outer.as_slice() else {
        return None;
    };
    (tag == "Attest").then(|| {
        fields
            .iter()
            .map(|(key, _)| key.as_text().unwrap().to_owned())
            .collect()
    })
}

fn cancels(frames: &Frames) -> usize {
    frames
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|frame| matches!(decode_cbor(frame), Ok(EnclaveRequest::Cancel { .. })))
        .count()
}

async fn bank_over_tcp_link() -> (PathBuf, Arc<Bank<TcpLink>>, Arc<Enclave>, Frames) {
    let dir = std::env::temp_dir().join(format!(
        "tv-tests-attest-source-{}-{}",
        std::process::id(),
        hex::encode(tv_core::random_bytes32())
    ));
    let keys = tv_bank::init(&dir, RESERVE).unwrap();
    let enclave = Arc::new(Enclave::boot(keys, Box::new(MockProvider::new())).unwrap());
    let (endpoint, frames) = recording_enclave(Arc::clone(&enclave)).await;
    let bank = Arc::new(Bank::open(&dir, TcpLink::new(endpoint)).unwrap());
    (dir, bank, enclave, frames)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_attest_sent_to_the_enclave_carries_no_source_and_the_bank_holds_the_cap() {
    let (dir, bank, enclave, frames) = bank_over_tcp_link().await;
    let listener = bind(&Endpoint::tcp("127.0.0.1:0").unwrap()).await.unwrap();
    let addr = listener.local_endpoint().unwrap();
    let (_stop, rx) = watch::channel(false);
    let config = ServerConfig {
        after_append: None,
        enclave: None,
        trust: mock_trust(),
    };
    tokio::spawn(serve(listener, Arc::clone(&bank), config, rx));
    let client = BankClient::new(addr, &client_trust()).unwrap();
    client.attest(&[4u8; 32]).await.unwrap();

    let recorded = frames
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        attest_fields(&recorded[0]),
        Some(vec!["nonce".to_owned(), "owner".to_owned()])
    );
    assert!(!recorded[0].windows(9).any(|w| w == b"127.0.0.1"));
    assert_eq!(bank.pending_attestations_for("127.0.0.1"), 1);

    for i in 0..=MAX_PENDING_KEYS_PER_SOURCE {
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let request = BankRequest::Attest {
            nonce,
            owner: nonce,
        };
        let outcome = bank.handle_from(FLOODER, &request).await;
        assert!(matches!(outcome.response, BankResponse::Attestation { .. }));
    }
    assert_eq!(
        bank.pending_attestations_for(FLOODER),
        MAX_PENDING_KEYS_PER_SOURCE
    );
    assert_eq!(cancels(&frames), 1);
    assert_eq!(enclave.pending_keys(), 1 + MAX_PENDING_KEYS_PER_SOURCE);
    assert_eq!(bank.pending_attestations_for("127.0.0.1"), 1);
    std::fs::remove_dir_all(dir).unwrap();
}
