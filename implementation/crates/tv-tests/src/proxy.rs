use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use pt_tee::framing::{decode_cbor, read_frame_bounded, write_frame};
use pt_tee::transport::{Endpoint, Listener, Stream, connect};
use tokio::task::JoinHandle;
use tv_client::BankClient;
use tv_core::BankRequest;

use crate::client_trust;

const MAX_FRAME: usize = 4 * 1024 * 1024;

pub fn request_kind(request: &BankRequest) -> &'static str {
    match request {
        BankRequest::Attest { .. } => "Attest",
        BankRequest::Receive(_) => "Receive",
        BankRequest::Enroll(_) => "Enroll",
        BankRequest::Refresh(_) => "Refresh",
        BankRequest::Lookup { .. } => "Lookup",
        BankRequest::LogRange { .. } => "LogRange",
        BankRequest::RegisterEnclave => "RegisterEnclave",
    }
}

pub struct RecordingProxy {
    addr: String,
    seen: Arc<Mutex<Vec<BankRequest>>>,
    drop_reply: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

async fn relay(
    mut downstream: Stream,
    upstream: &Endpoint,
    seen: &Mutex<Vec<BankRequest>>,
    drop_reply: &AtomicBool,
) {
    let Ok(frame) = read_frame_bounded(&mut downstream, MAX_FRAME).await else {
        return;
    };
    if let Ok(request) = decode_cbor::<BankRequest>(&frame) {
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
    }
    let Ok(mut bank) = connect(upstream).await else {
        return;
    };
    if write_frame(&mut bank, &frame).await.is_err() {
        return;
    }
    if let Ok(reply) = read_frame_bounded(&mut bank, MAX_FRAME).await
        && !drop_reply.swap(false, Ordering::SeqCst)
    {
        let _ = write_frame(&mut downstream, &reply).await;
    }
}

impl RecordingProxy {
    pub async fn start(bank_addr: &str) -> Self {
        let upstream = Endpoint::tcp(bank_addr).expect("bank endpoint");
        let listener = Listener::bind(&Endpoint::tcp("127.0.0.1:0").expect("endpoint"))
            .await
            .expect("bind proxy");
        let addr = match listener.local_endpoint().expect("local endpoint") {
            Endpoint::Tcp(addr) => addr,
            Endpoint::Vsock { .. } => unreachable!("tcp listener"),
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let drop_reply = Arc::new(AtomicBool::new(false));
        let recorded = Arc::clone(&seen);
        let dropping = Arc::clone(&drop_reply);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let upstream = upstream.clone();
                let seen = Arc::clone(&recorded);
                let dropping = Arc::clone(&dropping);
                tokio::spawn(async move { relay(stream, &upstream, &seen, &dropping).await });
            }
        });
        Self {
            addr,
            seen,
            drop_reply,
            task,
        }
    }

    pub fn drop_next_reply(&self) {
        self.drop_reply.store(true, Ordering::SeqCst);
    }

    pub fn client(&self) -> BankClient {
        BankClient::new(
            Endpoint::tcp(&self.addr).expect("endpoint"),
            &client_trust(),
        )
        .expect("client")
    }

    pub fn recorded(&self) -> Vec<BankRequest> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn requests(&self) -> Vec<&'static str> {
        self.recorded().iter().map(request_kind).collect()
    }

    pub fn count(&self, kind: &str) -> usize {
        self.requests().iter().filter(|k| **k == kind).count()
    }
}

impl Drop for RecordingProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
