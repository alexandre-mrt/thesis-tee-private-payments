#![forbid(unsafe_code)]

pub mod link;
pub mod proxy;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use pt_tee::attestation::MockProvider;
use pt_tee::transport::Endpoint;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tv_bank::{Bank, EnclaveTrust, Policy, ServerConfig, bank_wallet_path, bind, serve};
use tv_client::{BankClient, ClientError, OfferFile, Trust, Wallet, flows, payment, seal_to};
use tv_core::{
    BankKeys, BankRequest, BankResponse, Bytes32, EnrollRequest, EnrollSecret, PayPublic,
    PaySecret, Receive, Seed, SigningKey, commitment, enroll_digest, pay_digest, sign_digest,
};
use tv_enclave::Enclave;

pub use link::{Mode, TestLink};
pub use proxy::{RecordingProxy, request_kind};

pub const RESERVE: u64 = 1_000_000_000;

pub struct Forge {
    pub a_next: u64,
    pub b_next: u64,
    pub payer_secret: PaySecret,
    pub payee_secret: PaySecret,
    pub payer_signer: SigningKey,
    pub payee_signer: SigningKey,
    pub pk_a: Bytes32,
    pub pk_b: Bytes32,
}

pub struct Harness {
    dir: PathBuf,
    pub keys: BankKeys,
    pub link: TestLink,
    bank: Option<Arc<Bank<TestLink>>>,
    pub client: BankClient,
    pub result_key: SigningKey,
    addr: String,
    server: Option<(watch::Sender<bool>, JoinHandle<()>)>,
}

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tv-tests-{}-{nanos}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

async fn spawn_server(
    bank: Arc<Bank<TestLink>>,
    addr: &str,
) -> (String, watch::Sender<bool>, JoinHandle<()>) {
    let listener = bind(&Endpoint::tcp(addr).expect("endpoint"))
        .await
        .expect("bind");
    let local = match listener.local_endpoint().expect("local endpoint") {
        Endpoint::Tcp(addr) => addr,
        Endpoint::Vsock { .. } => unreachable!("tcp listener"),
    };
    let (tx, rx) = watch::channel(false);
    let config = ServerConfig {
        after_append: None,
        enclave: None,
        trust: mock_trust(),
    };
    let task = tokio::spawn(async move {
        serve(listener, bank, config, rx).await.expect("serve");
    });
    (local, tx, task)
}

impl Harness {
    pub async fn new() -> Self {
        let dir = temp_dir();
        let keys = tv_bank::init(&dir, RESERVE).expect("init");
        let result_key = SigningKey::generate();
        let enclave =
            Enclave::boot_with_result_key(keys, Box::new(MockProvider::new()), result_key.clone())
                .expect("boot enclave");
        let link = TestLink::new(enclave);
        let bank = Arc::new(
            Bank::open(&dir, link.clone())
                .expect("open bank")
                .with_policy(mock_policy()),
        );
        bank.register(&mock_trust(), None).await.expect("register");
        let (addr, tx, task) = spawn_server(Arc::clone(&bank), "127.0.0.1:0").await;
        let client = BankClient::new(Endpoint::tcp(&addr).expect("endpoint"), &client_trust())
            .expect("client");
        Self {
            dir,
            keys,
            link,
            bank: Some(bank),
            client,
            result_key,
            addr,
            server: Some((tx, task)),
        }
    }

    pub fn bank(&self) -> &Bank<TestLink> {
        self.bank.as_ref().expect("bank open")
    }

    pub fn bank_arc(&self) -> Arc<Bank<TestLink>> {
        Arc::clone(self.bank.as_ref().expect("bank open"))
    }

    pub async fn serve_with_trust(&self, trust: EnclaveTrust) -> (String, watch::Sender<bool>) {
        let listener = bind(&Endpoint::tcp("127.0.0.1:0").expect("endpoint"))
            .await
            .expect("bind");
        let addr = match listener.local_endpoint().expect("local endpoint") {
            Endpoint::Tcp(addr) => addr,
            Endpoint::Vsock { .. } => unreachable!("tcp listener"),
        };
        let (tx, rx) = watch::channel(false);
        let config = ServerConfig {
            after_append: None,
            enclave: None,
            trust,
        };
        let bank = self.bank_arc();
        tokio::spawn(async move {
            serve(listener, bank, config, rx).await.expect("serve");
        });
        (addr, tx)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn wallet(&self, name: &str) -> Wallet {
        Wallet::create(
            &self.dir.join(format!("{name}.json")),
            Seed::generate(),
            self.keys,
        )
        .expect("wallet")
    }

    pub fn wallet_from_seed(&self, name: &str, seed: Seed) -> Wallet {
        Wallet::create(&self.dir.join(format!("{name}.json")), seed, self.keys).expect("wallet")
    }

    pub fn bank_wallet(&self) -> Wallet {
        Wallet::load(&bank_wallet_path(&self.dir)).expect("bank wallet")
    }

    pub async fn restart_enclave(&self) {
        self.restart_enclave_unregistered();
        self.bank()
            .register(&mock_trust(), None)
            .await
            .expect("re-register");
    }

    pub fn restart_enclave_unregistered(&self) -> Bytes32 {
        self.replace_enclave(
            Enclave::boot(self.keys, Box::new(MockProvider::new())).expect("boot enclave"),
        )
    }

    pub fn replace_enclave(&self, enclave: Enclave) -> Bytes32 {
        let result_pk = enclave.result_pk();
        self.link.replace(enclave);
        result_pk
    }

    pub async fn restart_bank(&mut self) {
        let (tx, task) = self.server.take().expect("server running");
        let _ = tx.send(true);
        task.await.expect("server task");
        drop(self.bank.take());
        let bank = Arc::new(
            Bank::open(&self.dir, self.link.clone())
                .expect("reopen")
                .with_policy(mock_policy()),
        );
        let (addr, tx, task) = spawn_server(Arc::clone(&bank), &self.addr).await;
        self.bank = Some(bank);
        assert_eq!(addr, self.addr);
        self.server = Some((tx, task));
    }

    pub async fn enroll(&self, wallet: &mut Wallet) {
        flows::enroll_and_refresh(wallet, &self.client)
            .await
            .expect("enroll and refresh off pk_0");
    }

    pub async fn transfer(
        &self,
        payer: &mut Wallet,
        payee: &mut Wallet,
        v: u64,
    ) -> Result<(), ClientError> {
        let request = payment::request(payee, &self.client, Some(v)).await?;
        let offer = payment::pay(payer, self.client.verifier(), &request)?;
        let receipt = payment::receive(payee, &self.client, &offer).await?;
        flows::finish(payer, &self.client, Some(&receipt)).await
    }

    pub async fn issue(&self, wallet: &mut Wallet, v: u64) -> Result<(), ClientError> {
        let mut bank_wallet = self.bank_wallet();
        self.transfer(&mut bank_wallet, wallet, v).await
    }

    pub fn build_receive(&self, payee: &Wallet, offer: &OfferFile) -> Receive {
        let (v, com_next, channel_pk) = match payee.pending() {
            Some(tv_client::Pending::Request {
                v,
                com_next,
                channel_pk,
                ..
            }) => (*v, *com_next, *channel_pk),
            other => panic!("payee has no pending request: {other:?}"),
        };
        let key = payee.current_key().expect("key");
        let pk_b = key.public_key();
        let digest = pay_digest(&offer.pk_a, &offer.com_a_next, &pk_b, &com_next);
        let payee_blob = seal_to(
            &channel_pk,
            &PaySecret {
                v,
                opening: payee.opening().expect("opening"),
            },
        )
        .expect("seal");
        Receive {
            channel_pk,
            public: PayPublic {
                pk_a: offer.pk_a,
                com_a_next: offer.com_a_next,
                sig_a: offer.sig_a,
                pk_b,
                com_b_next: com_next,
                sig_b: sign_digest(&key, &digest),
            },
            payer: offer.payer.clone(),
            payee: payee_blob,
        }
    }

    pub fn forge(&self, payer: &Wallet, payee: &Wallet, v: u64) -> Forge {
        Forge {
            a_next: payer.balance().wrapping_sub(v),
            b_next: payee.balance().wrapping_add(v),
            payer_secret: PaySecret {
                v,
                opening: payer.opening().expect("payer opening"),
            },
            payee_secret: PaySecret {
                v,
                opening: payee.opening().expect("payee opening"),
            },
            payer_signer: payer.current_key().expect("payer key"),
            payee_signer: payee.current_key().expect("payee key"),
            pk_a: payer.current_pk().expect("payer pk"),
            pk_b: payee.current_pk().expect("payee pk"),
        }
    }

    pub async fn forge_receive(&self, forge: &Forge) -> Receive {
        let channel_pk = self
            .client
            .attest(&forge.pk_b)
            .await
            .expect("attest")
            .channel_pk;
        let a = &forge.payer_secret.opening;
        let b = &forge.payee_secret.opening;
        let com_a_next = commitment(forge.a_next, &a.next_pk, &a.next_r);
        let com_b_next = commitment(forge.b_next, &b.next_pk, &b.next_r);
        let digest = pay_digest(&forge.pk_a, &com_a_next, &forge.pk_b, &com_b_next);
        Receive {
            channel_pk,
            public: PayPublic {
                pk_a: forge.pk_a,
                com_a_next,
                sig_a: sign_digest(&forge.payer_signer, &digest),
                pk_b: forge.pk_b,
                com_b_next,
                sig_b: sign_digest(&forge.payee_signer, &digest),
            },
            payer: seal_to(&channel_pk, &forge.payer_secret).expect("seal"),
            payee: seal_to(&channel_pk, &forge.payee_secret).expect("seal"),
        }
    }

    pub async fn submit(&self, receive: Receive) -> BankResponse {
        self.client
            .call(&BankRequest::Receive(Box::new(receive)))
            .await
            .expect("bank call")
    }

    pub fn total_supply(&self, wallets: &[&Wallet]) -> u64 {
        wallets.iter().map(|w| w.balance()).sum::<u64>() + self.bank_wallet().balance()
    }

    pub fn spent_serials(&self) -> Vec<Bytes32> {
        self.bank()
            .entries()
            .iter()
            .filter(|e| e.kind != tv_core::OpKind::Enroll)
            .flat_map(|e| e.serials.clone())
            .collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some((tx, _)) = self.server.take() {
            let _ = tx.send(true);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn mock_trust() -> EnclaveTrust {
    EnclaveTrust {
        pcr0_hex: None,
        allow_mock: true,
    }
}

pub fn mock_policy() -> Policy {
    Policy {
        trust: mock_trust(),
        enclave: None,
    }
}

pub fn client_trust() -> Trust {
    Trust {
        pcr0_hex: None,
        allow_mock: true,
    }
}

pub fn enroll_request(
    key: &SigningKey,
    channel_pk: [u8; 32],
    r0: Bytes32,
    com0: Bytes32,
) -> EnrollRequest {
    let pk0 = key.public_key();
    EnrollRequest {
        channel_pk,
        pk0,
        com0,
        sig: sign_digest(key, &enroll_digest(&pk0, &com0)),
        sealed: seal_to(&channel_pk, &EnrollSecret { r0 }).expect("seal"),
    }
}

pub fn flip(bytes: &Bytes32) -> Bytes32 {
    let mut out = *bytes;
    out[0] ^= 0x01;
    out
}
