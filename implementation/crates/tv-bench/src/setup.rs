use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, bail};
use pt_tee::attestation::{AttestationVerifier, MockProvider};
use pt_tee::channel::PK_LEN;
use pt_tee::transport::{Endpoint, Listener};
use tokio::sync::watch;
use tv_bank::{Bank, EnclaveLink, EnclaveTrust, LinkError, Policy, ServerConfig, TcpLink};
use tv_client::{AttestationBundle, BankClient, Trust, verify_bundle};
use tv_core::{
    BankKeys, BankRequest, BankResponse, Bytes32, CheckOp, EnclaveResponse, random_bytes32,
};
use tv_enclave::Enclave;

const ANY_LOOPBACK: &str = "127.0.0.1:0";

pub struct BankDir {
    pub dir: PathBuf,
    pub keys: BankKeys,
}

pub fn bank_dir(root: &Path, name: &str) -> Result<BankDir> {
    let dir = root.join(name);
    let keys = tv_bank::init(&dir, tv_bank::DEFAULT_RESERVE)?;
    Ok(BankDir { dir, keys })
}

pub fn mock_trust() -> EnclaveTrust {
    EnclaveTrust {
        pcr0_hex: None,
        allow_mock: true,
    }
}

pub fn client_trust() -> Trust {
    Trust {
        pcr0_hex: None,
        allow_mock: true,
    }
}

pub fn verifier() -> Result<AttestationVerifier> {
    Ok(AttestationVerifier::with_aws_root()?.allow_mock(true))
}

pub fn attest_in_process(
    enclave: &Enclave,
    verifier: &AttestationVerifier,
    owner: &Bytes32,
) -> Result<[u8; PK_LEN]> {
    let nonce = random_bytes32();
    let EnclaveResponse::Attestation { doc, manifest, .. } = enclave.attest(&nonce, Some(*owner))
    else {
        bail!("the enclave refused the attestation");
    };
    Ok(verify_bundle(
        verifier,
        &AttestationBundle {
            nonce,
            doc,
            manifest,
        },
    )?)
}

pub async fn attest_bank<L: EnclaveLink>(
    bank: &Bank<L>,
    verifier: &AttestationVerifier,
    owner: &Bytes32,
) -> Result<[u8; PK_LEN]> {
    let nonce = random_bytes32();
    let request = BankRequest::Attest {
        nonce,
        owner: *owner,
    };
    let outcome = bank.handle(&request).await;
    let BankResponse::Attestation { doc, manifest } = outcome.response else {
        bail!("the bank refused the attestation");
    };
    Ok(verify_bundle(
        verifier,
        &AttestationBundle {
            nonce,
            doc,
            manifest,
        },
    )?)
}

#[derive(Clone)]
pub struct InProcessLink(Arc<Enclave>);

impl EnclaveLink for InProcessLink {
    async fn attest(
        &self,
        nonce: Bytes32,
        owner: Option<Bytes32>,
    ) -> Result<EnclaveResponse, LinkError> {
        Ok(self.0.attest(&nonce, owner))
    }

    async fn cancel(&self, channel_pk: [u8; 32]) -> Result<EnclaveResponse, LinkError> {
        Ok(self.0.cancel(&channel_pk))
    }

    async fn check(&self, bank_nonce: Bytes32, op: CheckOp) -> Result<EnclaveResponse, LinkError> {
        Ok(self.0.check(bank_nonce, &op))
    }
}

pub async fn in_process_bank(
    root: &Path,
    name: &str,
) -> Result<(Arc<Bank<InProcessLink>>, PathBuf)> {
    let BankDir { dir, keys } = bank_dir(root, name)?;
    let enclave = Enclave::boot(keys, Box::new(MockProvider::new()))?;
    let bank = Bank::open(&dir, InProcessLink(Arc::new(enclave)))?.with_policy(Policy {
        trust: mock_trust(),
        enclave: None,
    });
    bank.register(&mock_trust(), None).await?;
    Ok((Arc::new(bank), dir))
}

fn local_addr(listener: &Listener) -> Result<String> {
    match listener.local_endpoint()? {
        Endpoint::Tcp(addr) => Ok(addr),
        other => bail!("not a TCP listener: {other}"),
    }
}

pub struct Loopback {
    pub client: BankClient,
    pub dir: PathBuf,
    pub keys: BankKeys,
    shutdown: Vec<watch::Sender<bool>>,
}

impl Drop for Loopback {
    fn drop(&mut self) {
        for tx in &self.shutdown {
            let _ = tx.send(true);
        }
    }
}

pub async fn start_loopback(root: &Path, name: &str) -> Result<Loopback> {
    let BankDir { dir, keys } = bank_dir(root, name)?;
    let enclave_listener = tv_enclave::bind(&Endpoint::tcp(ANY_LOOPBACK)?).await?;
    let enclave_endpoint = Endpoint::tcp(&local_addr(&enclave_listener)?)?;
    let (enclave_tx, enclave_rx) = watch::channel(false);
    let enclave = Arc::new(Enclave::boot(keys, Box::new(MockProvider::new()))?);
    tokio::spawn(async move {
        let config = tv_enclave::ServerConfig::default();
        if let Err(err) = tv_enclave::serve(enclave_listener, enclave, config, enclave_rx).await {
            eprintln!("enclave server: {err}");
        }
    });
    let bank = Bank::open(&dir, TcpLink::new(enclave_endpoint.clone()))?.with_policy(Policy {
        trust: mock_trust(),
        enclave: Some(enclave_endpoint.clone()),
    });
    bank.register(&mock_trust(), Some(&enclave_endpoint))
        .await?;
    let bank_listener = tv_bank::bind(&Endpoint::tcp(ANY_LOOPBACK)?).await?;
    let bank_addr = local_addr(&bank_listener)?;
    let (bank_tx, bank_rx) = watch::channel(false);
    let config = ServerConfig {
        after_append: None,
        enclave: Some(enclave_endpoint),
        trust: mock_trust(),
    };
    tokio::spawn(async move {
        if let Err(err) = tv_bank::serve(bank_listener, Arc::new(bank), config, bank_rx).await {
            eprintln!("bank server: {err}");
        }
    });
    let client = BankClient::new(Endpoint::tcp(&bank_addr)?, &client_trust())?;
    Ok(Loopback {
        client,
        dir,
        keys,
        shutdown: vec![enclave_tx, bank_tx],
    })
}
