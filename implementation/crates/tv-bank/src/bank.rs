mod attest;
mod handlers;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pt_tee::transport::Endpoint;
use serde::Serialize;
use tracing::{info, warn};
use tv_core::{
    BankKeys, BankRequest, BankResponse, Bytes32, CheckOp, EnclaveResponse, LogEntry, OpKind,
    SideKind, Signature, SigningKey, VerifyingKey, random_bytes32, sign_state, verify_result_with,
};

use crate::commit::{Committer, SharedStore};
use crate::error::BankError;
use crate::index::{Index, answer_for};
use crate::inflight::{Claim, InFlight};
use crate::init::{ENCLAVE_PK_FILE, ISSUANCE_KEY_FILE, STATE_KEY_FILE, require_complete};
use crate::journal::LogWriter;
use crate::keys::{read_key, read_public, write_public};
use crate::link::EnclaveLink;
use crate::quota::AttestQuota;
use crate::registry::{EnclaveTrust, attest_enclave};
use crate::store::{Store, Ticket};

pub const BANK_SOURCE: &str = "local";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub response: BankResponse,
    pub appended: bool,
}

impl Outcome {
    fn reply(response: BankResponse) -> Self {
        Self {
            response,
            appended: false,
        }
    }

    fn refuse(reason: &str) -> Self {
        warn!(reason, "refused");
        Self::reply(BankResponse::Refused)
    }

    fn unavailable(err: &BankError, what: &str) -> Self {
        warn!(error = %err, "{what}; the operation is not settled");
        Self::reply(BankResponse::Unavailable)
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub trust: EnclaveTrust,
    pub enclave: Option<Endpoint>,
}

#[derive(Serialize)]
struct View<'a> {
    registered_result_pk: Option<Bytes32>,
    index: &'a Index,
}

pub struct Bank<L: EnclaveLink, W: LogWriter = File> {
    dir: PathBuf,
    state_key: SigningKey,
    issuance_key: SigningKey,
    store: SharedStore<W>,
    committer: Committer,
    registered: Mutex<Option<VerifyingKey>>,
    registering: tokio::sync::Mutex<()>,
    in_flight: InFlight,
    quota: Mutex<AttestQuota>,
    policy: Option<Policy>,
    link: L,
}

impl<L: EnclaveLink> Bank<L, File> {
    pub fn open(dir: &Path, link: L) -> Result<Self, BankError> {
        require_complete(dir)?;
        Self::from_store(dir, link, Store::open(dir)?)
    }
}

impl<L: EnclaveLink, W: LogWriter> Bank<L, W> {
    pub(crate) fn from_store(dir: &Path, link: L, store: Store<W>) -> Result<Self, BankError> {
        let state_key = read_key(&dir.join(STATE_KEY_FILE))?;
        let issuance_key = read_key(&dir.join(ISSUANCE_KEY_FILE))?;
        let registered = read_public(&dir.join(ENCLAVE_PK_FILE))?
            .map(|pk| VerifyingKey::parse(&pk))
            .transpose()?;
        info!(
            entries = store.index().len(),
            spent = store.index().spent_count(),
            registered = registered.is_some(),
            "bank opened"
        );
        Ok(Self {
            dir: dir.to_path_buf(),
            state_key,
            issuance_key,
            store: Arc::new(Mutex::new(store)),
            committer: Committer::default(),
            registered: Mutex::new(registered),
            registering: tokio::sync::Mutex::new(()),
            in_flight: InFlight::default(),
            quota: Mutex::new(AttestQuota::default()),
            policy: None,
            link,
        })
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn keys(&self) -> BankKeys {
        BankKeys {
            state_pk: self.state_key.public_key(),
            issuance_pk: self.issuance_key.public_key(),
        }
    }

    pub fn link(&self) -> &L {
        &self.link
    }

    pub fn registered_result_pk(&self) -> Option<Bytes32> {
        self.registered_result_key().map(|key| key.to_bytes())
    }

    fn registered_result_key(&self) -> Option<VerifyingKey> {
        self.registered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn store(&self) -> MutexGuard<'_, Store<W>> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn entries(&self) -> Vec<LogEntry> {
        self.store().entries().to_vec()
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    async fn claim(&self, digest: Bytes32) -> Result<Claim<'_>, Outcome> {
        loop {
            if let Some(answer) = self.stored_answer(&digest).await {
                return Err(Outcome::reply(answer));
            }
            match self.in_flight.try_claim(digest) {
                Ok(claim) => return Ok(claim),
                Err(mut released) => {
                    if released.changed().await.is_err() {
                        return Err(Outcome::refuse("in-flight gate closed"));
                    }
                }
            }
        }
    }

    async fn stored_answer(&self, digest: &Bytes32) -> Option<BankResponse> {
        let (ticket, answer) = self.store().answer(digest)?;
        match self.committer.commit(&self.store, ticket).await {
            Ok(()) => Some(answer),
            Err(err) => {
                Some(Outcome::unavailable(&err, "stored answer never became durable").response)
            }
        }
    }

    pub fn view_bytes(&self) -> Result<Vec<u8>, BankError> {
        let mut store = self.store();
        let mut bytes = store.raw_bytes()?;
        bytes.extend(serde_json::to_vec(&View {
            registered_result_pk: self.registered_result_pk(),
            index: store.index(),
        })?);
        Ok(bytes)
    }

    pub async fn register(
        &self,
        trust: &EnclaveTrust,
        enclave: Option<&Endpoint>,
    ) -> Result<Bytes32, BankError> {
        let _single = self.registering.lock().await;
        self.register_locked(trust, enclave).await
    }

    async fn register_locked(
        &self,
        trust: &EnclaveTrust,
        enclave: Option<&Endpoint>,
    ) -> Result<Bytes32, BankError> {
        let verifier = trust.verifier(enclave)?;
        let result_pk = attest_enclave(&self.link, &verifier, &self.keys()).await?;
        let result_key = VerifyingKey::parse(&result_pk)?;
        write_public(&self.dir.join(ENCLAVE_PK_FILE), &result_pk)?;
        *self
            .registered
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(result_key);
        info!(result_pk = %hex::encode(result_pk), "enclave registered");
        Ok(result_pk)
    }

    pub async fn handle(&self, request: &BankRequest) -> Outcome {
        self.handle_from(BANK_SOURCE, request).await
    }

    pub async fn handle_from(&self, source: &str, request: &BankRequest) -> Outcome {
        if let Err(err) = self.store().healthy() {
            warn!(error = %err, "request refused");
            return Outcome::reply(BankResponse::Refused);
        }
        match request {
            BankRequest::Attest { nonce, owner } => self.attest(*nonce, source, *owner).await,
            BankRequest::Receive(receive) => self.receive(receive).await,
            BankRequest::Enroll(enroll) => self.enroll(enroll).await,
            BankRequest::Refresh(refresh) => self.refresh(refresh).await,
            BankRequest::Lookup { serial } => Outcome::reply(BankResponse::Entry(
                self.store().lookup(serial).cloned().map(Box::new),
            )),
            BankRequest::LogRange { from, limit } => {
                Outcome::reply(BankResponse::Entries(self.store().range(*from, *limit)))
            }
            BankRequest::RegisterEnclave => Outcome::refuse("registration over the wire"),
        }
    }

    async fn checked(&self, digest: &Bytes32, op: CheckOp) -> Result<Vec<SideKind>, Outcome> {
        let Some(result_key) = self.registered_result_key() else {
            return Err(Outcome::refuse("no enclave registered"));
        };
        let nonce = random_bytes32();
        let channel_pk = *op.channel_pk();
        let result = match self.link.check(nonce, op).await {
            Ok(EnclaveResponse::Result(result)) => {
                self.quota().consumed(&channel_pk);
                result
            }
            Ok(_) => return Err(Outcome::refuse("enclave refused")),
            Err(err) => {
                warn!(error = %err, "enclave unreachable");
                return Err(Outcome::reply(BankResponse::Unavailable));
            }
        };
        if verify_result_with(&result_key, &result, &nonce, digest).is_err() {
            let fresh = self.re_register(&result_key).await?;
            if verify_result_with(&fresh, &result, &nonce, digest).is_err() {
                return Err(Outcome::refuse("enclave result signature"));
            }
        }
        Ok(result.sides)
    }

    async fn re_register(&self, stale: &VerifyingKey) -> Result<VerifyingKey, Outcome> {
        let Some(policy) = self.policy.as_ref() else {
            return Err(Outcome::refuse("enclave result signature"));
        };
        let _single = self.registering.lock().await;
        if let Some(current) = self.registered_result_key().filter(|key| key != stale) {
            return Ok(current);
        }
        match self
            .register_locked(&policy.trust, policy.enclave.as_ref())
            .await
            .and_then(|result_pk| Ok(VerifyingKey::parse(&result_pk)?))
        {
            Ok(fresh) => {
                info!("enclave re-attested after a result signature mismatch");
                Ok(fresh)
            }
            Err(err) if err.is_transient() => Err(Outcome::unavailable(
                &err,
                "re-attestation after a result signature mismatch failed",
            )),
            Err(err) => {
                warn!(error = %err, "re-attestation after a result signature mismatch rejected");
                Err(Outcome::refuse("enclave result signature"))
            }
        }
    }

    fn signer(&self, side: SideKind) -> &SigningKey {
        match side {
            SideKind::User => &self.state_key,
            SideKind::Bank => &self.issuance_key,
        }
    }

    async fn settle(
        &self,
        kind: OpKind,
        serials: Vec<Bytes32>,
        commitments: Vec<Bytes32>,
        sides: Vec<SideKind>,
        digest: Bytes32,
    ) -> Outcome {
        let sigs = commitments
            .iter()
            .zip(&sides)
            .map(|(com, side)| sign_state(self.signer(*side), com))
            .collect();
        let (ticket, response, staged) = match self.stage(kind, serials, commitments, sigs, digest)
        {
            Ok(staged) => staged,
            Err(reason) => return Outcome::refuse(reason),
        };
        if let Err(err) = self.committer.commit(&self.store, ticket).await {
            return Outcome::unavailable(&err, "commit failed");
        }
        if staged {
            info!(kind = ?kind, "settled");
        }
        Outcome {
            response,
            appended: staged,
        }
    }

    fn stage(
        &self,
        kind: OpKind,
        serials: Vec<Bytes32>,
        commitments: Vec<Bytes32>,
        sigs: Vec<Signature>,
        digest: Bytes32,
    ) -> Result<(Ticket, BankResponse, bool), &'static str> {
        let mut store = self.store();
        if let Some((ticket, answer)) = store.answer(&digest) {
            return Ok((ticket, answer, false));
        }
        let consumed = serials.iter().any(|s| match kind {
            OpKind::Enroll => !store.index().is_fresh_serial(s),
            OpKind::Pay | OpKind::Refresh => store.index().is_spent(s),
        });
        let reused = kind == OpKind::Enroll
            && commitments
                .iter()
                .any(|c| !store.index().is_fresh_commitment(c));
        if consumed || reused {
            return Err("serial or commitment consumed concurrently");
        }
        let entry = LogEntry {
            seq: store.index().len(),
            kind,
            serials,
            commitments,
            sigs,
            digest,
        };
        let Some(response) = answer_for(&entry) else {
            return Err("entry shape");
        };
        let ticket = store.stage(entry).map_err(|err| {
            warn!(error = %err, "stage failed; the operation is not settled");
            "storage"
        })?;
        Ok((ticket, response, true))
    }
}
