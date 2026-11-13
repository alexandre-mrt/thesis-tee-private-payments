use std::time::{SystemTime, UNIX_EPOCH};

use pt_tee::PROTOCOL_TAG;
use pt_tee::attestation::{AttestationVerifier, VerifyRequest};
use pt_tee::channel::PK_LEN;
use pt_tee::transport::Endpoint;
use serde::{Deserialize, Serialize};
use tv_core::{ATTEST_CLOCK_SKEW, Bytes32, MAX_KEY_AGE, Manifest, manifest_digest};

use crate::error::ClientError;

pub const PCR0_LEN: usize = 48;

pub fn parse_pcr0(hex_pcr0: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_pcr0.trim()).map_err(|e| format!("PCR0 is not hex: {e}"))?;
    if bytes.len() != PCR0_LEN {
        return Err(format!(
            "PCR0 is {} bytes, a SHA-384 measurement is {PCR0_LEN}",
            bytes.len()
        ));
    }
    Ok(hex::encode(bytes))
}

#[derive(Debug, Clone, Default)]
pub struct Trust {
    pub pcr0_hex: Option<String>,
    pub allow_mock: bool,
}

impl Trust {
    pub fn verifier(&self, bank: &Endpoint) -> Result<AttestationVerifier, ClientError> {
        if self.allow_mock && self.pcr0_hex.is_some() {
            return Err(ClientError::MockWithPin);
        }
        if self.allow_mock && !bank.is_loopback() {
            return Err(ClientError::MockRequiresLoopback);
        }
        let verifier = AttestationVerifier::with_aws_root()
            .map_err(|e| ClientError::Attestation(e.to_string()))?
            .allow_mock(self.allow_mock);
        match &self.pcr0_hex {
            Some(hex) => verifier
                .expect_pcr0_hex(hex)
                .map_err(|e| ClientError::Attestation(e.to_string())),
            None if self.allow_mock => Ok(verifier),
            None => Err(ClientError::Pcr0Required),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub nonce: Bytes32,
    pub doc: Vec<u8>,
    pub manifest: Manifest,
}

pub fn now_unix_millis() -> Result<u128, ClientError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClientError::Clock)?
        .as_millis())
}

pub fn check_fresh(timestamp_ms: u64, now_ms: u128) -> Result<(), ClientError> {
    let issued = u128::from(timestamp_ms);
    if issued > now_ms + ATTEST_CLOCK_SKEW.as_millis() {
        return Err(ClientError::FutureAttestation {
            ahead_ms: issued - now_ms,
        });
    }
    let age_ms = now_ms.saturating_sub(issued);
    if age_ms >= MAX_KEY_AGE.as_millis() {
        return Err(ClientError::StaleAttestation { age_ms });
    }
    Ok(())
}

pub fn verify_bundle(
    verifier: &AttestationVerifier,
    bundle: &AttestationBundle,
) -> Result<[u8; PK_LEN], ClientError> {
    verify_bundle_at(verifier, bundle, now_unix_millis()?)
}

fn verify_bundle_at(
    verifier: &AttestationVerifier,
    bundle: &AttestationBundle,
    now_ms: u128,
) -> Result<[u8; PK_LEN], ClientError> {
    let digest = manifest_digest(&bundle.manifest);
    let now_unix_secs = i64::try_from(now_ms / 1000).map_err(|_| ClientError::Clock)?;
    let attested = verifier
        .verify(
            &bundle.doc,
            &VerifyRequest {
                nonce: &bundle.nonce,
                user_data_prefix: PROTOCOL_TAG,
                user_data_digest: &digest,
                now_unix_secs,
            },
        )
        .map_err(|e| ClientError::Attestation(e.to_string()))?;
    check_fresh(attested.timestamp_ms, now_ms)?;
    attested
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| ClientError::Attestation("bad channel key length".to_owned()))
}
