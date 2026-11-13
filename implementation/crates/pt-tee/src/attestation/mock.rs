//! Mock attestation: a distinct, loudly marked, unsigned format.
//!
//! A mock document is [`MOCK_MAGIC`] followed by the CBOR encoding of
//! [`MockAttestation`]. It carries no certificate and no signature, so it
//! proves nothing; [`super::AttestationVerifier`] rejects it unless
//! `allow_mock` is set. It exists so `pt-enclave --mock` and the local demo
//! exercise the full protocol without Nitro hardware.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::{AttestationError, AttestationInputs, AttestationProvider, now_millis};
use crate::framing::{decode_cbor, encode_cbor};

/// Prefix of every mock document. Never appears in a real COSE_Sign1 document
/// (which starts with a CBOR array or tag byte).
pub const MOCK_MAGIC: &[u8] = b"PLATYPUS-TEE-MOCK-ATTESTATION-INSECURE/v1\n";

/// PCR0 reported by the default mock provider: 48 zero bytes, which is also
/// what a Nitro enclave in debug mode reports.
pub const MOCK_PCR0: [u8; 48] = [0u8; 48];

/// Body of a mock document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockAttestation {
    pub public_key: ByteBuf,
    pub nonce: ByteBuf,
    pub user_data: ByteBuf,
    pub pcr0: ByteBuf,
    pub timestamp_ms: u64,
}

impl MockAttestation {
    /// `MOCK_MAGIC || CBOR(self)`.
    pub fn encode(&self) -> Result<Vec<u8>, AttestationError> {
        let body = encode_cbor(self).map_err(|e| AttestationError::Encode(e.to_string()))?;
        let mut out = Vec::with_capacity(MOCK_MAGIC.len() + body.len());
        out.extend_from_slice(MOCK_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parses a mock document. `Err` if the magic is missing or the body is malformed.
    pub fn decode(doc: &[u8]) -> Result<Self, String> {
        let body = doc
            .strip_prefix(MOCK_MAGIC)
            .ok_or_else(|| "missing mock magic".to_owned())?;
        decode_cbor(body).map_err(|e| e.to_string())
    }
}

/// True if `doc` is in the mock format.
pub fn is_mock(doc: &[u8]) -> bool {
    doc.starts_with(MOCK_MAGIC)
}

/// Mock provider for local runs. Not an attestation.
#[derive(Debug, Clone)]
pub struct MockProvider {
    pcr0: Vec<u8>,
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProvider {
    /// Mock provider reporting [`MOCK_PCR0`].
    pub fn new() -> Self {
        Self {
            pcr0: MOCK_PCR0.to_vec(),
        }
    }

    /// Mock provider reporting a chosen PCR0 (to exercise PCR checks locally).
    pub fn with_pcr0(pcr0: Vec<u8>) -> Self {
        Self { pcr0 }
    }

    /// The PCR0 this provider reports.
    pub fn pcr0(&self) -> &[u8] {
        &self.pcr0
    }
}

impl AttestationProvider for MockProvider {
    fn attest(&self, inputs: &AttestationInputs<'_>) -> Result<Vec<u8>, AttestationError> {
        MockAttestation {
            public_key: ByteBuf::from(inputs.public_key.to_vec()),
            nonce: ByteBuf::from(inputs.nonce.to_vec()),
            user_data: ByteBuf::from(inputs.user_data.to_vec()),
            pcr0: ByteBuf::from(self.pcr0.clone()),
            timestamp_ms: now_millis()?,
        }
        .encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_documents_are_marked_and_roundtrip() {
        let provider = MockProvider::new();
        let doc = provider
            .attest(&AttestationInputs {
                nonce: &[1u8; 32],
                user_data: b"platypus-tee/v1digest",
                public_key: &[2u8; 32],
            })
            .unwrap();
        assert!(is_mock(&doc));
        assert!(doc.starts_with(b"PLATYPUS-TEE-MOCK"));
        let parsed = MockAttestation::decode(&doc).unwrap();
        assert_eq!(parsed.nonce.as_slice(), &[1u8; 32]);
        assert_eq!(parsed.public_key.as_slice(), &[2u8; 32]);
        assert_eq!(parsed.user_data.as_slice(), b"platypus-tee/v1digest");
        assert_eq!(parsed.pcr0.as_slice(), &MOCK_PCR0);
        assert!(parsed.timestamp_ms > 0);
    }

    #[test]
    fn custom_pcr0_and_malformed_bodies() {
        let provider = MockProvider::with_pcr0(vec![0xAA; 48]);
        assert_eq!(provider.pcr0(), &[0xAA; 48]);
        let doc = provider
            .attest(&AttestationInputs {
                nonce: &[],
                user_data: &[],
                public_key: &[0u8; 32],
            })
            .unwrap();
        assert_eq!(
            MockAttestation::decode(&doc).unwrap().pcr0.as_slice(),
            &[0xAA; 48]
        );

        assert!(!is_mock(b"\x84\x44\xa1\x01\x38\x22"));
        assert!(MockAttestation::decode(b"not a mock").is_err());
        let mut truncated = doc.clone();
        truncated.truncate(MOCK_MAGIC.len() + 3);
        assert!(MockAttestation::decode(&truncated).is_err());
        let mut trailing = doc;
        trailing.push(0);
        assert!(MockAttestation::decode(&trailing).is_err());
    }
}
