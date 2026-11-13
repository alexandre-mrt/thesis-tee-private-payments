//! The Nitro attestation document payload (CBOR inside the COSE_Sign1).
//!
//! Field names and encodings mirror `aws_nitro_enclaves_nsm_api::api::AttestationDoc`
//! (serde_cbor: text keys, `digest` as a text string, `pcrs` as an integer-keyed
//! map, byte fields as CBOR byte strings) so the real NSM output parses here
//! without depending on the Linux-only NSM crate on the client side.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::framing::{FrameError, decode_cbor, encode_cbor};

/// PCR digest algorithm of the NSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Digest {
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA384")]
    Sha384,
    #[serde(rename = "SHA512")]
    Sha512,
}

/// Attestation document payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationDoc {
    /// Issuing NSM id.
    pub module_id: String,
    /// PCR digest algorithm (SHA384 on Nitro).
    pub digest: Digest,
    /// Creation time, milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// Locked PCRs at creation time.
    pub pcrs: BTreeMap<usize, ByteBuf>,
    /// DER leaf certificate that signed the document.
    pub certificate: ByteBuf,
    /// DER CA bundle, root first, issuer of `certificate` last.
    pub cabundle: Vec<ByteBuf>,
    /// Caller-provided public key (here: the enclave X25519 key).
    #[serde(default)]
    pub public_key: Option<ByteBuf>,
    /// Caller-provided user data.
    #[serde(default)]
    pub user_data: Option<ByteBuf>,
    /// Caller-provided nonce.
    #[serde(default)]
    pub nonce: Option<ByteBuf>,
}

impl AttestationDoc {
    /// Parses the CBOR payload.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, FrameError> {
        decode_cbor(bytes)
    }

    /// Serializes to CBOR (used by the mock chain in tests and tooling).
    pub fn to_cbor(&self) -> Result<Vec<u8>, FrameError> {
        encode_cbor(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wire_shape() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, ByteBuf::from(vec![1u8; 48]));
        pcrs.insert(8, ByteBuf::from(vec![2u8; 48]));
        let doc = AttestationDoc {
            module_id: "i-0123-enc0456".to_owned(),
            digest: Digest::Sha384,
            timestamp: 1_700_000_000_000,
            pcrs,
            certificate: ByteBuf::from(vec![0x30, 0x00]),
            cabundle: vec![ByteBuf::from(vec![0x30, 0x01])],
            public_key: Some(ByteBuf::from(vec![9u8; 32])),
            user_data: None,
            nonce: Some(ByteBuf::from(vec![7u8; 32])),
        };
        let bytes = doc.to_cbor().unwrap();
        assert_eq!(AttestationDoc::from_cbor(&bytes).unwrap(), doc);
        // "digest" is encoded as the text string "SHA384" like serde_cbor does.
        let needle = b"\x66SHA384";
        assert!(bytes.windows(needle.len()).any(|w| w == needle));
        // Byte fields are byte strings (0x58 0x20 = 32-byte bstr), not arrays.
        assert!(bytes.windows(2).any(|w| w == [0x58, 0x20]));
    }

    #[test]
    fn missing_optional_fields_default_to_none() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, ByteBuf::from(vec![0u8; 48]));
        let full = AttestationDoc {
            module_id: "m".to_owned(),
            digest: Digest::Sha384,
            timestamp: 1,
            pcrs,
            certificate: ByteBuf::from(vec![1]),
            cabundle: vec![],
            public_key: None,
            user_data: None,
            nonce: None,
        };
        // Encode a map without the optional keys at all.
        #[derive(Serialize)]
        struct Partial<'a> {
            module_id: &'a str,
            digest: Digest,
            timestamp: u64,
            pcrs: &'a BTreeMap<usize, ByteBuf>,
            certificate: &'a ByteBuf,
            cabundle: &'a [ByteBuf],
        }
        let bytes = encode_cbor(&Partial {
            module_id: &full.module_id,
            digest: full.digest,
            timestamp: full.timestamp,
            pcrs: &full.pcrs,
            certificate: &full.certificate,
            cabundle: &full.cabundle,
        })
        .unwrap();
        assert_eq!(AttestationDoc::from_cbor(&bytes).unwrap(), full);
    }
}
