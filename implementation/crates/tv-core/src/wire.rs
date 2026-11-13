use pt_tee::channel::{NONCE_LEN, PK_LEN};
use serde::{Deserialize, Serialize};

use crate::commit::{enroll_digest, pay_digest, refresh_digest};
use crate::result::EnclaveResult;
use crate::sig::Signature;
use crate::types::{Bytes32, Manifest, Opening};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    pub client_pk: [u8; PK_LEN],
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayPublic {
    pub pk_a: Bytes32,
    pub com_a_next: Bytes32,
    pub sig_a: Signature,
    pub pk_b: Bytes32,
    pub com_b_next: Bytes32,
    pub sig_b: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaySecret {
    pub v: u64,
    pub opening: Opening,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receive {
    pub channel_pk: [u8; PK_LEN],
    pub public: PayPublic,
    pub payer: SealedBlob,
    pub payee: SealedBlob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollSecret {
    pub r0: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub channel_pk: [u8; PK_LEN],
    pub pk0: Bytes32,
    pub com0: Bytes32,
    pub sig: Signature,
    pub sealed: SealedBlob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshSecret {
    pub opening: Opening,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub channel_pk: [u8; PK_LEN],
    pub pk: Bytes32,
    pub com_next: Bytes32,
    pub sig: Signature,
    pub sealed: SealedBlob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKind {
    Enroll,
    Pay,
    Refresh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub kind: OpKind,
    pub serials: Vec<Bytes32>,
    pub commitments: Vec<Bytes32>,
    pub sigs: Vec<Signature>,
    pub digest: Bytes32,
}

impl LogEntry {
    pub fn sig_for(&self, commitment: &Bytes32) -> Option<Signature> {
        self.commitments
            .iter()
            .position(|c| c == commitment)
            .and_then(|i| self.sigs.get(i).copied())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BankRequest {
    Attest { nonce: Bytes32, owner: Bytes32 },
    Receive(Box<Receive>),
    Enroll(Box<EnrollRequest>),
    Refresh(Box<RefreshRequest>),
    Lookup { serial: Bytes32 },
    LogRange { from: u64, limit: u64 },
    RegisterEnclave,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BankResponse {
    Attestation {
        #[serde(with = "serde_bytes")]
        doc: Vec<u8>,
        manifest: Manifest,
    },
    Settled {
        sig_a_next: Signature,
        sig_b_next: Signature,
    },
    Enrolled {
        sig: Signature,
    },
    Refreshed {
        sig: Signature,
    },
    Entry(Option<Box<LogEntry>>),
    Entries(Vec<LogEntry>),
    Registered {
        result_pk: Bytes32,
    },
    Unavailable,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckOp {
    Pay(Box<Receive>),
    Enroll(Box<EnrollRequest>),
    Refresh(Box<RefreshRequest>),
}

impl CheckOp {
    pub fn channel_pk(&self) -> &[u8; PK_LEN] {
        match self {
            CheckOp::Pay(r) => &r.channel_pk,
            CheckOp::Enroll(r) => &r.channel_pk,
            CheckOp::Refresh(r) => &r.channel_pk,
        }
    }

    pub fn owner(&self) -> &Bytes32 {
        match self {
            CheckOp::Pay(r) => &r.public.pk_b,
            CheckOp::Enroll(r) => &r.pk0,
            CheckOp::Refresh(r) => &r.pk,
        }
    }

    pub fn digest(&self) -> Bytes32 {
        match self {
            CheckOp::Pay(r) => pay_digest(
                &r.public.pk_a,
                &r.public.com_a_next,
                &r.public.pk_b,
                &r.public.com_b_next,
            ),
            CheckOp::Enroll(r) => enroll_digest(&r.pk0, &r.com0),
            CheckOp::Refresh(r) => refresh_digest(&r.pk, &r.com_next),
        }
    }

    pub fn side_count(&self) -> usize {
        match self {
            CheckOp::Pay(_) => 2,
            CheckOp::Enroll(_) | CheckOp::Refresh(_) => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveRequest {
    Attest {
        nonce: Bytes32,
        owner: Option<Bytes32>,
    },
    Check {
        bank_nonce: Bytes32,
        op: CheckOp,
    },
    Cancel {
        channel_pk: [u8; PK_LEN],
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveResponse {
    Attestation {
        #[serde(with = "serde_bytes")]
        doc: Vec<u8>,
        manifest: Manifest,
        channel_pk: [u8; PK_LEN],
    },
    Result(EnclaveResult),
    Cancelled,
    Refused,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{decode_cbor, encode_cbor};

    #[test]
    fn requests_roundtrip_and_blobs_are_byte_strings() {
        let blob = SealedBlob {
            client_pk: [1u8; 32],
            nonce: [2u8; 12],
            ciphertext: vec![3u8; 40],
        };
        let bytes = encode_cbor(&blob).unwrap();
        assert!(bytes.windows(2).any(|w| w == [0x58, 40]));
        let back: SealedBlob = decode_cbor(&bytes).unwrap();
        assert_eq!(back, blob);
        let req = BankRequest::LogRange { from: 3, limit: 9 };
        let back: BankRequest = decode_cbor(&encode_cbor(&req).unwrap()).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn log_entry_sig_lookup_follows_commitment_position() {
        let entry = LogEntry {
            seq: 0,
            kind: OpKind::Pay,
            serials: vec![[1u8; 32], [2u8; 32]],
            commitments: vec![[3u8; 32], [4u8; 32]],
            sigs: vec![Signature([5u8; 64]), Signature([6u8; 64])],
            digest: [7u8; 32],
        };
        assert_eq!(entry.sig_for(&[4u8; 32]), Some(Signature([6u8; 64])));
        assert_eq!(entry.sig_for(&[9u8; 32]), None);
    }
}
