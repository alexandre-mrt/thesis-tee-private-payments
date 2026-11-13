#![allow(
    dead_code,
    reason = "each test binary uses a subset of the shared fixtures"
)]

use pt_tee::channel::ClientChannel;
use tv_core::{
    CheckOp, EnclaveResponse, Opening, PayPublic, PaySecret, Receive, SealedBlob, SideKind,
    Signature, encode_cbor,
};
use tv_enclave::Enclave;

pub const AMOUNT: u64 = 0x5A5A_1234;
pub const PAYER_BALANCE: u64 = 987_654;
pub const PAYER_NEXT_PK: [u8; 32] = [0xC3; 32];
pub const PAYER_NEXT_R: [u8; 32] = [0xA5; 32];
pub const PAYEE_NEXT_PK: [u8; 32] = [0xD4; 32];
pub const PAYEE_NEXT_R: [u8; 32] = [0xB7; 32];

fn seal(channel_pk: &[u8; 32], balance: u64, next_pk: [u8; 32], next_r: [u8; 32]) -> SealedBlob {
    let opening = Opening {
        balance,
        r: [0x11; 32],
        sig: Signature([0u8; 64]),
        side: SideKind::User,
        next_pk,
        next_r,
    };
    let channel = ClientChannel::connect(channel_pk).unwrap();
    let secret = encode_cbor(&PaySecret { v: AMOUNT, opening }).unwrap();
    let sealed = channel.seal_request(&secret).unwrap();
    SealedBlob {
        client_pk: channel.client_pk(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    }
}

pub fn pay_op(enclave: &Enclave) -> CheckOp {
    let owner = [7u8; 32];
    let EnclaveResponse::Attestation { channel_pk, .. } = enclave.attest(&[1u8; 32], Some(owner))
    else {
        panic!("the enclave did not attest");
    };
    CheckOp::Pay(Box::new(Receive {
        channel_pk,
        public: PayPublic {
            pk_a: [5u8; 32],
            com_a_next: [6u8; 32],
            sig_a: Signature([0u8; 64]),
            pk_b: owner,
            com_b_next: [8u8; 32],
            sig_b: Signature([0u8; 64]),
        },
        payer: seal(&channel_pk, PAYER_BALANCE, PAYER_NEXT_PK, PAYER_NEXT_R),
        payee: seal(&channel_pk, 55_555, PAYEE_NEXT_PK, PAYEE_NEXT_R),
    }))
}
