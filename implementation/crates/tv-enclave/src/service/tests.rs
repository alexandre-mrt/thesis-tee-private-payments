use pt_tee::PROTOCOL_TAG;
use pt_tee::attestation::{AttestationVerifier, MockProvider, VerifyRequest};
use pt_tee::channel::ClientChannel;
use tv_core::{
    EnrollRequest, EnrollSecret, commitment, encode_cbor, enroll_digest, sign_digest, verify_result,
};

use super::*;

fn enclave() -> Enclave {
    Enclave::boot(
        BankKeys {
            state_pk: SigningKey::generate().public_key(),
            issuance_pk: SigningKey::generate().public_key(),
        },
        Box::new(MockProvider::new()),
    )
    .unwrap()
}

fn attested_channel_pk(e: &Enclave, nonce: &Bytes32, owner: &Bytes32) -> [u8; 32] {
    let EnclaveResponse::Attestation {
        doc,
        manifest,
        channel_pk,
    } = e.attest(nonce, Some(*owner))
    else {
        panic!("attestation expected");
    };
    let verifier = AttestationVerifier::with_aws_root()
        .unwrap()
        .allow_mock(true);
    let attested = verifier
        .verify(
            &doc,
            &VerifyRequest {
                nonce,
                user_data_prefix: PROTOCOL_TAG,
                user_data_digest: &manifest_digest(&manifest),
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap();
    assert_eq!(attested.public_key, channel_pk);
    channel_pk
}

fn enroll_op(channel_pk: [u8; 32], sk: &SigningKey) -> (CheckOp, Bytes32) {
    let r0 = [5u8; 32];
    let com0 = commitment(0, &sk.public_key(), &r0);
    let channel = ClientChannel::connect(&channel_pk).unwrap();
    let sealed = channel
        .seal_request(&encode_cbor(&EnrollSecret { r0 }).unwrap())
        .unwrap();
    let digest = enroll_digest(&sk.public_key(), &com0);
    let op = CheckOp::Enroll(Box::new(EnrollRequest {
        channel_pk,
        pk0: sk.public_key(),
        com0,
        sig: sign_digest(sk, &digest),
        sealed: SealedBlob {
            client_pk: channel.client_pk(),
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
        },
    }));
    (op, digest)
}

fn attested_enroll(e: &Enclave, nonce: &Bytes32) -> ([u8; 32], SigningKey) {
    let sk = SigningKey::generate();
    (attested_channel_pk(e, nonce, &sk.public_key()), sk)
}

#[test]
fn attest_check_and_single_use_keys() {
    let e = enclave();
    let (channel_pk, sk) = attested_enroll(&e, &[7u8; 32]);
    assert_eq!(e.pending_keys(), 1);
    let (op, digest) = enroll_op(channel_pk, &sk);
    let nonce = [9u8; 32];
    let EnclaveResponse::Result(result) = e.check(nonce, &op) else {
        panic!("result expected");
    };
    assert!(verify_result(&e.result_pk(), &result, &nonce, &digest).is_ok());
    assert_eq!(e.pending_keys(), 0);
    assert_eq!(e.check(nonce, &op), EnclaveResponse::Refused);
}

#[test]
fn a_cancelled_key_is_gone_and_cancelling_an_unknown_key_is_harmless() {
    let e = enclave();
    let (channel_pk, sk) = attested_enroll(&e, &[6u8; 32]);
    assert_eq!(e.pending_keys(), 1);
    assert_eq!(
        e.handle(&EnclaveRequest::Cancel { channel_pk }),
        EnclaveResponse::Cancelled
    );
    assert_eq!(e.pending_keys(), 0);
    let (op, _) = enroll_op(channel_pk, &sk);
    assert_eq!(e.check([9u8; 32], &op), EnclaveResponse::Refused);
    assert_eq!(
        e.handle(&EnclaveRequest::Cancel { channel_pk }),
        EnclaveResponse::Cancelled
    );
}

#[test]
fn an_attestation_without_an_owner_keeps_no_channel_key() {
    let e = enclave();
    let nonce = [8u8; 32];
    let EnclaveResponse::Attestation { doc, manifest, .. } = e.attest(&nonce, None) else {
        panic!("attestation expected");
    };
    assert_eq!(e.pending_keys(), 0);
    assert_eq!(manifest.result_pk, e.result_pk());
    let verifier = AttestationVerifier::with_aws_root()
        .unwrap()
        .allow_mock(true);
    verifier
        .verify(
            &doc,
            &VerifyRequest {
                nonce: &nonce,
                user_data_prefix: PROTOCOL_TAG,
                user_data_digest: &manifest_digest(&manifest),
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap();
    let (channel_pk, sk) = attested_enroll(&e, &[7u8; 32]);
    assert_eq!(e.pending_keys(), 1);
    let (op, _) = enroll_op(channel_pk, &sk);
    assert!(matches!(
        e.check([0u8; 32], &op),
        EnclaveResponse::Result(_)
    ));
    assert_eq!(e.pending_keys(), 0);
}

#[test]
fn leaked_memory_opens_blobs_but_a_consumed_key_is_gone() {
    let e = enclave();
    let (channel_pk, sk) = attested_enroll(&e, &[1u8; 32]);
    let (op, _) = enroll_op(channel_pk, &sk);
    let CheckOp::Enroll(request) = &op else {
        panic!("enroll");
    };
    let leaked = e.leak_memory();
    assert_eq!(leaked.channel_count(), 1);
    let plaintext = leaked.open_blob(&request.sealed).unwrap();
    let secret: EnrollSecret = decode_cbor(&plaintext).unwrap();
    assert_eq!(secret.r0, [5u8; 32]);
    assert!(matches!(
        e.check([0u8; 32], &op),
        EnclaveResponse::Result(_)
    ));
    assert!(leaked.open_blob(&request.sealed).is_some());
    assert_eq!(e.leak_memory().channel_count(), 0);
}

#[test]
fn a_junk_blob_does_not_burn_the_channel_key() {
    let e = enclave();
    let (own, sk) = attested_enroll(&e, &[1u8; 32]);
    let other = attested_channel_pk(&enclave(), &[2u8; 32], &sk.public_key());
    let (foreign, _) = enroll_op(other, &sk);
    let CheckOp::Enroll(mut request) = foreign else {
        panic!("enroll");
    };
    request.channel_pk = own;
    assert_eq!(
        e.check([0u8; 32], &CheckOp::Enroll(request)),
        EnclaveResponse::Refused
    );
    assert_eq!(e.pending_keys(), 1);
    let (mut tampered, _) = enroll_op(own, &sk);
    if let CheckOp::Enroll(request) = &mut tampered {
        request.sealed.ciphertext[0] ^= 0x01;
    }
    assert_eq!(e.check([0u8; 32], &tampered), EnclaveResponse::Refused);
    assert_eq!(e.pending_keys(), 1);
    let (genuine, digest) = enroll_op(own, &sk);
    let nonce = [4u8; 32];
    let EnclaveResponse::Result(result) = e.check(nonce, &genuine) else {
        panic!("result expected");
    };
    assert!(verify_result(&e.result_pk(), &result, &nonce, &digest).is_ok());
    assert_eq!(e.pending_keys(), 0);
    assert_eq!(e.check(nonce, &genuine), EnclaveResponse::Refused);
}

#[test]
fn a_key_attested_for_another_serial_is_refused_without_being_consumed() {
    let e = enclave();
    let (channel_pk, owner) = attested_enroll(&e, &[1u8; 32]);
    let intruder = SigningKey::generate();
    let (hijack, _) = enroll_op(channel_pk, &intruder);
    assert_eq!(e.check([0u8; 32], &hijack), EnclaveResponse::Refused);
    assert_eq!(e.pending_keys(), 1);
    let (genuine, digest) = enroll_op(channel_pk, &owner);
    let nonce = [4u8; 32];
    let EnclaveResponse::Result(result) = e.check(nonce, &genuine) else {
        panic!("result expected");
    };
    assert!(verify_result(&e.result_pk(), &result, &nonce, &digest).is_ok());
    assert_eq!(e.pending_keys(), 0);
}

#[test]
fn a_failed_check_after_a_good_opening_still_consumes_the_key() {
    let e = enclave();
    let (own, sk) = attested_enroll(&e, &[1u8; 32]);
    let (mut op, _) = enroll_op(own, &sk);
    if let CheckOp::Enroll(request) = &mut op {
        request.com0[0] ^= 0x01;
    }
    assert_eq!(e.check([0u8; 32], &op), EnclaveResponse::Refused);
    assert_eq!(e.pending_keys(), 0);
}
