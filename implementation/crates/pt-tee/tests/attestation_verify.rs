//! Verifier tests against a generated CA chain (SPEC section 7, client verification).

mod support;

use pt_tee::PROTOCOL_TAG;
use pt_tee::attestation::root::{AWS_NITRO_ROOT_G1_SHA256_HEX, aws_nitro_root_g1_der, sha256_hex};
use pt_tee::attestation::{AttestationDoc, AttestationVerifier, VerifyError, VerifyRequest};
use serde_bytes::ByteBuf;
use support::{
    Cert, CertSpec, Chain, DocSpec, NOW, chain, make_cert, p256_key, p384_key, sign, signed_doc,
};

const PCR0: [u8; 48] = [0x5A; 48];
const NONCE: [u8; 32] = [0x42; 32];
const DIGEST: [u8; 32] = [0x77; 32];
const ENCLAVE_PK: [u8; 32] = [0x99; 32];

fn user_data() -> Vec<u8> {
    [PROTOCOL_TAG, &DIGEST[..]].concat()
}

fn spec<'a>(ud: &'a [u8]) -> DocSpec<'a> {
    DocSpec {
        pcr0: &PCR0,
        public_key: Some(&ENCLAVE_PK),
        user_data: Some(ud),
        nonce: Some(&NONCE),
    }
}

fn request<'a>(now: i64) -> VerifyRequest<'a> {
    VerifyRequest {
        nonce: &NONCE,
        user_data_prefix: PROTOCOL_TAG,
        user_data_digest: &DIGEST,
        now_unix_secs: now,
    }
}

fn verifier(chain: &Chain) -> AttestationVerifier {
    AttestationVerifier::with_root_der(chain.root.der())
        .expect("root")
        .expect_pcr0(PCR0.to_vec())
}

#[test]
fn embedded_aws_root_fingerprint_is_pinned() {
    let der = aws_nitro_root_g1_der().unwrap();
    assert_eq!(sha256_hex(&der), AWS_NITRO_ROOT_G1_SHA256_HEX);
    assert_eq!(
        AWS_NITRO_ROOT_G1_SHA256_HEX,
        "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
    );
    let v = AttestationVerifier::with_aws_root().unwrap();
    assert_eq!(v.root_der(), der.as_slice());
}

#[test]
fn valid_document_yields_attested_public_key() {
    let ch = chain("ok");
    let ud = user_data();
    let doc = signed_doc(&ch, &spec(&ud));
    let attested = verifier(&ch).verify(&doc, &request(NOW)).unwrap();
    assert_eq!(attested.public_key, ENCLAVE_PK);
    assert_eq!(attested.pcrs.get(&0).unwrap(), &PCR0.to_vec());
    assert_eq!(attested.pcrs.len(), 3);
    assert_eq!(attested.module_id, "i-test-enc0");
    assert_eq!(attested.timestamp_ms, NOW as u64 * 1000);
    assert!(!attested.mock);

    // Root injected as PEM works the same.
    let pem = ch.root.x509.to_pem().unwrap();
    let v = AttestationVerifier::with_root_pem(&pem)
        .unwrap()
        .expect_pcr0_hex(&hex::encode(PCR0))
        .unwrap();
    assert!(v.verify(&doc, &request(NOW)).is_ok());

    // Without an expected PCR0 a signed document is refused (security review H-1):
    // the pin is what distinguishes the audited image from any other enclave.
    let unpinned = AttestationVerifier::with_root_der(ch.root.der()).unwrap();
    assert!(matches!(
        unpinned.verify(&doc, &request(NOW)),
        Err(VerifyError::Pcr0NotPinned)
    ));
}

/// H-1 debug-mode variant: a debug enclave reports all-zero PCRs. Pinning that
/// value is refused, and a debug-mode document never matches a real pin.
#[test]
fn debug_mode_measurements_are_never_pinned_or_accepted() {
    let ch = chain("debug");
    let ud = user_data();
    let zero_pcr0 = [0u8; 48];
    let debug_doc = signed_doc(
        &ch,
        &DocSpec {
            pcr0: &zero_pcr0,
            ..spec(&ud)
        },
    );
    assert!(matches!(
        verifier(&ch).verify(&debug_doc, &request(NOW)),
        Err(VerifyError::Pcr0Mismatch { .. })
    ));
    let zero_pin = AttestationVerifier::with_root_der(ch.root.der())
        .unwrap()
        .expect_pcr0(zero_pcr0.to_vec());
    assert!(matches!(
        zero_pin.verify(&debug_doc, &request(NOW)),
        Err(VerifyError::Pcr0Zero)
    ));
    let zero_hex = AttestationVerifier::with_root_der(ch.root.der())
        .unwrap()
        .expect_pcr0_hex(&"00".repeat(48))
        .unwrap();
    assert!(matches!(
        zero_hex.verify(&signed_doc(&ch, &spec(&ud)), &request(NOW)),
        Err(VerifyError::Pcr0Zero)
    ));
}

#[test]
fn leaf_signed_directly_by_root_is_accepted() {
    let ch = chain("short");
    let leaf = make_cert(
        &CertSpec {
            cn: "direct-leaf",
            issuer: Some(&ch.root),
            ca: false,
            not_before: NOW - 60,
            not_after: NOW + 3600,
            serial: 9,
        },
        p384_key(),
    );
    let ud = user_data();
    let mut d = support::doc(&ch, &spec(&ud));
    d.certificate = ByteBuf::from(leaf.der());
    d.cabundle = vec![ByteBuf::from(ch.root.der())];
    let doc = sign(&d.to_cbor().unwrap(), &leaf.key);
    assert!(verifier(&ch).verify(&doc, &request(NOW)).is_ok());
}

#[test]
fn nonce_user_data_and_pcr0_mismatches_are_rejected() {
    let ch = chain("bind");
    let ud = user_data();
    let doc = signed_doc(&ch, &spec(&ud));
    let v = verifier(&ch);

    let mut bad_nonce = request(NOW);
    let other = [0u8; 32];
    bad_nonce.nonce = &other;
    assert!(matches!(
        v.verify(&doc, &bad_nonce),
        Err(VerifyError::NonceMismatch)
    ));

    let mut bad_digest = request(NOW);
    bad_digest.user_data_digest = &other;
    assert!(matches!(
        v.verify(&doc, &bad_digest),
        Err(VerifyError::UserDataMismatch)
    ));

    let mut bad_prefix = request(NOW);
    bad_prefix.user_data_prefix = b"platypus-tee/v2";
    assert!(matches!(
        v.verify(&doc, &bad_prefix),
        Err(VerifyError::UserDataMismatch)
    ));

    let strict = AttestationVerifier::with_root_der(ch.root.der())
        .unwrap()
        .expect_pcr0(vec![0x01; 48]);
    assert!(matches!(
        strict.verify(&doc, &request(NOW)),
        Err(VerifyError::Pcr0Mismatch { .. })
    ));

    // Document without nonce / user_data / public_key / PCR0.
    let no_nonce = signed_doc(
        &ch,
        &DocSpec {
            nonce: None,
            ..spec(&ud)
        },
    );
    assert!(matches!(
        v.verify(&no_nonce, &request(NOW)),
        Err(VerifyError::NonceMismatch)
    ));
    let no_ud = signed_doc(
        &ch,
        &DocSpec {
            user_data: None,
            ..spec(&ud)
        },
    );
    assert!(matches!(
        v.verify(&no_ud, &request(NOW)),
        Err(VerifyError::UserDataMismatch)
    ));
    let no_pk = signed_doc(
        &ch,
        &DocSpec {
            public_key: None,
            ..spec(&ud)
        },
    );
    assert!(matches!(
        v.verify(&no_pk, &request(NOW)),
        Err(VerifyError::MissingPublicKey)
    ));
    let mut d = support::doc(&ch, &spec(&ud));
    d.pcrs.remove(&0);
    let no_pcr0 = sign(&d.to_cbor().unwrap(), &ch.leaf.key);
    assert!(matches!(
        v.verify(&no_pcr0, &request(NOW)),
        Err(VerifyError::Pcr0Missing)
    ));
}

#[test]
fn tampered_payload_or_foreign_signer_fails_signature() {
    let ch = chain("sig");
    let ud = user_data();
    let v = verifier(&ch);

    // Sign a payload with a key that is not the leaf's key.
    let payload = support::doc(&ch, &spec(&ud)).to_cbor().unwrap();
    let forged = sign(&payload, &p384_key());
    assert!(matches!(
        v.verify(&forged, &request(NOW)),
        Err(VerifyError::SignatureInvalid)
    ));

    // Re-sign a modified payload (public key swapped) with the intermediate key:
    // the chain still verifies, but the COSE signature must not.
    let mut d = support::doc(&ch, &spec(&ud));
    d.public_key = Some(ByteBuf::from(vec![0xEE; 32]));
    let resigned = sign(&d.to_cbor().unwrap(), &ch.intermediate.key);
    assert!(matches!(
        v.verify(&resigned, &request(NOW)),
        Err(VerifyError::SignatureInvalid)
    ));

    // Flip a byte inside the payload of a genuine document: the CBOR still
    // parses for most positions, and the signature must fail; otherwise the
    // envelope/payload parse must fail. Never success.
    let good = signed_doc(&ch, &spec(&ud));
    let marker = b"i-test-enc0";
    let pos = good
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap();
    let mut tampered = good.clone();
    tampered[pos] ^= 0x01;
    let err = v.verify(&tampered, &request(NOW)).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::SignatureInvalid | VerifyError::Cose(_) | VerifyError::Payload(_)
        ),
        "{err}"
    );
    // Flip the last byte (inside the signature).
    let mut bad_sig = good;
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0x01;
    assert!(matches!(
        v.verify(&bad_sig, &request(NOW)),
        Err(VerifyError::SignatureInvalid)
    ));
}

#[test]
fn untrusted_root_and_broken_chains_are_rejected() {
    let ch = chain("a");
    let other = chain("b");
    let ud = user_data();

    // A perfectly valid document from another CA.
    let foreign = signed_doc(&other, &spec(&ud));
    assert!(matches!(
        verifier(&ch).verify(&foreign, &request(NOW)),
        Err(VerifyError::UntrustedRoot)
    ));

    // Forged chain: the real AWS root in cabundle[0], but our intermediate below it.
    let aws = AttestationVerifier::with_aws_root()
        .unwrap()
        .expect_pcr0(PCR0.to_vec());
    let mut d = support::doc(&ch, &spec(&ud));
    d.cabundle[0] = ByteBuf::from(aws_nitro_root_g1_der().unwrap());
    let forged = sign(&d.to_cbor().unwrap(), &ch.leaf.key);
    let err = aws.verify(&forged, &request(NOW)).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::ChainName { index: 1 } | VerifyError::ChainSignature { index: 1 }
        ),
        "{err}"
    );

    // Intermediate from another chain under our root: name mismatch.
    let mut d = support::doc(&ch, &spec(&ud));
    d.cabundle[1] = ByteBuf::from(other.intermediate.der());
    let mixed = sign(&d.to_cbor().unwrap(), &ch.leaf.key);
    assert!(matches!(
        verifier(&ch).verify(&mixed, &request(NOW)),
        Err(VerifyError::ChainName { index: 1 })
    ));

    // Intermediate with the right names but signed by the wrong key.
    let rogue_root = make_cert(
        &CertSpec {
            cn: "a-root",
            issuer: None,
            ca: true,
            not_before: NOW - 3600,
            not_after: NOW + 3600,
            serial: 77,
        },
        p384_key(),
    );
    let rogue_intermediate = make_cert(
        &CertSpec {
            cn: "a-intermediate",
            issuer: Some(&rogue_root),
            ca: true,
            not_before: NOW - 3600,
            not_after: NOW + 3600,
            serial: 78,
        },
        p384_key(),
    );
    let mut d = support::doc(&ch, &spec(&ud));
    d.cabundle[1] = ByteBuf::from(rogue_intermediate.der());
    let rogue_leaf = make_cert(
        &CertSpec {
            cn: "a-leaf",
            issuer: Some(&rogue_intermediate),
            ca: false,
            not_before: NOW - 60,
            not_after: NOW + 3600,
            serial: 79,
        },
        p384_key(),
    );
    d.certificate = ByteBuf::from(rogue_leaf.der());
    let rogue = sign(&d.to_cbor().unwrap(), &rogue_leaf.key);
    assert!(matches!(
        verifier(&ch).verify(&rogue, &request(NOW)),
        Err(VerifyError::ChainSignature { index: 1 })
    ));

    // Empty cabundle.
    let mut d = support::doc(&ch, &spec(&ud));
    d.cabundle.clear();
    let empty = sign(&d.to_cbor().unwrap(), &ch.leaf.key);
    assert!(matches!(
        verifier(&ch).verify(&empty, &request(NOW)),
        Err(VerifyError::EmptyChain)
    ));

    // Leaf used as an intermediate (not a CA).
    let mut d = support::doc(&ch, &spec(&ud));
    d.cabundle.push(ByteBuf::from(ch.leaf.der()));
    let leaf2 = make_cert(
        &CertSpec {
            cn: "leaf2",
            issuer: Some(&ch.leaf),
            ca: false,
            not_before: NOW - 60,
            not_after: NOW + 3600,
            serial: 80,
        },
        p384_key(),
    );
    d.certificate = ByteBuf::from(leaf2.der());
    let not_ca = sign(&d.to_cbor().unwrap(), &leaf2.key);
    assert!(matches!(
        verifier(&ch).verify(&not_ca, &request(NOW)),
        Err(VerifyError::NotCa { index: 2 })
    ));

    // Malformed certificate bytes.
    let mut d = support::doc(&ch, &spec(&ud));
    d.certificate = ByteBuf::from(vec![0x30, 0x03, 0x02, 0x01]);
    let malformed = sign(&d.to_cbor().unwrap(), &ch.leaf.key);
    assert!(matches!(
        verifier(&ch).verify(&malformed, &request(NOW)),
        Err(VerifyError::Certificate { index: 2, .. })
    ));
}

#[test]
fn validity_is_checked_at_the_given_time() {
    let ch = chain("time");
    let ud = user_data();
    let doc = signed_doc(&ch, &spec(&ud));
    let v = verifier(&ch);
    assert!(v.verify(&doc, &request(NOW)).is_ok());
    // Leaf lives 3 hours: one day later it is expired (index 2 = leaf).
    assert!(matches!(
        v.verify(&doc, &request(NOW + 86_400)),
        Err(VerifyError::NotValidAt { index: 2, .. })
    ));
    // Two hours before NOW the intermediate and leaf are not yet valid.
    assert!(matches!(
        v.verify(&doc, &request(NOW - 7200)),
        Err(VerifyError::NotValidAt { index: 1, .. })
    ));
    // Far in the future everything including the root is expired.
    assert!(matches!(
        v.verify(&doc, &request(NOW + 40 * 365 * 86_400)),
        Err(VerifyError::NotValidAt { index: 0, .. })
    ));
}

#[test]
fn non_p384_leaf_and_wrong_digest_are_rejected() {
    let ch = chain("alg");
    let ud = user_data();

    // ES256 leaf (P-256) signed by the P-384 intermediate: chain ok, key rejected.
    let p256_leaf = make_cert(
        &CertSpec {
            cn: "p256-leaf",
            issuer: Some(&ch.intermediate),
            ca: false,
            not_before: NOW - 60,
            not_after: NOW + 3600,
            serial: 11,
        },
        p256_key(),
    );
    let mut d = support::doc(&ch, &spec(&ud));
    d.certificate = ByteBuf::from(p256_leaf.der());
    let doc = sign(&d.to_cbor().unwrap(), &p256_leaf.key);
    assert!(matches!(
        verifier(&ch).verify(&doc, &request(NOW)),
        Err(VerifyError::LeafKeyNotP384)
    ));

    // Digest other than SHA384.
    let mut d = support::doc(&ch, &spec(&ud));
    d.digest = pt_tee::attestation::Digest::Sha256;
    let doc = sign(&d.to_cbor().unwrap(), &ch.leaf.key);
    assert!(matches!(
        verifier(&ch).verify(&doc, &request(NOW)),
        Err(VerifyError::UnsupportedDigest(_))
    ));
}

#[test]
fn cose_payload_must_be_an_attestation_doc() {
    let ch = chain("payload");
    let v = verifier(&ch);
    let doc = sign(b"\xa0", &ch.leaf.key);
    assert!(matches!(
        v.verify(&doc, &request(NOW)),
        Err(VerifyError::Payload(_))
    ));
    let doc = sign(&[0xFF], &ch.leaf.key);
    assert!(matches!(
        v.verify(&doc, &request(NOW)),
        Err(VerifyError::Payload(_))
    ));
    // A doc that parses is checked fully; this one has an unrelated certificate.
    let ud = user_data();
    let parsed: AttestationDoc = support::doc(&ch, &spec(&ud));
    assert_eq!(parsed.cabundle.len(), 2);
}

#[test]
fn test_ca_shape_matches_expectations() {
    let ch = chain("shape");
    let check = |c: &Cert, ca: bool| {
        let der = c.der();
        let (_, x) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert_eq!(x.is_ca(), ca);
        assert!(
            x.validity()
                .is_valid_at(x509_parser::time::ASN1Time::from_timestamp(NOW).unwrap())
        );
    };
    check(&ch.root, true);
    check(&ch.intermediate, true);
    check(&ch.leaf, false);
}
