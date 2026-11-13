//! Test support: a generated P-384 CA chain shaped like the Nitro PKI
//! (root -> intermediate -> leaf) and COSE_Sign1 signing of attestation
//! payloads with the leaf key, built with the `openssl` crate that
//! `aws-nitro-enclaves-cose` already pulls in.

use std::collections::BTreeMap;

use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_cose::crypto::Openssl;
use aws_nitro_enclaves_cose::header_map::HeaderMap;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509, X509NameBuilder};
use pt_tee::attestation::{AttestationDoc, Digest};
use serde_bytes::ByteBuf;

/// Fixed "now" used by every chain test (2023-11-14T22:13:20Z).
pub const NOW: i64 = 1_700_000_000;
const HOUR: i64 = 3600;
const YEAR: i64 = 365 * 24 * HOUR;

pub struct Cert {
    pub x509: X509,
    pub key: PKey<Private>,
}

impl Cert {
    pub fn der(&self) -> Vec<u8> {
        self.x509.to_der().expect("DER")
    }
}

pub struct Chain {
    pub root: Cert,
    pub intermediate: Cert,
    pub leaf: Cert,
}

pub fn p384_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("group");
    PKey::from_ec_key(EcKey::generate(&group).expect("keygen")).expect("pkey")
}

pub fn p256_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("group");
    PKey::from_ec_key(EcKey::generate(&group).expect("keygen")).expect("pkey")
}

pub struct CertSpec<'a> {
    pub cn: &'a str,
    pub issuer: Option<&'a Cert>,
    pub ca: bool,
    pub not_before: i64,
    pub not_after: i64,
    pub serial: u32,
}

pub fn make_cert(spec: &CertSpec<'_>, key: PKey<Private>) -> Cert {
    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_nid(Nid::COMMONNAME, spec.cn)
        .expect("cn");
    let name = name.build();

    let mut b = X509::builder().expect("builder");
    b.set_version(2).expect("v3");
    let serial = BigNum::from_u32(spec.serial).expect("bn");
    b.set_serial_number(&Asn1Integer::from_bn(&serial).expect("serial"))
        .expect("serial");
    b.set_subject_name(&name).expect("subject");
    match spec.issuer {
        Some(issuer) => b.set_issuer_name(issuer.x509.subject_name()),
        None => b.set_issuer_name(&name),
    }
    .expect("issuer");
    b.set_pubkey(&key).expect("pubkey");
    b.set_not_before(&Asn1Time::from_unix(spec.not_before).expect("nb"))
        .expect("nb");
    b.set_not_after(&Asn1Time::from_unix(spec.not_after).expect("na"))
        .expect("na");

    let mut bc = BasicConstraints::new();
    bc.critical();
    if spec.ca {
        bc.ca();
    }
    b.append_extension(bc.build().expect("bc")).expect("bc");
    let mut ku = KeyUsage::new();
    ku.critical();
    if spec.ca {
        ku.key_cert_sign().crl_sign();
    } else {
        ku.digital_signature();
    }
    b.append_extension(ku.build().expect("ku")).expect("ku");

    let signer = spec.issuer.map(|c| &c.key).unwrap_or(&key);
    b.sign(signer, MessageDigest::sha384()).expect("sign");
    Cert {
        x509: b.build(),
        key,
    }
}

/// Root (30 years), intermediate (1 year), leaf (3 hours), all valid at NOW.
pub fn chain(label: &str) -> Chain {
    let root = make_cert(
        &CertSpec {
            cn: &format!("{label}-root"),
            issuer: None,
            ca: true,
            not_before: NOW - YEAR,
            not_after: NOW + 30 * YEAR,
            serial: 1,
        },
        p384_key(),
    );
    let intermediate = make_cert(
        &CertSpec {
            cn: &format!("{label}-intermediate"),
            issuer: Some(&root),
            ca: true,
            not_before: NOW - HOUR,
            not_after: NOW + YEAR,
            serial: 2,
        },
        p384_key(),
    );
    let leaf = make_cert(
        &CertSpec {
            cn: &format!("{label}-leaf"),
            issuer: Some(&intermediate),
            ca: false,
            not_before: NOW - HOUR,
            not_after: NOW + 3 * HOUR,
            serial: 3,
        },
        p384_key(),
    );
    Chain {
        root,
        intermediate,
        leaf,
    }
}

pub struct DocSpec<'a> {
    pub pcr0: &'a [u8],
    pub public_key: Option<&'a [u8]>,
    pub user_data: Option<&'a [u8]>,
    pub nonce: Option<&'a [u8]>,
}

/// Unsigned payload with cabundle = [root, intermediate] and certificate = leaf.
pub fn doc(chain: &Chain, spec: &DocSpec<'_>) -> AttestationDoc {
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0usize, ByteBuf::from(spec.pcr0.to_vec()));
    pcrs.insert(1usize, ByteBuf::from(vec![0x01; 48]));
    pcrs.insert(2usize, ByteBuf::from(vec![0x02; 48]));
    AttestationDoc {
        module_id: "i-test-enc0".to_owned(),
        digest: Digest::Sha384,
        timestamp: (NOW as u64) * 1000,
        pcrs,
        certificate: ByteBuf::from(chain.leaf.der()),
        cabundle: vec![
            ByteBuf::from(chain.root.der()),
            ByteBuf::from(chain.intermediate.der()),
        ],
        public_key: spec.public_key.map(|b| ByteBuf::from(b.to_vec())),
        user_data: spec.user_data.map(|b| ByteBuf::from(b.to_vec())),
        nonce: spec.nonce.map(|b| ByteBuf::from(b.to_vec())),
    }
}

/// Untagged COSE_Sign1 over the CBOR payload, like the NSM emits.
pub fn sign(payload: &[u8], key: &PKey<Private>) -> Vec<u8> {
    CoseSign1::new::<Openssl>(payload, &HeaderMap::new(), key)
        .expect("cose sign")
        .as_bytes(false)
        .expect("cose bytes")
}

pub fn signed_doc(chain: &Chain, spec: &DocSpec<'_>) -> Vec<u8> {
    let payload = doc(chain, spec).to_cbor().expect("cbor");
    sign(&payload, &chain.leaf.key)
}
