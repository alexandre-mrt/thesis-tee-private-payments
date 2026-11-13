//! Client-side verification of Nitro attestation documents (SPEC section 7).
//!
//! Checks, in order: mock handling, presence of a non-zero PCR0 pin (a signed
//! document is never accepted without one), COSE_Sign1 parsing, payload
//! parsing, certificate chain (byte-equal trusted root, issuer/subject names,
//! CA bits, signatures, validity at the given time), ES384 COSE signature under
//! the leaf key, PCR0, nonce, `user_data = prefix || digest`, presence of the
//! attested public key.

use std::collections::BTreeMap;

use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_cose::crypto::Openssl;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;
use x509_parser::time::ASN1Time;

use super::doc::{AttestationDoc, Digest};
use super::mock::{MockAttestation, is_mock};
use super::root::{aws_nitro_root_g1_der, pem_to_der};

/// PCR index of the enclave image measurement.
pub const PCR0_INDEX: usize = 0;

/// Verification failures. Messages carry no attested payload bytes beyond PCR values.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("attestation document is a mock document and allow_mock is false")]
    MockRejected,
    #[error("malformed mock attestation document: {0}")]
    MockMalformed(String),
    #[error("root certificate PEM is malformed: {0}")]
    RootPem(String),
    #[error("embedded AWS root fingerprint mismatch: expected {expected}, got {actual}")]
    RootFingerprint { expected: String, actual: String },
    #[error("trusted root certificate is malformed or not self-signed: {0}")]
    RootInvalid(String),
    #[error("COSE_Sign1 envelope is malformed: {0}")]
    Cose(String),
    #[error("attestation payload is not a valid attestation document: {0}")]
    Payload(String),
    #[error("unsupported PCR digest {0:?}, expected SHA384")]
    UnsupportedDigest(Digest),
    #[error("certificate chain is empty")]
    EmptyChain,
    #[error("certificate {index} in the chain is malformed: {reason}")]
    Certificate { index: usize, reason: String },
    #[error("chain root does not match the trusted root certificate")]
    UntrustedRoot,
    #[error("certificate {index} issuer does not match its parent subject")]
    ChainName { index: usize },
    #[error("certificate {index} is not a CA certificate")]
    NotCa { index: usize },
    #[error("certificate {index} is not signed by its issuer")]
    ChainSignature { index: usize },
    #[error("certificate {index} is not valid at unix time {now}")]
    NotValidAt { index: usize, now: i64 },
    #[error("invalid verification time {0}")]
    InvalidTime(i64),
    #[error("leaf certificate key is not an ECDSA P-384 key")]
    LeafKeyNotP384,
    #[error("COSE signature does not verify under the leaf certificate")]
    SignatureInvalid,
    #[error("PCR0 is missing from the attestation document")]
    Pcr0Missing,
    #[error(
        "no expected PCR0 is pinned: a signed document from any enclave image under the trusted root would pass"
    )]
    Pcr0NotPinned,
    #[error(
        "expected PCR0 is all zeros (the measurement of a debug-mode enclave); refusing to pin it"
    )]
    Pcr0Zero,
    #[error("PCR0 mismatch: expected {expected}, attested {actual}")]
    Pcr0Mismatch { expected: String, actual: String },
    #[error("invalid PCR0 hex: {0}")]
    Pcr0Hex(String),
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("user_data mismatch")]
    UserDataMismatch,
    #[error("attestation document carries no public key")]
    MissingPublicKey,
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

/// What the client expects to find in the document.
#[derive(Debug, Clone, Copy)]
pub struct VerifyRequest<'a> {
    /// The nonce the client sent in `Request::Attest`.
    pub nonce: &'a [u8],
    /// Expected `user_data` prefix (normally [`crate::PROTOCOL_TAG`]).
    pub user_data_prefix: &'a [u8],
    /// Expected digest following the prefix (sha256 of the keys manifest).
    pub user_data_digest: &'a [u8],
    /// Verification time, seconds since the Unix epoch.
    pub now_unix_secs: i64,
}

/// Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedEnclave {
    /// The public key bound into the document (enclave X25519 key).
    pub public_key: Vec<u8>,
    /// All PCRs of the document (mock: only PCR0).
    pub pcrs: BTreeMap<usize, Vec<u8>>,
    /// NSM module id (mock: empty).
    pub module_id: String,
    /// Document creation time, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// True if the document was a mock accepted because `allow_mock` was set.
    pub mock: bool,
}

/// Verifier with an injectable root, an expected PCR0 and a mock switch.
///
/// The PCR0 pin is mandatory for signed documents: without it every enclave
/// image under the trusted root would pass (any AWS account, a modified EIF,
/// or the genuine EIF in debug mode). Mock documents carry no signature, so
/// their PCR0 is only compared when a pin is set (a local test hook).
#[derive(Debug, Clone)]
pub struct AttestationVerifier {
    root_der: Vec<u8>,
    expected_pcr0: Option<Vec<u8>>,
    allow_mock: bool,
}

impl AttestationVerifier {
    /// Verifier trusting the embedded AWS Nitro Enclaves Root G1.
    pub fn with_aws_root() -> Result<Self, VerifyError> {
        Self::with_root_der(aws_nitro_root_g1_der()?)
    }

    /// Verifier trusting a PEM root (tests, private CAs).
    pub fn with_root_pem(pem: &[u8]) -> Result<Self, VerifyError> {
        Self::with_root_der(pem_to_der(pem)?)
    }

    /// Verifier trusting a DER root. The root must parse, be a CA and be self-signed.
    pub fn with_root_der(root_der: Vec<u8>) -> Result<Self, VerifyError> {
        let (_, root) = parse_x509_certificate(&root_der)
            .map_err(|e| VerifyError::RootInvalid(e.to_string()))?;
        if !root.is_ca() {
            return Err(VerifyError::RootInvalid("not a CA".to_owned()));
        }
        root.verify_signature(None)
            .map_err(|e| VerifyError::RootInvalid(format!("self-signature: {e}")))?;
        Ok(Self {
            root_der,
            expected_pcr0: None,
            allow_mock: false,
        })
    }

    /// Requires PCR0 to equal `pcr0`. Mandatory for signed documents: without
    /// it [`Self::verify`] fails with [`VerifyError::Pcr0NotPinned`]; an
    /// all-zero value (debug mode) fails with [`VerifyError::Pcr0Zero`].
    pub fn expect_pcr0(mut self, pcr0: Vec<u8>) -> Self {
        self.expected_pcr0 = Some(pcr0);
        self
    }

    /// Same as [`Self::expect_pcr0`] from the hex printed by `nitro-cli build-enclave`.
    pub fn expect_pcr0_hex(self, pcr0_hex: &str) -> Result<Self, VerifyError> {
        let pcr0 = hex::decode(pcr0_hex.trim()).map_err(|e| VerifyError::Pcr0Hex(e.to_string()))?;
        Ok(self.expect_pcr0(pcr0))
    }

    /// Accept mock documents (local demo only).
    pub fn allow_mock(mut self, allow: bool) -> Self {
        self.allow_mock = allow;
        self
    }

    /// The trusted root, DER.
    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// The pinned PCR0, if any.
    pub fn expected_pcr0(&self) -> Option<&[u8]> {
        self.expected_pcr0.as_deref()
    }

    /// A signed document needs a pinned, non-zero PCR0 before anything else is
    /// looked at: without a pin the signature only proves "some Nitro enclave",
    /// and the all-zero value is what every debug-mode enclave reports.
    fn require_pin(&self) -> Result<&[u8], VerifyError> {
        let expected = self
            .expected_pcr0
            .as_deref()
            .ok_or(VerifyError::Pcr0NotPinned)?;
        if expected.iter().all(|b| *b == 0) {
            return Err(VerifyError::Pcr0Zero);
        }
        Ok(expected)
    }

    /// Verifies `doc` against `request` and returns the attested public key.
    pub fn verify(
        &self,
        doc: &[u8],
        request: &VerifyRequest<'_>,
    ) -> Result<AttestedEnclave, VerifyError> {
        if is_mock(doc) {
            return self.verify_mock(doc, request);
        }
        self.require_pin()?;
        let cose = CoseSign1::from_bytes(doc).map_err(|e| VerifyError::Cose(e.to_string()))?;
        let payload = cose
            .get_payload::<Openssl>(None)
            .map_err(|e| VerifyError::Cose(e.to_string()))?;
        let parsed =
            AttestationDoc::from_cbor(&payload).map_err(|e| VerifyError::Payload(e.to_string()))?;
        if parsed.digest != Digest::Sha384 {
            return Err(VerifyError::UnsupportedDigest(parsed.digest));
        }
        self.verify_chain(&parsed, request.now_unix_secs)?;
        verify_cose_signature(&cose, &parsed.certificate, parsed.cabundle.len())?;
        let pcrs = self.check_pcrs(parsed.pcrs.iter().map(|(k, v)| (*k, v.to_vec())))?;
        check_binding(
            parsed.nonce.as_ref().map(|b| b.as_slice()),
            parsed.user_data.as_ref().map(|b| b.as_slice()),
            request,
        )?;
        let public_key = parsed
            .public_key
            .filter(|pk| !pk.is_empty())
            .ok_or(VerifyError::MissingPublicKey)?;
        Ok(AttestedEnclave {
            public_key: public_key.into_vec(),
            pcrs,
            module_id: parsed.module_id,
            timestamp_ms: parsed.timestamp,
            mock: false,
        })
    }

    fn verify_mock(
        &self,
        doc: &[u8],
        request: &VerifyRequest<'_>,
    ) -> Result<AttestedEnclave, VerifyError> {
        if !self.allow_mock {
            return Err(VerifyError::MockRejected);
        }
        let mock = MockAttestation::decode(doc).map_err(VerifyError::MockMalformed)?;
        let pcrs = self.check_pcrs(std::iter::once((PCR0_INDEX, mock.pcr0.into_vec())))?;
        check_binding(
            Some(mock.nonce.as_slice()),
            Some(mock.user_data.as_slice()),
            request,
        )?;
        if mock.public_key.is_empty() {
            return Err(VerifyError::MissingPublicKey);
        }
        Ok(AttestedEnclave {
            public_key: mock.public_key.into_vec(),
            pcrs,
            module_id: String::new(),
            timestamp_ms: mock.timestamp_ms,
            mock: true,
        })
    }

    /// Chain = cabundle (root first) followed by the leaf. Every link is checked.
    fn verify_chain(&self, doc: &AttestationDoc, now: i64) -> Result<(), VerifyError> {
        let now_t = ASN1Time::from_timestamp(now).map_err(|_| VerifyError::InvalidTime(now))?;
        let root = doc.cabundle.first().ok_or(VerifyError::EmptyChain)?;
        if root.as_slice() != self.root_der.as_slice() {
            return Err(VerifyError::UntrustedRoot);
        }
        let ders: Vec<&[u8]> = doc
            .cabundle
            .iter()
            .map(|c| c.as_slice())
            .chain(std::iter::once(doc.certificate.as_slice()))
            .collect();
        let certs = ders
            .iter()
            .enumerate()
            .map(|(index, der)| parse_cert(index, der))
            .collect::<Result<Vec<_>, _>>()?;
        let last = certs.len() - 1;
        for (index, cert) in certs.iter().enumerate() {
            if !cert.validity().is_valid_at(now_t) {
                return Err(VerifyError::NotValidAt { index, now });
            }
            if index < last && !cert.is_ca() {
                return Err(VerifyError::NotCa { index });
            }
            let parent = if index == 0 { cert } else { &certs[index - 1] };
            if cert.issuer().as_raw() != parent.subject().as_raw() {
                return Err(VerifyError::ChainName { index });
            }
            cert.verify_signature(Some(parent.public_key()))
                .map_err(|_| VerifyError::ChainSignature { index })?;
        }
        Ok(())
    }

    fn check_pcrs(
        &self,
        pcrs: impl Iterator<Item = (usize, Vec<u8>)>,
    ) -> Result<BTreeMap<usize, Vec<u8>>, VerifyError> {
        let pcrs: BTreeMap<usize, Vec<u8>> = pcrs.collect();
        let pcr0 = pcrs.get(&PCR0_INDEX).ok_or(VerifyError::Pcr0Missing)?;
        if let Some(expected) = &self.expected_pcr0
            && expected != pcr0
        {
            return Err(VerifyError::Pcr0Mismatch {
                expected: hex::encode(expected),
                actual: hex::encode(pcr0),
            });
        }
        Ok(pcrs)
    }
}

fn parse_cert(index: usize, der: &[u8]) -> Result<X509Certificate<'_>, VerifyError> {
    let (rem, cert) = parse_x509_certificate(der).map_err(|e| VerifyError::Certificate {
        index,
        reason: e.to_string(),
    })?;
    if !rem.is_empty() {
        return Err(VerifyError::Certificate {
            index,
            reason: format!("{} trailing byte(s)", rem.len()),
        });
    }
    Ok(cert)
}

/// `index` is the leaf's position in the chain (`cabundle.len()`), for error reporting.
fn leaf_public_key(leaf_der: &[u8], index: usize) -> Result<PKey<Public>, VerifyError> {
    let (_, leaf) = parse_x509_certificate(leaf_der).map_err(|e| VerifyError::Certificate {
        index,
        reason: e.to_string(),
    })?;
    let pkey = PKey::public_key_from_der(leaf.public_key().raw)?;
    let ec = pkey.ec_key().map_err(|_| VerifyError::LeafKeyNotP384)?;
    if ec.group().curve_name() != Some(Nid::SECP384R1) {
        return Err(VerifyError::LeafKeyNotP384);
    }
    Ok(pkey)
}

/// ES384 over the COSE Sig_structure with the leaf certificate key.
fn verify_cose_signature(
    cose: &CoseSign1,
    leaf_der: &[u8],
    leaf_index: usize,
) -> Result<(), VerifyError> {
    let pkey = leaf_public_key(leaf_der, leaf_index)?;
    let valid = cose
        .verify_signature::<Openssl>(&pkey)
        .map_err(|e| VerifyError::Cose(e.to_string()))?;
    if !valid {
        return Err(VerifyError::SignatureInvalid);
    }
    Ok(())
}

fn check_binding(
    nonce: Option<&[u8]>,
    user_data: Option<&[u8]>,
    request: &VerifyRequest<'_>,
) -> Result<(), VerifyError> {
    if nonce != Some(request.nonce) {
        return Err(VerifyError::NonceMismatch);
    }
    let expected_len = request.user_data_prefix.len() + request.user_data_digest.len();
    let Some(user_data) = user_data else {
        return Err(VerifyError::UserDataMismatch);
    };
    if user_data.len() != expected_len
        || !user_data.starts_with(request.user_data_prefix)
        || &user_data[request.user_data_prefix.len()..] != request.user_data_digest
    {
        return Err(VerifyError::UserDataMismatch);
    }
    Ok(())
}
