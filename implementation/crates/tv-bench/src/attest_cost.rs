use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_cose::crypto::Openssl;
use openssl::pkey::{PKey, Public};
use pt_tee::attestation::AttestationDoc;
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;

#[derive(Debug)]
pub struct AttestCost {
    pub certificates: usize,
    pub parse: Vec<Duration>,
    pub chain: Vec<Duration>,
    pub signature: Vec<Duration>,
}

fn decode(doc: &[u8]) -> Result<(CoseSign1, AttestationDoc)> {
    let cose = CoseSign1::from_bytes(doc).context("COSE_Sign1")?;
    let payload = cose.get_payload::<Openssl>(None).context("COSE payload")?;
    let parsed = AttestationDoc::from_cbor(&payload).context("attestation payload")?;
    Ok((cose, parsed))
}

fn chain_ders(doc: &AttestationDoc) -> Vec<&[u8]> {
    doc.cabundle
        .iter()
        .map(|c| c.as_slice())
        .chain(std::iter::once(doc.certificate.as_slice()))
        .collect()
}

fn verify_chain(ders: &[&[u8]]) -> Result<()> {
    let certs = ders
        .iter()
        .map(|der| Ok(parse_x509_certificate(der).context("certificate")?.1))
        .collect::<Result<Vec<X509Certificate<'_>>>>()?;
    for (index, cert) in certs.iter().enumerate() {
        let parent = if index == 0 { cert } else { &certs[index - 1] };
        if cert.verify_signature(Some(parent.public_key())).is_err() {
            bail!("certificate {index} does not verify under its parent");
        }
    }
    Ok(())
}

fn leaf_key(leaf_der: &[u8]) -> Result<PKey<Public>> {
    let (_, leaf) = parse_x509_certificate(leaf_der).context("leaf certificate")?;
    Ok(PKey::public_key_from_der(leaf.public_key().raw)?)
}

fn verify_signature(cose: &CoseSign1, leaf_der: &[u8]) -> Result<()> {
    if !cose.verify_signature::<Openssl>(&leaf_key(leaf_der)?)? {
        bail!("COSE signature does not verify under the leaf key");
    }
    Ok(())
}

pub fn attest_cost(doc: &[u8], iterations: usize) -> Result<AttestCost> {
    let (cose, parsed) = decode(doc)?;
    let ders = chain_ders(&parsed);
    let mut out = AttestCost {
        certificates: ders.len(),
        parse: Vec::with_capacity(iterations),
        chain: Vec::with_capacity(iterations),
        signature: Vec::with_capacity(iterations),
    };
    for _ in 0..iterations {
        let start = Instant::now();
        decode(doc)?;
        out.parse.push(start.elapsed());
        let start = Instant::now();
        verify_chain(&ders)?;
        out.chain.push(start.elapsed());
        let start = Instant::now();
        verify_signature(&cose, &parsed.certificate)?;
        out.signature.push(start.elapsed());
    }
    Ok(out)
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "shared pt-tee test support, only part of it is used here"
)]
#[path = "../../pt-tee/tests/support/mod.rs"]
mod support;

#[cfg(test)]
mod tests {
    use super::attest_cost;
    use super::support::{DocSpec, chain, doc, sign, signed_doc};

    const PCR0: [u8; 48] = [7; 48];
    const PUBLIC_KEY: [u8; 32] = [1; 32];

    fn spec() -> DocSpec<'static> {
        DocSpec {
            pcr0: &PCR0,
            public_key: Some(&PUBLIC_KEY),
            user_data: None,
            nonce: None,
        }
    }

    #[test]
    fn a_nitro_shaped_document_is_timed_in_three_steps() {
        let bytes = signed_doc(&chain("bench"), &spec());
        let cost = attest_cost(&bytes, 3).unwrap();
        assert_eq!(cost.certificates, 3);
        assert_eq!(cost.parse.len(), 3);
        assert_eq!(cost.chain.len(), 3);
        assert_eq!(cost.signature.len(), 3);
    }

    #[test]
    fn a_document_signed_by_a_key_outside_its_chain_is_refused() {
        let payload = doc(&chain("bench"), &spec()).to_cbor().unwrap();
        let bytes = sign(&payload, &chain("other").leaf.key);
        let err = attest_cost(&bytes, 1).unwrap_err();
        assert!(err.to_string().contains("COSE signature"), "{err}");
    }
}
