//! Trust roots: the embedded AWS Nitro Enclaves Root G1 and PEM helpers.
//!
//! The PEM was downloaded from
//! <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
//! and is pinned by the SHA-256 fingerprint of its DER encoding, which is
//! re-checked at runtime by [`aws_nitro_root_g1_der`] and in tests.

use sha2::{Digest as _, Sha256};
use x509_parser::pem::parse_x509_pem;

use super::verify::VerifyError;

/// AWS Nitro Enclaves Root G1 certificate, PEM.
pub const AWS_NITRO_ROOT_G1_PEM: &str = include_str!("aws_nitro_root_g1.pem");

/// SHA-256 fingerprint (DER) of the AWS Nitro Enclaves Root G1, lowercase hex.
pub const AWS_NITRO_ROOT_G1_SHA256_HEX: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Decodes the first PEM block of `pem` to DER.
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let (_, block) = parse_x509_pem(pem).map_err(|e| VerifyError::RootPem(e.to_string()))?;
    if block.label != "CERTIFICATE" {
        return Err(VerifyError::RootPem(format!(
            "expected a CERTIFICATE block, found {}",
            block.label
        )));
    }
    Ok(block.contents)
}

/// DER of the embedded AWS root, after re-checking its pinned fingerprint.
pub fn aws_nitro_root_g1_der() -> Result<Vec<u8>, VerifyError> {
    let der = pem_to_der(AWS_NITRO_ROOT_G1_PEM.as_bytes())?;
    let actual = sha256_hex(&der);
    if actual != AWS_NITRO_ROOT_G1_SHA256_HEX {
        return Err(VerifyError::RootFingerprint {
            expected: AWS_NITRO_ROOT_G1_SHA256_HEX.to_owned(),
            actual,
        });
    }
    Ok(der)
}

#[cfg(test)]
mod tests {
    use x509_parser::parse_x509_certificate;

    use super::*;

    #[test]
    fn embedded_root_matches_pinned_fingerprint() {
        let der = pem_to_der(AWS_NITRO_ROOT_G1_PEM.as_bytes()).unwrap();
        assert_eq!(sha256_hex(&der), AWS_NITRO_ROOT_G1_SHA256_HEX);
        assert_eq!(aws_nitro_root_g1_der().unwrap(), der);
    }

    #[test]
    fn embedded_root_is_a_self_signed_p384_ca_valid_until_2049() {
        let der = aws_nitro_root_g1_der().unwrap();
        let (rem, cert) = parse_x509_certificate(&der).unwrap();
        assert!(rem.is_empty());
        assert!(cert.is_ca());
        assert_eq!(cert.subject(), cert.issuer());
        cert.verify_signature(None).unwrap();
        assert!(cert.subject().to_string().contains("aws.nitro-enclaves"));
        // Not before 2019-10-28, not after 2049-10-28 (UTC).
        assert_eq!(cert.validity().not_before.timestamp(), 1_572_269_285);
        assert_eq!(cert.validity().not_after.timestamp(), 2_519_044_085);
        assert!(cert.validity().is_valid());
    }

    #[test]
    fn pem_helpers_reject_garbage() {
        assert!(matches!(
            pem_to_der(b"not pem"),
            Err(VerifyError::RootPem(_))
        ));
        let key_block = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(matches!(
            pem_to_der(key_block),
            Err(VerifyError::RootPem(_))
        ));
    }
}
