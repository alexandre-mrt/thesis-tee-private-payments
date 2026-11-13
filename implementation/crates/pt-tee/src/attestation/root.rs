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
