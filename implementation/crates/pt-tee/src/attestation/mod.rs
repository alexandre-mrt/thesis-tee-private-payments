//! Attestation: providers (NSM, mock) and the verifier (SPEC section 7).
//!
//! The enclave calls an [`AttestationProvider`] with its X25519 public key,
//! the client nonce and `user_data = "platypus-tee/v1" || sha256(manifest)`.
//! The client runs [`AttestationVerifier`] on the returned document and
//! obtains the attested public key.

pub mod doc;

#[cfg(target_os = "linux")]
pub mod nsm;

pub use doc::{AttestationDoc, Digest};
#[cfg(target_os = "linux")]
pub use nsm::NsmProvider;

use crate::PROTOCOL_TAG;

/// Provider-side errors.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// `/dev/nsm` could not be opened (not inside a Nitro Enclave).
    #[error("NSM device unavailable: {0}")]
    DeviceUnavailable(String),
    /// The NSM answered with an error code.
    #[error("NSM returned an error: {0}")]
    Nsm(String),
    /// The NSM answered with a response of the wrong kind.
    #[error("NSM returned an unexpected response kind")]
    UnexpectedResponse,
    /// The system clock is before the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    Clock,
    /// Encoding the (mock) document failed.
    #[error("encoding the attestation document failed: {0}")]
    Encode(String),
}

/// Values bound into an attestation document.
#[derive(Debug, Clone, Copy)]
pub struct AttestationInputs<'a> {
    /// Client-chosen nonce (freshness).
    pub nonce: &'a [u8],
    /// Protocol tag followed by the keys manifest digest, see [`user_data_for`].
    pub user_data: &'a [u8],
    /// The enclave's X25519 public key.
    pub public_key: &'a [u8],
}

/// Produces attestation documents.
pub trait AttestationProvider: Send + Sync {
    /// Returns the serialized attestation document for `inputs`.
    fn attest(&self, inputs: &AttestationInputs<'_>) -> Result<Vec<u8>, AttestationError>;
}

/// `user_data = PROTOCOL_TAG || digest`.
pub fn user_data_for(manifest_digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROTOCOL_TAG.len() + manifest_digest.len());
    out.extend_from_slice(PROTOCOL_TAG);
    out.extend_from_slice(manifest_digest);
    out
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_millis() -> Result<u64, AttestationError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AttestationError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| AttestationError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_data_layout() {
        let digest = [0xABu8; 32];
        let ud = user_data_for(&digest);
        assert_eq!(&ud[..PROTOCOL_TAG.len()], PROTOCOL_TAG);
        assert_eq!(&ud[PROTOCOL_TAG.len()..], &digest);
        assert_eq!(ud.len(), 15 + 32);
    }

    #[test]
    fn clock_is_after_epoch() {
        assert!(now_millis().unwrap() > 1_600_000_000_000);
    }
}
