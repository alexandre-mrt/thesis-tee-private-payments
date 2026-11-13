//! pt-tee: attestation, secure channel and framing for platypus-tee.
//!
//! Implements SPEC.md section 7 (enclave protocol) in a generic way: this
//! crate knows nothing about `pt-core`, arkworks or the Platypus statements.
//! It provides
//!
//! - [`framing`]: length-prefixed CBOR frames over any `AsyncRead`/`AsyncWrite`
//!   (4-byte big-endian length, body capped at [`MAX_FRAME_LEN`]);
//! - [`transport`]: TCP and vsock listeners and connectors behind one
//!   [`transport::Endpoint`] type (vsock only on Linux);
//! - [`attestation`]: the [`attestation::AttestationProvider`] trait with the
//!   real NSM provider (Linux only) and a clearly marked mock, plus the
//!   [`attestation::AttestationVerifier`] that checks a COSE_Sign1 Nitro
//!   attestation document against an injectable root (default: embedded AWS
//!   Nitro Enclaves Root G1);
//! - [`channel`]: X25519 + HKDF-SHA256 + ChaCha20-Poly1305 request/response
//!   sealing with direction-separated keys.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod channel;
pub mod framing;
pub mod transport;

/// Protocol tag. Prefix of the attestation `user_data` and of the HKDF infos.
pub const PROTOCOL_TAG: &[u8] = b"platypus-tee/v1";

/// HKDF info for the client-to-enclave (request) key.
pub const HKDF_INFO_REQ: &[u8] = b"platypus-tee/v1/req";

/// HKDF info for the enclave-to-client (response) key.
pub const HKDF_INFO_RESP: &[u8] = b"platypus-tee/v1/resp";

/// Maximum frame body size: 32 MiB (SPEC section 7).
pub const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;

/// Port the enclave listens on (vsock in Nitro, TCP loopback with `--mock`).
pub const DEFAULT_ENCLAVE_PORT: u32 = 5005;

/// Default enclave CID used by `pt-host`.
pub const DEFAULT_ENCLAVE_CID: u32 = 16;

/// Default `pt-host` TCP listen address.
pub const DEFAULT_HOST_LISTEN: &str = "0.0.0.0:8443";

/// TCP address the enclave binary listens on in `--mock` mode.
pub const MOCK_ENCLAVE_LISTEN: &str = "127.0.0.1:5005";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_infos_are_namespaced_by_protocol_tag() {
        assert!(HKDF_INFO_REQ.starts_with(PROTOCOL_TAG));
        assert!(HKDF_INFO_RESP.starts_with(PROTOCOL_TAG));
        assert_ne!(HKDF_INFO_REQ, HKDF_INFO_RESP);
        assert_eq!(HKDF_INFO_REQ, b"platypus-tee/v1/req");
        assert_eq!(HKDF_INFO_RESP, b"platypus-tee/v1/resp");
    }

    #[test]
    fn frame_cap_is_32_mib() {
        assert_eq!(MAX_FRAME_LEN, 33_554_432);
    }
}
