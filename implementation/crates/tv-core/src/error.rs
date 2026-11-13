#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("CBOR encoding failed: {0}")]
    Encode(String),
    #[error("CBOR decoding failed: {0}")]
    Decode(String),
    #[error("invalid {what}")]
    InvalidKeyMaterial { what: &'static str },
    #[error("signature does not verify")]
    BadSignature,
    #[error("key derivation failed")]
    Derivation,
}
