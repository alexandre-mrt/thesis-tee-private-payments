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
    #[error("proof refused: {what}")]
    BadProof { what: &'static str },
    #[error("log entry {seq} does not extend the chain head before it")]
    BrokenChain { seq: u64 },
    #[error("log entry: {what} is malformed")]
    MalformedEntry { what: &'static str },
    #[error("memo of {len} bytes exceeds the limit of {max}")]
    MemoTooLong { len: usize, max: usize },
}
