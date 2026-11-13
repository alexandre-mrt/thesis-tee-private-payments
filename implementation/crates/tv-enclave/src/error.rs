use pt_tee::framing::FrameError;
use pt_tee::transport::TransportError;

#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("NSM attestation is only available inside a Linux Nitro enclave")]
    NsmUnavailable,
    #[error("attestation provider failed: {0}")]
    Attestation(String),
    #[error("{what} is not a 32-byte hex string")]
    KeyHex { what: &'static str },
    #[error("bank key: {0}")]
    BankKey(#[from] tv_core::CoreError),
    #[error("{var}=1 is only honoured with --mock")]
    CrashInjectionRequiresMock { var: &'static str },
    #[error("{var}=1 needs a tv-enclave built with the test-hooks feature")]
    CrashInjectionNotCompiled { var: &'static str },
}
