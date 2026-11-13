use pt_tee::framing::FrameError;
use pt_tee::transport::TransportError;
use tv_core::CoreError;

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("enclave unavailable: {0}")]
    Unavailable(String),
    #[error("the enclave did not answer within {after:?}")]
    TimedOut { after: std::time::Duration },
}

impl BankError {
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::File { .. } | Self::Link(_) | Self::Transport(_) | Self::Frame(_)
        )
    }

    pub fn file(path: &std::path::Path) -> impl FnOnce(std::io::Error) -> Self + '_ {
        move |source| Self::File {
            path: path.display().to_string(),
            source,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BankError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("log JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Link(#[from] LinkError),
    #[error(transparent)]
    Client(#[from] tv_client::ClientError),
    #[error("{path}: {source}")]
    File {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "invalid --enclave {input}: {reason}; expected tcp://HOST:PORT with HOST an IP address or a host name, or vsock://CID:PORT"
    )]
    EnclaveAddress { input: String, reason: String },
    #[error("key file: {0}")]
    KeyFile(String),
    #[error("{path} is locked by another bank process")]
    Locked { path: String },
    #[error("log line {line} is corrupt: {reason}")]
    Corrupt { line: usize, reason: String },
    #[error("issuance ledger line {line} is corrupt: {reason}")]
    LedgerCorrupt { line: usize, reason: String },
    #[error("the log store is poisoned after a failed append; restart the bank to replay the log")]
    StorePoisoned,
    #[error("the log write of this operation was rolled back; it is not settled")]
    RolledBack,
    #[error("a log flush is already in progress")]
    FlushInProgress,
    #[error("attestation rejected: {0}")]
    Attestation(String),
    #[error("the enclave manifest names other bank keys than this bank")]
    ManifestKeyMismatch,
    #[error("no enclave is registered; run register-enclave first")]
    NotRegistered,
    #[error("--allow-mock and --pcr0 are mutually exclusive")]
    MockWithPin,
    #[error("mock attestation is only acceptable on a loopback enclave address")]
    MockRequiresLoopback,
    #[error("a PCR0 pin is required unless --allow-mock is given")]
    Pcr0Required,
    #[error("registration is only accepted from loopback peers")]
    Forbidden,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("{var}=1 is only honoured with --dev")]
    CrashInjectionRequiresDev { var: &'static str },
    #[error("the bank wallet refused: {0}")]
    Wallet(String),
    #[error("the request asks for {requested} but --amount states {agreed}; nothing was issued")]
    IssueAmount { agreed: u64, requested: u64 },
    #[error("data dir {path} already exists and is not empty; init needs a fresh directory")]
    DataDirNotEmpty { path: String },
    #[error("data dir {path} has no name to stage an init next to")]
    DataDirName { path: String },
    #[error(
        "data dir {path} is incomplete: {missing} is missing; run tv-bank init on a fresh directory"
    )]
    DataDirIncomplete { path: String, missing: &'static str },
}
