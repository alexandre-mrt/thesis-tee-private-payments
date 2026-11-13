use pt_tee::channel::ChannelError;
use pt_tee::framing::FrameError;
use pt_tee::transport::TransportError;
use tv_core::CoreError;

use crate::wallet::Pending;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Channel(#[from] ChannelError),
    #[error("attestation rejected: {0}")]
    Attestation(String),
    #[error(
        "the attestation is {} s old, past the enclave's channel-key lifetime; ask for a fresh request or re-attest",
        age_ms / 1000
    )]
    StaleAttestation { age_ms: u128 },
    #[error("the attestation is dated {} s ahead of this clock; check the system clock", ahead_ms / 1000)]
    FutureAttestation { ahead_ms: u128 },
    #[error("{what} file {path}: {reason}")]
    File {
        what: &'static str,
        path: String,
        reason: String,
    },
    #[error("wallet {path} is in use by another process")]
    WalletLocked { path: String },
    #[error("wallet is not enrolled")]
    NotEnrolled,
    #[error("wallet is already enrolled")]
    AlreadyEnrolled,
    #[error(
        "the wallet is still on its enrolled serial pk_0, whose balance 0 is public; run `tv-cli refresh` before requesting a payment"
    )]
    EnrolledSerial,
    #[error("no pending {what} in the wallet")]
    NoPending { what: &'static str },
    #[error("a pending {what} blocks this operation; {way_out}")]
    PendingBlocks {
        what: &'static str,
        way_out: &'static str,
    },
    #[error(
        "a pending {what} is in the wallet; complete it with {completion}, run `tv-cli recover` to resync with the public log, or pass --force to abandon it and burn its serial"
    )]
    RefreshBlocked {
        what: &'static str,
        completion: &'static str,
    },
    #[error(
        "serial {serial} was already spent by another operation: this wallet is behind the public log, run `tv-cli recover`"
    )]
    Behind { serial: String },
    #[error("the request names this wallet's own current serial as payee; nothing was signed")]
    SelfPayment,
    #[error("{what} does not match the pending operation")]
    Mismatch { what: &'static str },
    #[error(
        "the request names another payee serial or amount than the pending payment; complete that payment with `tv-cli finish`, or, if the payee abandoned it, run `tv-cli refresh --force`, then `tv-cli pay` the new request"
    )]
    PayRequestMismatch,
    #[error(
        "the offer was sealed to an earlier request of this wallet; ask the payer to run `tv-cli reseal --request <latest request.json>`, then `tv-cli receive --offer` the new offer"
    )]
    OfferForEarlierRequest,
    #[error(
        "the offer answers another request than the pending one; run `tv-cli receive --offer` with the offer for the latest request.json, or abandon the pending request with `tv-cli refresh --force`"
    )]
    OfferForOtherRequest,
    #[error("the request asks for {requested} but --amount states {agreed}; nothing was signed")]
    PayAmount { agreed: u64, requested: u64 },
    #[error("insufficient balance: {balance} < {amount}")]
    Insufficient { balance: u64, amount: u64 },
    #[error("amount must be positive")]
    ZeroAmount,
    #[error("balance {balance} plus {amount} exceeds the balance cap")]
    ExceedsCap { balance: u64, amount: u64 },
    #[error("the enclave manifest names other bank keys than this wallet")]
    BankKeyMismatch,
    #[error("the bank refused the operation")]
    Refused,
    #[error(
        "the bank refused the payment, which exposed this wallet's payee serial; burn it with `tv-cli refresh --force`, or re-attest with `tv-cli request` and ask the payer for a fresh offer with `tv-cli reseal`"
    )]
    ReceiveRefused,
    #[error("the bank refused the refresh; run `tv-cli refresh` again")]
    RefreshRefused,
    #[error("the bank could not complete the operation (enclave link or log write); {retry}")]
    Unavailable { retry: &'static str },
    #[error("the enclave restarted since the request was made; regenerate the request and reseal")]
    EnclaveRestarted,
    #[error("the bank answered with an unexpected message at step {step}")]
    UnexpectedResponse { step: &'static str },
    #[error("the bank signature on the new state does not verify")]
    BadStateSignature,
    #[error("the operation is not in the public log yet; {next}")]
    NotSettled { next: &'static str },
    #[error("mock attestation is only acceptable on a loopback bank address")]
    MockRequiresLoopback,
    #[error("--allow-mock and --pcr0 are mutually exclusive")]
    MockWithPin,
    #[error("a PCR0 pin is required unless --allow-mock is given")]
    Pcr0Required,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("recovery failed: {0}")]
    Recover(String),
}

pub fn describe(err: &(dyn std::error::Error + 'static)) -> String {
    let mut text = err.to_string();
    let mut cause = err.source();
    while let Some(err) = cause {
        let message = err.to_string();
        if !text.contains(&message) {
            text.push_str(": ");
            text.push_str(&message);
        }
        cause = err.source();
    }
    text
}

impl ClientError {
    pub fn is_connection_refused(&self) -> bool {
        let io = match self {
            ClientError::Io(err) => err,
            ClientError::Transport(TransportError::Io { source, .. }) => source,
            _ => return false,
        };
        io.kind() == std::io::ErrorKind::ConnectionRefused
    }

    pub fn is_retryable(&self) -> bool {
        match self {
            ClientError::Transport(_)
            | ClientError::Frame(FrameError::Closed | FrameError::Io(_)) => true,
            ClientError::Io(err) => matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ),
            _ => false,
        }
    }
}

pub const RETRY_COMMAND: &str = "rerun the same command";
pub const RETRY_ENROLL: &str = "rerun `tv-cli enroll`";
pub const RETRY_REFRESH: &str = "rerun `tv-cli refresh` (or `tv-cli finish` if it already settled)";
pub const PAY_NOT_SETTLED: &str = "rerun `tv-cli finish` once the payee has run `tv-cli receive`, or pass the payee's receipt with `--receipt`; if the payee abandoned the request, the payment can never settle: run `tv-cli refresh --force`";
pub const RETRY_RECEIVE: &str = "re-attest and reseal (`tv-cli request` without an amount, then the payer's `tv-cli reseal`), then retry `tv-cli receive`";

fn completion(pending: &Pending) -> &'static str {
    match pending {
        Pending::Request { .. } => "`tv-cli receive --offer`",
        _ => "`tv-cli finish`",
    }
}

fn way_out(pending: &Pending) -> &'static str {
    match pending {
        Pending::Enroll { .. } => "complete it with `tv-cli enroll`",
        Pending::Refresh { .. } => {
            "complete it with `tv-cli refresh` (or `tv-cli finish` if it already settled)"
        }
        Pending::Request { .. } => {
            "complete it with `tv-cli receive --offer` or abandon it with `tv-cli refresh --force`"
        }
        Pending::Pay { .. } => {
            "complete it with `tv-cli finish` or abandon it with `tv-cli refresh --force`"
        }
    }
}

impl ClientError {
    pub fn pending_blocks(pending: &Pending) -> Self {
        ClientError::PendingBlocks {
            what: pending.what(),
            way_out: way_out(pending),
        }
    }

    pub fn refresh_blocked(pending: &Pending) -> Self {
        ClientError::RefreshBlocked {
            what: pending.what(),
            completion: completion(pending),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_guidance_names_only_commands_that_clear_that_kind() {
        let zero = [0u8; 32];
        let request = Pending::Request {
            v: 1,
            com_next: zero,
            channel_pk: zero,
            result_pk: zero,
        };
        let pay = Pending::Pay {
            v: 1,
            pk_b: zero,
            com_b_next: zero,
            com_a_next: zero,
            digest: zero,
        };
        let refresh = Pending::Refresh {
            com_next: zero,
            digest: zero,
        };
        let enroll = Pending::Enroll {
            com0: zero,
            digest: zero,
        };
        for blocked in [
            ClientError::pending_blocks(&request),
            ClientError::refresh_blocked(&request),
        ] {
            let text = blocked.to_string();
            assert!(text.contains("tv-cli receive --offer"), "{text}");
            assert!(!text.contains("finish"), "{text}");
        }
        let text = ClientError::pending_blocks(&request).to_string();
        assert!(text.contains("tv-cli refresh --force"), "{text}");
        let text = ClientError::pending_blocks(&pay).to_string();
        assert!(text.contains("tv-cli finish") && text.contains("refresh --force"));
        assert!(
            ClientError::refresh_blocked(&pay)
                .to_string()
                .contains("tv-cli finish")
        );
        let text = ClientError::pending_blocks(&refresh).to_string();
        assert!(text.contains("complete it with `tv-cli refresh`"), "{text}");
        let text = ClientError::pending_blocks(&enroll).to_string();
        assert!(text.ends_with("complete it with `tv-cli enroll`"), "{text}");
        assert!(!text.contains("finish"), "{text}");
    }

    #[test]
    fn unavailable_names_the_retry_of_its_own_operation() {
        let text = ClientError::Unavailable {
            retry: RETRY_ENROLL,
        }
        .to_string();
        assert!(text.ends_with("rerun `tv-cli enroll`"), "{text}");
        assert!(!text.contains("reseal"), "{text}");
        let text = ClientError::Unavailable {
            retry: RETRY_REFRESH,
        }
        .to_string();
        assert!(text.contains("rerun `tv-cli refresh`"), "{text}");
        assert!(!text.contains("reseal"), "{text}");
        let text = ClientError::Unavailable {
            retry: RETRY_RECEIVE,
        }
        .to_string();
        assert!(text.contains("re-attest and reseal"), "{text}");
    }

    #[test]
    fn describe_adds_only_causes_the_message_does_not_already_carry() {
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let transport = ClientError::Transport(TransportError::Io {
            endpoint: pt_tee::transport::Endpoint::tcp("127.0.0.1:1").unwrap(),
            source: refused,
        });
        assert!(transport.is_connection_refused());
        let text = describe(&transport);
        assert_eq!(text.matches("onnection refused").count(), 1, "{text}");
        let chained = anyhow_like("opening the bank", ClientError::NotEnrolled);
        assert_eq!(
            describe(&chained),
            "opening the bank: wallet is not enrolled"
        );
        assert!(!ClientError::Refused.is_connection_refused());
    }

    #[derive(Debug)]
    struct Context(&'static str, ClientError);

    impl std::fmt::Display for Context {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Context {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.1)
        }
    }

    fn anyhow_like(context: &'static str, err: ClientError) -> Context {
        Context(context, err)
    }
}
