use super::*;

fn filter_of(args: &[&str]) -> &'static str {
    Cli::try_parse_from(args)
        .unwrap()
        .command
        .default_log_filter()
}

#[test]
fn only_serve_logs_at_info_by_default() {
    assert_eq!(
        filter_of(&["tv-bank", "serve", "--data", "d", "--allow-mock"]),
        SERVE_LOG_FILTER
    );
    assert_eq!(
        filter_of(&["tv-bank", "balance", "--data", "d"]),
        COMMAND_LOG_FILTER
    );
    assert_eq!(
        filter_of(&["tv-bank", "init", "--data", "d"]),
        COMMAND_LOG_FILTER
    );
    assert_eq!(
        filter_of(&["tv-bank", "register-enclave"]),
        COMMAND_LOG_FILTER
    );
}

#[test]
fn verify_log_needs_the_auditors_receipt_key() {
    assert!(Cli::try_parse_from(["tv-bank", "verify-log", "--data", "d"]).is_err());
    assert!(
        Cli::try_parse_from(["tv-bank", "verify-log", "--data", "d", "--receipt-pk", "zz"])
            .is_err()
    );
    let pk = "ab".repeat(32);
    assert!(
        Cli::try_parse_from(["tv-bank", "verify-log", "--data", "d", "--receipt-pk", &pk]).is_ok()
    );
}
