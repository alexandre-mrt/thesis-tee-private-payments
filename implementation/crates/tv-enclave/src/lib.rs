#![forbid(unsafe_code)]

pub mod checks;
pub mod error;
pub mod keys;
pub mod server;
pub mod service;

pub use checks::{Refusal, check_enroll, check_pay, check_refresh};
pub use error::EnclaveError;
pub use keys::{ChannelKeys, MAX_KEY_AGE, MAX_PENDING_KEYS};
#[cfg(feature = "test-hooks")]
pub use server::exit_before_answer_hook;
pub use server::{BeforeAnswerHook, CRASH_EXIT_CODE, ServerConfig, bind, serve};
pub use service::Enclave;
#[cfg(feature = "test-hooks")]
pub use service::LeakedMemory;

pub use zeroizing_alloc::ZeroAlloc;

use pt_tee::attestation::AttestationProvider;
use pt_tee::transport::Endpoint;
use tv_core::{BankKeys, Bytes32};

#[cfg(feature = "test-hooks")]
pub const TEST_HOOKS: bool = true;

#[cfg(not(feature = "test-hooks"))]
#[doc = "```compile_fail"]
#[doc = "use tv_enclave::LeakedMemory;"]
#[doc = "```"]
#[doc = "```compile_fail"]
#[doc = "fn leak(enclave: &tv_enclave::Enclave) { enclave.leak_memory(); }"]
#[doc = "```"]
#[doc = "```compile_fail"]
#[doc = "use tv_enclave::Enclave; fn boot(k: tv_core::BankKeys, p: Box<dyn pt_tee::attestation::AttestationProvider>, r: tv_core::SigningKey) -> Result<Enclave, tv_enclave::EnclaveError> { Enclave::boot_with_result_key(k, p, r) }"]
#[doc = "```"]
pub const TEST_HOOKS: bool = false;

pub type EnclaveAllocator = ZeroAlloc<std::alloc::System>;

pub const ENCLAVE_ALLOCATOR: EnclaveAllocator = ZeroAlloc(std::alloc::System);

pub const CRASH_BEFORE_ANSWER_ENV: &str = "TV_CRASH_BEFORE_ANSWER";

pub const DEFAULT_MOCK_LISTEN: &str = pt_tee::MOCK_ENCLAVE_LISTEN;

pub fn attestation_provider(mock: bool) -> Result<Box<dyn AttestationProvider>, EnclaveError> {
    if mock {
        return Ok(Box::new(pt_tee::attestation::MockProvider::new()));
    }
    nsm_provider()
}

#[cfg(target_os = "linux")]
fn nsm_provider() -> Result<Box<dyn AttestationProvider>, EnclaveError> {
    pt_tee::attestation::NsmProvider::open()
        .map(|p| Box::new(p) as Box<dyn AttestationProvider>)
        .map_err(|e| EnclaveError::Attestation(e.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn nsm_provider() -> Result<Box<dyn AttestationProvider>, EnclaveError> {
    Err(EnclaveError::NsmUnavailable)
}

pub fn listen_endpoint(
    mock: bool,
    listen: &str,
    vsock_port: u32,
) -> Result<Endpoint, EnclaveError> {
    if mock {
        Ok(Endpoint::tcp(listen)?)
    } else {
        Ok(Endpoint::vsock(
            pt_tee::transport::VSOCK_CID_ANY,
            vsock_port,
        ))
    }
}

pub fn parse_pk(hex_pk: &str, what: &'static str) -> Result<Bytes32, EnclaveError> {
    let bytes = hex::decode(hex_pk.trim()).map_err(|_| EnclaveError::KeyHex { what })?;
    bytes.try_into().map_err(|_| EnclaveError::KeyHex { what })
}

pub fn parse_bank_keys(state_pk: &str, issuance_pk: &str) -> Result<BankKeys, EnclaveError> {
    Ok(BankKeys {
        state_pk: parse_pk(state_pk, "state public key")?,
        issuance_pk: parse_pk(issuance_pk, "issuance public key")?,
    })
}

pub fn before_answer_hook(mock: bool) -> Result<Option<BeforeAnswerHook>, EnclaveError> {
    let requested = std::env::var(CRASH_BEFORE_ANSWER_ENV).is_ok_and(|v| v == "1");
    before_answer_hook_from(mock, requested)
}

#[cfg(feature = "test-hooks")]
pub fn before_answer_hook_from(
    mock: bool,
    requested: bool,
) -> Result<Option<BeforeAnswerHook>, EnclaveError> {
    if requested && !mock {
        return Err(EnclaveError::CrashInjectionRequiresMock {
            var: CRASH_BEFORE_ANSWER_ENV,
        });
    }
    Ok(requested.then(exit_before_answer_hook))
}

#[cfg(not(feature = "test-hooks"))]
pub fn before_answer_hook_from(
    _mock: bool,
    requested: bool,
) -> Result<Option<BeforeAnswerHook>, EnclaveError> {
    if requested {
        return Err(EnclaveError::CrashInjectionNotCompiled {
            var: CRASH_BEFORE_ANSWER_ENV,
        });
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_and_keys() {
        assert_eq!(
            listen_endpoint(true, "127.0.0.1:5005", 5005).unwrap(),
            Endpoint::Tcp("127.0.0.1:5005".to_owned())
        );
        assert_eq!(
            listen_endpoint(false, "127.0.0.1:5005", 5005).unwrap(),
            Endpoint::vsock(pt_tee::transport::VSOCK_CID_ANY, 5005)
        );
        assert!(listen_endpoint(true, "nohost", 1).is_err());
        assert_eq!(parse_pk(&"ab".repeat(32), "k").unwrap(), [0xAB; 32]);
        assert!(matches!(
            parse_pk("zz", "k"),
            Err(EnclaveError::KeyHex { .. })
        ));
        assert!(parse_bank_keys(&"ab".repeat(32), &"cd".repeat(31)).is_err());
        assert!(attestation_provider(true).is_ok());
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn the_crash_hook_is_honoured_with_mock_only() {
        assert!(before_answer_hook_from(true, true).unwrap().is_some());
        assert!(before_answer_hook_from(true, false).unwrap().is_none());
        assert!(matches!(
            before_answer_hook_from(false, true),
            Err(EnclaveError::CrashInjectionRequiresMock { .. })
        ));
    }

    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn the_crash_hook_is_not_compiled_in_without_test_hooks() {
        assert!(before_answer_hook_from(true, false).unwrap().is_none());
        assert!(matches!(
            before_answer_hook_from(true, true),
            Err(EnclaveError::CrashInjectionNotCompiled { .. })
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn nsm_is_unavailable_off_linux() {
        assert!(matches!(
            attestation_provider(false).err(),
            Some(EnclaveError::NsmUnavailable)
        ));
    }
}
