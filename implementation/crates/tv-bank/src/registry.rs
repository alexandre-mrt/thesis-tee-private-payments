use pt_tee::PROTOCOL_TAG;
use pt_tee::attestation::{AttestationVerifier, VerifyRequest};
use pt_tee::transport::Endpoint;
use tv_core::{BankKeys, Bytes32, EnclaveResponse, manifest_digest, random_bytes32};

use std::net::{IpAddr, Ipv6Addr};

use crate::error::BankError;
use crate::link::EnclaveLink;

#[derive(Debug, Clone, Default)]
pub struct EnclaveTrust {
    pub pcr0_hex: Option<String>,
    pub allow_mock: bool,
}

impl EnclaveTrust {
    pub fn verifier(&self, enclave: Option<&Endpoint>) -> Result<AttestationVerifier, BankError> {
        if self.allow_mock && self.pcr0_hex.is_some() {
            return Err(BankError::MockWithPin);
        }
        if self.allow_mock && enclave.is_some_and(|e| !e.is_loopback()) {
            return Err(BankError::MockRequiresLoopback);
        }
        let verifier = AttestationVerifier::with_aws_root()
            .map_err(|e| BankError::Attestation(e.to_string()))?
            .allow_mock(self.allow_mock);
        match &self.pcr0_hex {
            Some(hex) => verifier
                .expect_pcr0_hex(hex)
                .map_err(|e| BankError::Attestation(e.to_string())),
            None if self.allow_mock => Ok(verifier),
            None => Err(BankError::Pcr0Required),
        }
    }
}

const MAX_HOST_NAME: usize = 253;
const MAX_LABEL: usize = 63;

fn is_label(label: &str) -> bool {
    (1..=MAX_LABEL).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn is_host(host: &str) -> bool {
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6.parse::<Ipv6Addr>().is_ok();
    }
    host.parse::<IpAddr>().is_ok() || (host.len() <= MAX_HOST_NAME && host.split('.').all(is_label))
}

pub fn parse_enclave(input: &str) -> Result<Endpoint, BankError> {
    let invalid = |reason: String| BankError::EnclaveAddress {
        input: input.to_owned(),
        reason,
    };
    let endpoint: Endpoint = input
        .parse()
        .map_err(|e: pt_tee::transport::TransportError| invalid(e.to_string()))?;
    match &endpoint {
        Endpoint::Tcp(addr) if !addr.rsplit_once(':').is_some_and(|(host, _)| is_host(host)) => {
            Err(invalid(
                "the host is neither an IP address nor a host name".to_owned(),
            ))
        }
        _ => Ok(endpoint),
    }
}

pub(crate) fn now_unix_secs() -> Result<i64, BankError> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| BankError::Clock)?
        .as_secs();
    i64::try_from(secs).map_err(|_| BankError::Clock)
}

pub async fn attest_enclave<L: EnclaveLink>(
    link: &L,
    verifier: &AttestationVerifier,
    bank: &BankKeys,
) -> Result<Bytes32, BankError> {
    let nonce = random_bytes32();
    let (doc, manifest) = match link.attest(nonce, None).await? {
        EnclaveResponse::Attestation { doc, manifest, .. } => (doc, manifest),
        EnclaveResponse::Refused => {
            return Err(BankError::Attestation("enclave refused".to_owned()));
        }
        EnclaveResponse::Result(_) | EnclaveResponse::Cancelled => {
            return Err(BankError::Attestation(
                "unexpected response to an attestation".to_owned(),
            ));
        }
    };
    if manifest.bank != *bank {
        return Err(BankError::ManifestKeyMismatch);
    }
    verifier
        .verify(
            &doc,
            &VerifyRequest {
                nonce: &nonce,
                user_data_prefix: PROTOCOL_TAG,
                user_data_digest: &manifest_digest(&manifest),
                now_unix_secs: now_unix_secs()?,
            },
        )
        .map_err(|e| BankError::Attestation(e.to_string()))?;
    Ok(manifest.result_pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_rules() {
        let loopback = Endpoint::tcp("127.0.0.1:5005").unwrap();
        let remote = Endpoint::tcp("10.0.0.1:5005").unwrap();
        let mock = EnclaveTrust {
            pcr0_hex: None,
            allow_mock: true,
        };
        assert!(mock.verifier(Some(&loopback)).is_ok());
        assert!(mock.verifier(None).is_ok());
        assert!(matches!(
            mock.verifier(Some(&remote)),
            Err(BankError::MockRequiresLoopback)
        ));
        let both = EnclaveTrust {
            pcr0_hex: Some("ab".repeat(48)),
            allow_mock: true,
        };
        assert!(matches!(
            both.verifier(Some(&loopback)),
            Err(BankError::MockWithPin)
        ));
        assert!(matches!(
            EnclaveTrust::default().verifier(Some(&remote)),
            Err(BankError::Pcr0Required)
        ));
        let pinned = EnclaveTrust {
            pcr0_hex: Some("ab".repeat(48)),
            allow_mock: false,
        };
        assert!(pinned.verifier(Some(&remote)).is_ok());
    }

    #[test]
    fn enclave_addresses_name_a_host_and_a_port() {
        for good in [
            "127.0.0.1:7977",
            "tcp://127.0.0.1:7977",
            "tcp://localhost:7977",
            "[::1]:7977",
            "enclave-1.internal:5005",
            "vsock://16:5005",
        ] {
            assert!(parse_enclave(good).is_ok(), "{good}");
        }
        for bad in [
            "http://127.0.0.1:7977",
            "tcp://127.0.0.1:7977x",
            "127.0.0.1",
            ":7977",
            "-bad.host:7977",
            "[nonsense]:7977",
        ] {
            let err = parse_enclave(bad).unwrap_err();
            assert!(matches!(err, BankError::EnclaveAddress { .. }), "{bad}");
            assert!(err.to_string().contains("--enclave"));
            assert!(err.to_string().contains("tcp://HOST:PORT"));
        }
    }
}
