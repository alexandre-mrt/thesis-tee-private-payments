use std::sync::Arc;
use std::time::Duration;

use pt_tee::framing::{FrameError, decode_cbor, read_frame_bounded, write_cbor};
use pt_tee::transport::{Endpoint, Listener, Stream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use tv_core::{BankRequest, BankResponse};

use crate::bank::Bank;
use crate::error::BankError;
use crate::link::EnclaveLink;
use crate::registry::EnclaveTrust;

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(60);

pub const CRASH_EXIT_CODE: i32 = 87;

pub const CRASH_AFTER_APPEND_ENV: &str = "TV_CRASH_AFTER_APPEND";

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

pub type AfterAppendHook = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone)]
pub struct ServerConfig {
    pub after_append: Option<AfterAppendHook>,
    pub enclave: Option<Endpoint>,
    pub trust: EnclaveTrust,
}

pub fn exit_after_append_hook() -> AfterAppendHook {
    Arc::new(|| {
        warn!("crash injected after append; exiting");
        std::process::exit(CRASH_EXIT_CODE)
    })
}

pub fn crash_after_append(dev: bool) -> Result<bool, BankError> {
    let requested = std::env::var(CRASH_AFTER_APPEND_ENV).is_ok_and(|v| v == "1");
    if requested && !dev {
        return Err(BankError::CrashInjectionRequiresDev {
            var: CRASH_AFTER_APPEND_ENV,
        });
    }
    Ok(requested)
}

pub fn source_of(peer: &Endpoint) -> String {
    match peer {
        Endpoint::Tcp(addr) => addr
            .rsplit_once(':')
            .map_or(addr.as_str(), |(host, _)| host)
            .to_owned(),
        Endpoint::Vsock { cid, .. } => format!("vsock:{cid}"),
    }
}

pub async fn bind(endpoint: &Endpoint) -> Result<Listener, BankError> {
    Ok(Listener::bind(endpoint).await?)
}

pub async fn serve<L: EnclaveLink>(
    listener: Listener,
    bank: Arc<Bank<L>>,
    config: ServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BankError> {
    let local = listener.local_endpoint()?;
    info!(endpoint = %local, "bank listening");
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = %err, "accept failed; retrying");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let bank = Arc::clone(&bank);
        let config = config.clone();
        connections.spawn(async move {
            match timeout(
                CONNECTION_LIFETIME,
                handle_connection(stream, &peer, &bank, &config),
            )
            .await
            {
                Ok(Ok(())) => debug!("connection closed"),
                Ok(Err(err)) => warn!(peer = %peer, error = %err, "connection ended with an error"),
                Err(_elapsed) => debug!("connection lifetime reached"),
            }
        });
    }
    while connections.join_next().await.is_some() {}
    info!(endpoint = %local, "bank server stopped");
    Ok(())
}

async fn read_request(stream: &mut Stream) -> Result<Option<BankRequest>, BankError> {
    let frame = match read_frame_bounded(stream, MAX_REQUEST_BYTES).await {
        Err(FrameError::Closed) => return Ok(None),
        Err(err) => return Err(err.into()),
        Ok(frame) => frame,
    };
    Ok(Some(decode_cbor::<BankRequest>(&frame)?))
}

pub async fn handle_connection<L: EnclaveLink>(
    mut stream: Stream,
    peer: &Endpoint,
    bank: &Bank<L>,
    config: &ServerConfig,
) -> Result<(), BankError> {
    let request = match read_request(&mut stream).await {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(err) => {
            if let Err(write_err) = write_cbor(&mut stream, &BankResponse::Refused).await {
                debug!(error = %write_err, "peer gone before the refusal was written");
            }
            return Err(err);
        }
    };
    let response = match request {
        BankRequest::RegisterEnclave => register(peer, bank, config).await.unwrap_or_else(|err| {
            warn!(error = %err, "enclave registration refused");
            BankResponse::Refused
        }),
        other => {
            let outcome = bank.handle_from(&source_of(peer), &other).await;
            if outcome.appended
                && let Some(hook) = &config.after_append
            {
                hook();
            }
            outcome.response
        }
    };
    write_cbor(&mut stream, &response).await?;
    Ok(())
}

async fn register<L: EnclaveLink>(
    peer: &Endpoint,
    bank: &Bank<L>,
    config: &ServerConfig,
) -> Result<BankResponse, BankError> {
    if !peer.is_loopback() {
        return Err(BankError::Forbidden);
    }
    let result_pk = bank
        .register(&config.trust, config.enclave.as_ref())
        .await?;
    Ok(BankResponse::Registered { result_pk })
}
