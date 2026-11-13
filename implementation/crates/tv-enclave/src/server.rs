use std::sync::Arc;
use std::time::Duration;

use pt_tee::framing::{FrameError, decode_cbor, read_frame_bounded, write_cbor};
use pt_tee::transport::{Endpoint, Listener, Stream};
use tokio::sync::watch;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use tv_core::{EnclaveRequest, EnclaveResponse};

use crate::error::EnclaveError;
use crate::service::Enclave;

pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(30);

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

pub const CRASH_EXIT_CODE: i32 = 86;

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

pub type BeforeAnswerHook = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone, Default)]
pub struct ServerConfig {
    pub before_answer: Option<BeforeAnswerHook>,
}

#[cfg(feature = "test-hooks")]
pub fn exit_before_answer_hook() -> BeforeAnswerHook {
    Arc::new(|| {
        warn!("crash injected before the answer; exiting");
        std::process::exit(CRASH_EXIT_CODE)
    })
}

pub async fn bind(endpoint: &Endpoint) -> Result<Listener, EnclaveError> {
    Ok(Listener::bind(endpoint).await?)
}

pub async fn serve(
    listener: Listener,
    enclave: Arc<Enclave>,
    config: ServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), EnclaveError> {
    let local = listener.local_endpoint()?;
    info!(endpoint = %local, "enclave listening");
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!(endpoint = %local, "enclave server stopped");
                    return Ok(());
                }
                continue;
            }
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = %err, "accept failed; retrying");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let enclave = Arc::clone(&enclave);
        let config = config.clone();
        tokio::spawn(async move {
            match timeout(
                CONNECTION_LIFETIME,
                handle_connection(stream, &enclave, &config),
            )
            .await
            {
                Ok(Ok(())) => debug!(peer = %peer, "connection closed"),
                Ok(Err(err)) => warn!(peer = %peer, error = %err, "connection ended with an error"),
                Err(_elapsed) => debug!(peer = %peer, "connection lifetime reached"),
            }
        });
    }
}

async fn read_request(stream: &mut Stream) -> Result<Option<EnclaveRequest>, EnclaveError> {
    let frame = match read_frame_bounded(stream, MAX_REQUEST_BYTES).await {
        Err(FrameError::Closed) => return Ok(None),
        Err(err) => return Err(err.into()),
        Ok(frame) => frame,
    };
    Ok(Some(decode_cbor::<EnclaveRequest>(&frame)?))
}

pub async fn handle_connection(
    mut stream: Stream,
    enclave: &Enclave,
    config: &ServerConfig,
) -> Result<(), EnclaveError> {
    let request = match read_request(&mut stream).await {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(err) => {
            if let Err(write_err) = write_cbor(&mut stream, &EnclaveResponse::Refused).await {
                debug!(error = %write_err, "peer gone before the refusal was written");
            }
            return Err(err);
        }
    };
    let response = enclave.handle(&request);
    if matches!(request, EnclaveRequest::Check { .. })
        && let Some(hook) = &config.before_answer
    {
        hook();
    }
    write_cbor(&mut stream, &response).await?;
    Ok(())
}
