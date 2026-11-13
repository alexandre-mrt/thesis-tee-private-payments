use std::future::Future;
use std::time::Duration;

use tracing::warn;

use crate::error::ClientError;

pub const ATTEMPTS: u32 = 12;
pub const REFUSED_ATTEMPTS: u32 = 6;
pub const INITIAL_DELAY: Duration = Duration::from_millis(100);
pub const MAX_DELAY: Duration = Duration::from_secs(2);

fn budget(err: &ClientError) -> u32 {
    if err.is_connection_refused() {
        REFUSED_ATTEMPTS
    } else {
        ATTEMPTS
    }
}

pub async fn with_backoff<T, F, Fut>(what: &'static str, mut op: F) -> Result<T, ClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ClientError>>,
{
    let mut delay = INITIAL_DELAY;
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if err.is_retryable() && attempt < budget(&err) => {
                warn!(what, attempt, error = %err, "retrying after backoff");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use pt_tee::framing::FrameError;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn retries_transient_failures_then_succeeds() {
        let calls = AtomicU32::new(0);
        let value = with_backoff("test", || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(ClientError::Frame(FrameError::Closed))
                } else {
                    Ok(n)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(value, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_connection_gets_a_short_budget() {
        let calls = AtomicU32::new(0);
        let err = with_backoff("test", || {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<(), _>(ClientError::Io(std::io::Error::from(
                    std::io::ErrorKind::ConnectionRefused,
                )))
            }
        })
        .await
        .unwrap_err();
        assert!(err.is_connection_refused());
        assert_eq!(calls.load(Ordering::SeqCst), REFUSED_ATTEMPTS);
        let calls = AtomicU32::new(0);
        with_backoff("test", || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(ClientError::Frame(FrameError::Closed)) }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), ATTEMPTS);
    }

    #[tokio::test]
    async fn never_retries_definitive_errors() {
        let calls = AtomicU32::new(0);
        let err = with_backoff("test", || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(ClientError::Refused) }
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ClientError::Refused));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
