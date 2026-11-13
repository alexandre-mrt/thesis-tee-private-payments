//! Raw byte proxy: every accepted TCP connection is piped, unmodified and in
//! both directions, to the configured upstream (vsock on Linux, TCP anywhere).
//!
//! The proxy never parses frames (SPEC section 7): it has no knowledge of the
//! CBOR protocol between the client and the enclave, and it never logs payload
//! bytes, only byte counts and connection events.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pt_tee::transport::{self, Endpoint, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Relay buffer size per direction. Frames are up to 32 MiB, so the copy is
/// chunked; 64 KiB matches the usual socket buffer and keeps memory bounded.
pub const BUF_SIZE: usize = 64 * 1024;

/// Pause after a failed `accept` (for example EMFILE) before retrying, so a
/// transient resource exhaustion does not turn into a busy loop.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Proxy settings. Built by the CLI in `main.rs`, or directly in tests.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Where accepted connections are piped to (vsock on Linux, TCP anywhere).
    pub target: Endpoint,
    /// Maximum number of concurrently relayed connections; excess ones are closed.
    pub max_connections: usize,
    /// Maximum number of concurrently relayed connections from one source
    /// address; excess ones are closed. One peer cannot take every slot.
    pub max_connections_per_ip: usize,
    /// A connection with no bytes in either direction for this long is closed.
    pub idle_timeout: Duration,
    /// Maximum time to establish the upstream connection.
    pub connect_timeout: Duration,
    /// How long to wait for in-flight connections after a shutdown request.
    pub shutdown_grace: Duration,
}

/// Fatal proxy errors (per-connection failures are logged, not returned).
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// The listener could not report its address or accept at all.
    #[error("listener error: {0}")]
    Listener(#[source] io::Error),
    /// A configured limit is zero or otherwise unusable.
    #[error("invalid proxy setting {name}: {reason}")]
    InvalidConfig {
        /// Which setting.
        name: &'static str,
        /// Why it is rejected.
        reason: &'static str,
    },
}

impl ProxyConfig {
    /// Rejects zero or oversize connection limits (tokio's semaphore panics
    /// above `Semaphore::MAX_PERMITS`) and zero timeouts.
    pub fn validate(self) -> Result<Self, ProxyError> {
        let invalid = |name, reason| ProxyError::InvalidConfig { name, reason };
        if self.max_connections == 0 {
            return Err(invalid("max_connections", "must be at least 1"));
        }
        if self.max_connections > Semaphore::MAX_PERMITS {
            return Err(invalid(
                "max_connections",
                "exceeds the semaphore permit maximum",
            ));
        }
        if self.max_connections_per_ip == 0 {
            return Err(invalid("max_connections_per_ip", "must be at least 1"));
        }
        if self.idle_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(invalid("timeouts", "must be positive"));
        }
        Ok(self)
    }
}

/// Live connection count per source address.
type PerIp = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// Takes one per-address slot for `ip`, or `None` when `cap` is reached.
fn take_ip_slot(per_ip: &PerIp, ip: IpAddr, cap: usize) -> Option<IpSlot> {
    // A poisoned lock only means another relay task panicked mid-update; the
    // map is still usable, so recover it rather than refuse every connection.
    let mut map = per_ip.lock().unwrap_or_else(|e| e.into_inner());
    let count = map.entry(ip).or_insert(0);
    if *count >= cap {
        return None;
    }
    *count += 1;
    Some(IpSlot {
        per_ip: Arc::clone(per_ip),
        ip,
    })
}

/// Releases the per-address slot on drop.
struct IpSlot {
    per_ip: PerIp,
    ip: IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut map = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Serves `listener` until `shutdown` becomes `true` (or its sender is
/// dropped), then stops accepting and drains in-flight connections for at most
/// `config.shutdown_grace` before aborting them.
pub async fn run(
    listener: TcpListener,
    config: ProxyConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ProxyError> {
    let local = listener.local_addr().map_err(ProxyError::Listener)?;
    info!(listen = %local, target = %config.target, max_connections = config.max_connections,
        idle_timeout_secs = config.idle_timeout.as_secs(), "pt-host listening");

    let config = Arc::new(config);
    let slots = Arc::new(Semaphore::new(config.max_connections));
    let per_ip: PerIp = Arc::new(Mutex::new(HashMap::new()));
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut next_id: u64 = 0;

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                // A dropped sender also means shutdown.
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    next_id += 1;
                    admit(&mut tasks, &slots, &per_ip, &config, next_id, stream, peer);
                }
                Err(e) => {
                    warn!(error = %e, "accept failed, retrying");
                    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                }
            },
            Some(finished) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(e) = finished {
                    warn!(error = %e, "connection task failed");
                }
            }
        }
    }

    drop(listener);
    info!(
        in_flight = tasks.len(),
        grace_secs = config.shutdown_grace.as_secs_f64(),
        "shutdown requested, draining"
    );
    drain(&mut tasks, config.shutdown_grace).await;
    info!("pt-host stopped");
    Ok(())
}

/// Spawns the relay for an accepted connection if a global slot and a
/// per-address slot are free, otherwise drops it immediately (the client
/// observes EOF).
fn admit(
    tasks: &mut JoinSet<()>,
    slots: &Arc<Semaphore>,
    per_ip: &PerIp,
    config: &Arc<ProxyConfig>,
    conn_id: u64,
    stream: TcpStream,
    peer: SocketAddr,
) {
    let Some(ip_slot) = take_ip_slot(per_ip, peer.ip(), config.max_connections_per_ip) else {
        warn!(conn_id, peer = %peer, limit = config.max_connections_per_ip,
            "per-address connection limit reached, closing new connection");
        drop(stream);
        return;
    };
    match Arc::clone(slots).try_acquire_owned() {
        Ok(permit) => {
            let config = Arc::clone(config);
            tasks.spawn(async move {
                handle_connection(conn_id, stream, peer, &config).await;
                drop(permit);
                drop(ip_slot);
            });
        }
        Err(_) => {
            warn!(conn_id, peer = %peer, limit = config.max_connections,
                "connection limit reached, closing new connection");
            drop(stream);
            drop(ip_slot);
        }
    }
}

/// Waits up to `grace` for all tasks, then aborts whatever is still running.
async fn drain(tasks: &mut JoinSet<()>, grace: Duration) {
    let all_done = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(grace, all_done).await.is_err() {
        warn!(
            aborted = tasks.len(),
            "grace period over, aborting connections"
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

/// Connects upstream and relays until either side closes, an error occurs or
/// the connection idles out. Logs counts only, never payload bytes.
async fn handle_connection(
    conn_id: u64,
    client: TcpStream,
    peer: SocketAddr,
    config: &ProxyConfig,
) {
    debug!(conn_id, peer = %peer, "connection accepted");
    if let Err(e) = client.set_nodelay(true) {
        debug!(conn_id, error = %e, "set_nodelay failed, continuing");
    }
    let started = Instant::now();
    let connect = transport::connect(&config.target);
    let upstream = match tokio::time::timeout(config.connect_timeout, connect).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(conn_id, peer = %peer, error = %e, "upstream connect failed");
            return;
        }
        Err(_) => {
            warn!(conn_id, peer = %peer, timeout_secs = config.connect_timeout.as_secs_f64(),
                "upstream connect timed out");
            return;
        }
    };

    match relay(client, upstream, config.idle_timeout).await {
        Ok((to_upstream, to_client)) => info!(conn_id, peer = %peer, to_upstream, to_client,
            elapsed_ms = started.elapsed().as_millis() as u64, "connection closed"),
        Err(e) => warn!(conn_id, peer = %peer, error = %e,
            elapsed_ms = started.elapsed().as_millis() as u64, "connection ended with error"),
    }
}

/// Pipes bytes both ways. Returns `(client_to_upstream, upstream_to_client)`
/// byte counts, or an error (including an idle timeout).
async fn relay(
    client: TcpStream,
    upstream: Stream,
    idle_timeout: Duration,
) -> io::Result<(u64, u64)> {
    let activity = Activity::new();
    let (client_rd, client_wr) = tokio::io::split(client);
    let (upstream_rd, upstream_wr) = tokio::io::split(upstream);

    let both = async {
        tokio::try_join!(
            pump(client_rd, upstream_wr, &activity),
            pump(upstream_rd, client_wr, &activity),
        )
    };
    tokio::select! {
        counts = both => counts,
        () = activity.wait_idle(idle_timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("no traffic for {}s", idle_timeout.as_secs_f64()),
        )),
    }
}

/// Copies `from` into `to` until EOF, then half-closes `to` so the peer sees
/// the EOF. Every successful read refreshes `activity`.
async fn pump<R, W>(mut from: R, mut to: W, activity: &Activity) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return match to.shutdown().await {
                Ok(()) => Ok(total),
                // The peer is already gone; the EOF is delivered either way.
                Err(e) if e.kind() == io::ErrorKind::NotConnected => Ok(total),
                Err(e) => Err(e),
            };
        }
        activity.touch();
        to.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

/// Last-activity clock shared by both pump directions.
struct Activity {
    epoch: Instant,
    /// Milliseconds since `epoch` of the last byte read on either direction.
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        // fetch_max keeps the clock monotonic even if two directions race.
        self.last_ms.fetch_max(now_ms, Ordering::AcqRel);
    }

    fn last(&self) -> Instant {
        self.epoch + Duration::from_millis(self.last_ms.load(Ordering::Acquire))
    }

    /// Resolves once no byte has been read for `idle` (checked at each deadline).
    async fn wait_idle(&self, idle: Duration) {
        loop {
            let last = self.last();
            tokio::time::sleep_until(last + idle).await;
            if self.last() == last {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, sleep, timeout};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// Echo server on an ephemeral loopback port.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    struct Harness {
        proxy_addr: SocketAddr,
        shutdown: watch::Sender<bool>,
        task: JoinHandle<Result<(), ProxyError>>,
    }

    async fn spawn_proxy(config: ProxyConfig) -> Harness {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (shutdown, rx) = watch::channel(false);
        let task = tokio::spawn(run(listener, config, rx));
        Harness {
            proxy_addr,
            shutdown,
            task,
        }
    }

    fn tcp_config(target: SocketAddr) -> ProxyConfig {
        ProxyConfig {
            target: Endpoint::Tcp(target.to_string()),
            max_connections: 8,
            max_connections_per_ip: 8,
            idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_secs(2),
        }
    }

    #[test]
    fn config_validation() {
        let base = tcp_config("127.0.0.1:1".parse().unwrap());
        assert!(base.clone().validate().is_ok());
        for (name, cfg) in [
            (
                "max_connections",
                ProxyConfig {
                    max_connections: 0,
                    ..base.clone()
                },
            ),
            (
                "max_connections",
                ProxyConfig {
                    max_connections: Semaphore::MAX_PERMITS + 1,
                    ..base.clone()
                },
            ),
            (
                "max_connections_per_ip",
                ProxyConfig {
                    max_connections_per_ip: 0,
                    ..base.clone()
                },
            ),
            (
                "timeouts",
                ProxyConfig {
                    idle_timeout: Duration::ZERO,
                    ..base.clone()
                },
            ),
        ] {
            assert!(
                matches!(cfg.validate(), Err(ProxyError::InvalidConfig { name: n, .. }) if n == name),
                "{name}"
            );
        }
    }

    /// Adversarial review A9: one source address cannot take every slot.
    #[tokio::test]
    async fn per_address_limit_rejects_excess_and_recovers() {
        let echo = spawn_echo().await;
        let config = ProxyConfig {
            max_connections: 8,
            max_connections_per_ip: 1,
            ..tcp_config(echo)
        };
        let h = spawn_proxy(config).await;

        let mut first = TcpStream::connect(h.proxy_addr).await.unwrap();
        echo_round_trip(&mut first, b"one").await;
        // Same source address (loopback): over the per-address limit although
        // seven global slots are free.
        let mut second = TcpStream::connect(h.proxy_addr).await.unwrap();
        let _ = second.write_all(b"two").await;
        assert!(
            peer_closed(&mut second).await,
            "excess per-address connection must be closed"
        );
        echo_round_trip(&mut first, b"still here").await;
        drop(first);

        let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
        loop {
            let mut third = TcpStream::connect(h.proxy_addr).await.unwrap();
            third.write_all(b"three").await.unwrap();
            let mut back = [0u8; 5];
            match timeout(Duration::from_millis(500), third.read_exact(&mut back)).await {
                Ok(Ok(_)) => {
                    assert_eq!(&back, b"three");
                    break;
                }
                _ if tokio::time::Instant::now() < deadline => {
                    sleep(Duration::from_millis(20)).await
                }
                other => panic!("per-address slot never released: {other:?}"),
            }
        }

        h.shutdown.send(true).unwrap();
        timeout(TEST_TIMEOUT, h.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    async fn echo_round_trip(stream: &mut TcpStream, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        let mut back = vec![0u8; payload.len()];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut back))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(back, payload);
    }

    /// Reads until EOF or error; returns true if the peer closed cleanly or reset.
    async fn peer_closed(stream: &mut TcpStream) -> bool {
        let mut buf = [0u8; 16];
        match timeout(TEST_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => true,
            Ok(Ok(_)) => false,
            Err(_) => panic!("peer did not close in time"),
        }
    }

    #[tokio::test]
    async fn echo_round_trip_over_tcp_target() {
        let echo = spawn_echo().await;
        let h = spawn_proxy(tcp_config(echo)).await;

        let mut client = TcpStream::connect(h.proxy_addr).await.unwrap();
        echo_round_trip(&mut client, b"hello enclave").await;
        // Larger than one read buffer, exercises chunked relaying both ways.
        let big: Vec<u8> = (0..(3 * BUF_SIZE + 17)).map(|i| (i % 251) as u8).collect();
        echo_round_trip(&mut client, &big).await;
        echo_round_trip(&mut client, b"again").await;

        // Client half-close propagates to the upstream, which then closes back.
        client.shutdown().await.unwrap();
        assert!(peer_closed(&mut client).await);

        h.shutdown.send(true).unwrap();
        timeout(TEST_TIMEOUT, h.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn connection_limit_rejects_excess_and_recovers() {
        let echo = spawn_echo().await;
        let config = ProxyConfig {
            max_connections: 1,
            ..tcp_config(echo)
        };
        let h = spawn_proxy(config).await;

        let mut first = TcpStream::connect(h.proxy_addr).await.unwrap();
        echo_round_trip(&mut first, b"one").await;

        // Second connection is over the limit: accepted by the kernel, then closed by the proxy.
        let mut second = TcpStream::connect(h.proxy_addr).await.unwrap();
        let _ = second.write_all(b"two").await;
        assert!(
            peer_closed(&mut second).await,
            "excess connection must be closed"
        );

        // The first connection is unaffected.
        echo_round_trip(&mut first, b"still here").await;
        drop(first);

        // Once the slot is released a new connection is served again. Release is
        // asynchronous (the relay task must observe the close), so poll briefly.
        let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
        loop {
            let mut third = TcpStream::connect(h.proxy_addr).await.unwrap();
            third.write_all(b"three").await.unwrap();
            let mut back = [0u8; 5];
            match timeout(Duration::from_millis(500), third.read_exact(&mut back)).await {
                Ok(Ok(_)) => {
                    assert_eq!(&back, b"three");
                    break;
                }
                _ if tokio::time::Instant::now() < deadline => {
                    sleep(Duration::from_millis(20)).await
                }
                other => panic!("slot never released: {other:?}"),
            }
        }

        h.shutdown.send(true).unwrap();
        timeout(TEST_TIMEOUT, h.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn idle_connection_is_closed() {
        let echo = spawn_echo().await;
        let config = ProxyConfig {
            idle_timeout: Duration::from_millis(150),
            ..tcp_config(echo)
        };
        let h = spawn_proxy(config).await;

        let mut client = TcpStream::connect(h.proxy_addr).await.unwrap();
        echo_round_trip(&mut client, b"ping").await;
        let started = tokio::time::Instant::now();
        assert!(
            peer_closed(&mut client).await,
            "idle connection must be closed"
        );
        assert!(started.elapsed() >= Duration::from_millis(100));

        h.shutdown.send(true).unwrap();
        timeout(TEST_TIMEOUT, h.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn unreachable_upstream_closes_client() {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = unused.local_addr().unwrap();
        drop(unused);
        let h = spawn_proxy(tcp_config(dead)).await;

        let mut client = TcpStream::connect(h.proxy_addr).await.unwrap();
        assert!(peer_closed(&mut client).await);

        h.shutdown.send(true).unwrap();
        timeout(TEST_TIMEOUT, h.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_stops_accepting_and_drains_within_grace() {
        let echo = spawn_echo().await;
        let config = ProxyConfig {
            shutdown_grace: Duration::from_millis(200),
            ..tcp_config(echo)
        };
        let h = spawn_proxy(config).await;

        let mut active = TcpStream::connect(h.proxy_addr).await.unwrap();
        echo_round_trip(&mut active, b"busy").await;

        h.shutdown.send(true).unwrap();
        // The run loop must return even though a connection is still open.
        timeout(TEST_TIMEOUT, h.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // The lingering connection was aborted after the grace period.
        assert!(peer_closed(&mut active).await);
        // The listener is gone.
        assert!(TcpStream::connect(h.proxy_addr).await.is_err());
    }
}
