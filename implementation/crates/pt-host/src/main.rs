//! pt-host: parent-instance byte proxy (SPEC sections 7 and 8).
//!
//! Listens on TCP and pipes raw bytes to the enclave over vsock `CID:port`
//! (Linux parent instance) or to `--tcp-target` (local mock setup, any OS).
//! It never parses frames and never logs payloads. SIGTERM or Ctrl-C stops
//! accepting, drains in-flight connections for the grace period, then exits.

#![forbid(unsafe_code)]

mod proxy;

use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;
use pt_tee::transport::Endpoint;
use pt_tee::{DEFAULT_ENCLAVE_CID, DEFAULT_ENCLAVE_PORT, DEFAULT_HOST_LISTEN};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_MAX_CONNECTIONS: usize = 64;
/// A client opens one connection per proof; a handful per address is plenty.
const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 8;
/// Generous because the enclave can take a while to compute a Groth16 proof
/// while neither direction carries bytes.
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 10;
const DEFAULT_LOG_FILTER: &str = "info";

/// Parent-instance byte proxy: TCP in, vsock (or TCP) out. Never parses frames.
#[derive(Debug, Parser)]
#[command(name = "pt-host", version, about)]
struct Cli {
    /// TCP address to listen on.
    #[arg(long, default_value = DEFAULT_HOST_LISTEN)]
    listen: String,

    /// Enclave vsock CID (Linux parent instance only).
    #[arg(long, default_value_t = DEFAULT_ENCLAVE_CID, conflicts_with = "tcp_target")]
    cid: u32,

    /// Enclave vsock port.
    #[arg(long, default_value_t = DEFAULT_ENCLAVE_PORT, conflicts_with = "tcp_target")]
    port: u32,

    /// Pipe to this TCP address instead of vsock (local `pt-enclave --mock` setup).
    #[arg(long, value_name = "HOST:PORT")]
    tcp_target: Option<String>,

    /// Maximum number of concurrently relayed connections; excess ones are closed.
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,

    /// Maximum number of concurrently relayed connections from one source address.
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS_PER_IP)]
    max_connections_per_ip: usize,

    /// Close a connection after this many seconds without traffic in either direction.
    #[arg(long, default_value_t = DEFAULT_IDLE_TIMEOUT_SECS)]
    idle_timeout_secs: u64,

    /// Give up on the upstream connect after this many seconds.
    #[arg(long, default_value_t = DEFAULT_CONNECT_TIMEOUT_SECS)]
    connect_timeout_secs: u64,

    /// After SIGTERM, wait this many seconds for in-flight connections before aborting them.
    #[arg(long, default_value_t = DEFAULT_SHUTDOWN_GRACE_SECS)]
    shutdown_grace_secs: u64,
}

impl Cli {
    fn target(&self) -> anyhow::Result<Endpoint> {
        match &self.tcp_target {
            Some(addr) => Endpoint::tcp(addr).context("invalid --tcp-target"),
            None => {
                if !cfg!(target_os = "linux") {
                    bail!(
                        "vsock targets are only supported on a Linux parent instance; \
                         use --tcp-target HOST:PORT on this platform"
                    );
                }
                Ok(Endpoint::vsock(self.cid, self.port))
            }
        }
    }

    fn proxy_config(&self) -> anyhow::Result<proxy::ProxyConfig> {
        Ok(proxy::ProxyConfig {
            target: self.target()?,
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            idle_timeout: Duration::from_secs(self.idle_timeout_secs),
            connect_timeout: Duration::from_secs(self.connect_timeout_secs),
            shutdown_grace: Duration::from_secs(self.shutdown_grace_secs),
        }
        .validate()?)
    }
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

/// Resolves on SIGTERM or SIGINT (Ctrl-C). Flips the watch to `true`.
async fn shutdown_signal(tx: watch::Sender<bool>) {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => tokio::select! {
                _ = ctrl_c => info!("SIGINT received"),
                _ = term.recv() => info!("SIGTERM received"),
            },
            Err(e) => {
                warn!(error = %e, "cannot listen for SIGTERM, only Ctrl-C will stop the proxy");
                let _ = ctrl_c.await;
                info!("SIGINT received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
        info!("Ctrl-C received");
    }
    // Receivers may already be gone if the proxy failed; nothing to signal then.
    let _ = tx.send(true);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let config = cli.proxy_config()?;

    let listener = TcpListener::bind(&cli.listen)
        .await
        .with_context(|| format!("cannot bind {}", cli.listen))?;

    let (tx, rx) = watch::channel(false);
    tokio::spawn(shutdown_signal(tx));

    proxy::run(listener, config, rx)
        .await
        .context("proxy failed")
}
