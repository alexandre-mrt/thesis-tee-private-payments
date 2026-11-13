use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tv_enclave::{
    DEFAULT_MOCK_LISTEN, ENCLAVE_ALLOCATOR, Enclave, EnclaveAllocator, ServerConfig,
    attestation_provider, before_answer_hook, bind, listen_endpoint, parse_bank_keys, serve,
};

const DEFAULT_LOG_FILTER: &str = "info";

#[global_allocator]
static ALLOCATOR: EnclaveAllocator = ENCLAVE_ALLOCATOR;

#[derive(Debug, Parser)]
#[command(name = "tv-enclave", version, about)]
struct Args {
    #[arg(
        long,
        help = "Local mode: TCP loopback and mock (unsigned, clearly marked) attestation"
    )]
    mock: bool,

    #[arg(
        long,
        value_name = "HEX",
        env = "TV_STATE_PK",
        help = "Bank state public key"
    )]
    state_pk: String,

    #[arg(
        long,
        value_name = "HEX",
        env = "TV_ISSUANCE_PK",
        help = "Bank issuance public key"
    )]
    issuance_pk: String,

    #[arg(long, default_value = DEFAULT_MOCK_LISTEN, help = "TCP address to listen on with --mock")]
    listen: String,

    #[arg(long, default_value_t = pt_tee::DEFAULT_ENCLAVE_PORT, help = "vsock port to listen on inside the enclave")]
    vsock_port: u32,
}

fn init_logging() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let args = Args::parse();
    let bank = parse_bank_keys(&args.state_pk, &args.issuance_pk)?;
    let before_answer = before_answer_hook(args.mock)?;
    let provider = attestation_provider(args.mock).context("opening the attestation provider")?;
    let enclave = Arc::new(Enclave::boot(bank, provider)?);
    let endpoint = listen_endpoint(args.mock, &args.listen, args.vsock_port)?;
    let listener = bind(&endpoint)
        .await
        .with_context(|| format!("binding {endpoint}"))?;
    let config = ServerConfig { before_answer };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::select! {
        result = serve(listener, enclave, config, shutdown_rx) => result.context("serving")?,
        signal = tokio::signal::ctrl_c() => {
            signal.context("waiting for ctrl-c")?;
            info!("shutdown requested");
            let _ = shutdown_tx.send(true);
        }
    }
    Ok(())
}
