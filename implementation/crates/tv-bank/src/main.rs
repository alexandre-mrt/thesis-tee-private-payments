use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use pt_tee::framing::{read_cbor_bounded, write_cbor};
use pt_tee::transport::{Endpoint, connect};
use tracing::info;
use tracing_subscriber::EnvFilter;
use tv_bank::{
    Bank, DEFAULT_ENCLAVE, DEFAULT_LISTEN, DEFAULT_RESERVE, EnclaveTrust, Policy, ServerConfig,
    TcpLink, bank_wallet_path, bind, crash_after_append, exit_after_append_hook, init, issue,
    parse_enclave, serve,
};
use tv_client::error::describe;
use tv_client::ops::{Session, balance};
use tv_client::{Trust, parse_pcr0};
use tv_core::{BankKeys, BankRequest, BankResponse};

const SERVE_LOG_FILTER: &str = "info";
const COMMAND_LOG_FILTER: &str = "warn";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(name = "tv-bank", version, about = "tee-pay-v2 bank")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Args)]
struct WalletArgs {
    #[arg(long, help = "Bank data directory (keys, log.jsonl, bank-wallet.json)")]
    data: PathBuf,
    #[arg(long, default_value = DEFAULT_LISTEN, help = "Bank address HOST:PORT")]
    bank: String,
    #[arg(long, help = "Accept mock attestation (loopback bank only)")]
    allow_mock: bool,
    #[arg(
        long,
        value_name = "HEX",
        conflicts_with = "allow_mock",
        value_parser = parse_pcr0,
        help = "PCR0 the enclave must attest (Nitro, 48-byte SHA-384 hex)"
    )]
    pcr0: Option<String>,
}

impl WalletArgs {
    fn issue(&self, to_request: &Path, out: &Path, amount: u64) -> anyhow::Result<String> {
        Ok(issue(
            &self.data,
            &self.session()?,
            to_request,
            out,
            amount,
        )?)
    }

    fn session(&self) -> anyhow::Result<Session> {
        let trust = Trust {
            pcr0_hex: self.pcr0.clone(),
            allow_mock: self.allow_mock,
        };
        Ok(Session::open(
            &bank_wallet_path(&self.data),
            &self.bank,
            &trust,
        )?)
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(
        about = "Generate the state and issuance keys and the bank wallet; prints state_pk=HEX and issuance_pk=HEX"
    )]
    Init {
        #[arg(long, help = "Bank data directory to create")]
        data: PathBuf,
        #[arg(
            long,
            default_value_t = DEFAULT_RESERVE,
            value_parser = clap::value_parser!(u64).range(1..),
            help = "Initial balance of the bank state (total supply, at least 1)"
        )]
        reserve: u64,
    },
    #[command(about = "Serve users over TCP and talk to the enclave")]
    Serve {
        #[arg(long, help = "Bank data directory (keys, log.jsonl, bank-wallet.json)")]
        data: PathBuf,
        #[arg(long, default_value = DEFAULT_LISTEN, help = "TCP address to listen on")]
        listen: String,
        #[arg(long, default_value = DEFAULT_ENCLAVE, help = "Enclave endpoint: tcp://HOST:PORT or vsock://CID:PORT")]
        enclave: String,
        #[arg(long, help = "Development mode: honours TV_CRASH_AFTER_APPEND=1")]
        dev: bool,
        #[arg(
            long,
            help = "Trust policy: accept the mock attestation of a loopback enclave"
        )]
        allow_mock: bool,
        #[arg(
            long,
            value_name = "HEX",
            conflicts_with = "allow_mock",
            value_parser = parse_pcr0,
            help = "Trust policy: PCR0 the enclave must attest (48-byte SHA-384 hex)"
        )]
        pcr0: Option<String>,
    },
    #[command(
        about = "Ask the running bank to attest its enclave under the policy it was started with"
    )]
    RegisterEnclave {
        #[arg(long, default_value = DEFAULT_LISTEN, help = "Bank address HOST:PORT")]
        bank: String,
    },
    #[command(about = "Issue: pay a user's request from the bank wallet")]
    Issue {
        #[command(flatten)]
        wallet: WalletArgs,
        #[arg(long, help = "The user's request.json")]
        to_request: PathBuf,
        #[arg(
            long,
            help = "Amount agreed with the user; the request must ask for exactly this"
        )]
        amount: u64,
        #[arg(long, help = "Where to write offer.json")]
        out: PathBuf,
    },
    #[command(about = "Produce a request the bank wallet will receive (redeem)")]
    Request {
        #[command(flatten)]
        wallet: WalletArgs,
        #[arg(long, help = "Amount to redeem")]
        amount: Option<u64>,
        #[arg(long, help = "Where to write request.json")]
        out: PathBuf,
    },
    #[command(about = "Receive a redeem offer into the bank wallet")]
    Receive {
        #[command(flatten)]
        wallet: WalletArgs,
        #[arg(long, help = "The user's offer.json")]
        offer: PathBuf,
        #[arg(long, help = "Where to write receipt.json")]
        out: PathBuf,
    },
    #[command(about = "Finish a pending issue from a receipt or the public log")]
    Finish {
        #[command(flatten)]
        wallet: WalletArgs,
        #[arg(
            long,
            help = "The user's receipt.json; looks the serial up in the log when omitted"
        )]
        receipt: Option<PathBuf>,
    },
    #[command(
        about = "Move the bank state to a fresh serial (--force abandons a pending issue or request)"
    )]
    Refresh {
        #[command(flatten)]
        wallet: WalletArgs,
        #[arg(long, help = "Abandon a pending issue or request and burn its serial")]
        force: bool,
    },
    #[command(
        about = "Rebuild the bank wallet from its genesis state, the public log and the issuance ledger"
    )]
    Recover {
        #[command(flatten)]
        wallet: WalletArgs,
    },
    #[command(about = "Print the bank wallet balance (local read)")]
    Balance {
        #[arg(long, help = "Bank data directory (keys, log.jsonl, bank-wallet.json)")]
        data: PathBuf,
    },
}

impl Command {
    fn default_log_filter(&self) -> &'static str {
        match self {
            Command::Serve { .. } => SERVE_LOG_FILTER,
            _ => COMMAND_LOG_FILTER,
        }
    }
}

fn init_logging(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
}

async fn run_serve(
    data: PathBuf,
    listen: String,
    enclave: String,
    dev: bool,
    trust: EnclaveTrust,
) -> anyhow::Result<()> {
    let crash = crash_after_append(dev)?;
    let enclave = parse_enclave(&enclave)?;
    trust
        .verifier(Some(&enclave))
        .context("enclave trust policy")?;
    let policy = Policy {
        trust: trust.clone(),
        enclave: Some(enclave.clone()),
    };
    let bank = Arc::new(
        Bank::open(&data, TcpLink::new(enclave.clone()))
            .context("opening the bank")?
            .with_policy(policy),
    );
    let listener = bind(&Endpoint::tcp(&listen)?)
        .await
        .with_context(|| format!("binding {listen}"))?;
    let config = ServerConfig {
        after_append: crash.then(exit_after_append_hook),
        enclave: Some(enclave),
        trust,
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::select! {
        result = serve(listener, bank, config, shutdown_rx) => result.context("serving")?,
        signal = tokio::signal::ctrl_c() => {
            signal.context("waiting for ctrl-c")?;
            info!("shutdown requested");
            let _ = shutdown_tx.send(true);
        }
    }
    Ok(())
}

async fn run_register(bank: String) -> anyhow::Result<String> {
    let mut stream = connect(&Endpoint::tcp(&bank)?)
        .await
        .with_context(|| format!("connecting to the bank at {bank}"))?;
    write_cbor(&mut stream, &BankRequest::RegisterEnclave).await?;
    let response: BankResponse = read_cbor_bounded(&mut stream, MAX_RESPONSE_BYTES).await?;
    match response {
        BankResponse::Registered { result_pk } => Ok(hex::encode(result_pk)),
        BankResponse::Refused => bail!("registration refused; see the bank log"),
        other => bail!("unexpected bank response: {other:?}"),
    }
}

fn describe_keys(keys: &BankKeys) -> String {
    format!(
        "state_pk={}\nissuance_pk={}",
        hex::encode(keys.state_pk),
        hex::encode(keys.issuance_pk)
    )
}

async fn run(cli: Cli) -> anyhow::Result<Option<String>> {
    Ok(match cli.command {
        Command::Init { data, reserve } => Some(describe_keys(
            &init(&data, reserve).context("initializing the bank")?,
        )),
        Command::Serve {
            data,
            listen,
            enclave,
            dev,
            allow_mock,
            pcr0,
        } => {
            let trust = EnclaveTrust {
                pcr0_hex: pcr0,
                allow_mock,
            };
            run_serve(data, listen, enclave, dev, trust).await?;
            None
        }
        Command::RegisterEnclave { bank } => Some(run_register(bank).await?),
        Command::Issue {
            wallet,
            to_request,
            amount,
            out,
        } => Some(wallet.issue(&to_request, &out, amount)?),
        Command::Request {
            wallet,
            amount,
            out,
        } => Some(wallet.session()?.request(amount, &out).await?),
        Command::Receive { wallet, offer, out } => {
            Some(wallet.session()?.receive(&offer, &out).await?)
        }
        Command::Finish { wallet, receipt } => {
            Some(wallet.session()?.finish(receipt.as_deref()).await?)
        }
        Command::Refresh { wallet, force } => Some(wallet.session()?.refresh(force).await?),
        Command::Recover { wallet } => {
            Some(tv_bank::genesis::recover(&wallet.data, &wallet.session()?).await?)
        }
        Command::Balance { data } => Some(balance(&bank_wallet_path(&data))?),
    })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_logging(cli.command.default_log_filter());
    match run(cli).await {
        Ok(Some(line)) => println!("{line}"),
        Ok(None) => {}
        Err(err) => {
            eprintln!("Error: {}", describe(err.as_ref()));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
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
}
