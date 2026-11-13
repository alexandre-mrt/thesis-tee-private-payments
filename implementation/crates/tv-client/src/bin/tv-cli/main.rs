use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use tv_client::error::describe;
use tv_client::ops::{Session, balance, create_wallet, seed_hex};
use tv_client::{DEFAULT_BANK, Trust, parse_pcr0};
use tv_core::{BankKeys, Bytes32, Seed, VerifyingKey};

const DEFAULT_LOG_FILTER: &str = "warn";

#[derive(Debug, Parser)]
#[command(name = "tv-cli", version, about = "tee-pay-v2 wallet")]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "wallet.json",
        help = "Wallet file (seed, bank keys, current state, pending operation)"
    )]
    wallet: PathBuf,
    #[arg(
        long,
        global = true,
        default_value = DEFAULT_BANK,
        help = "Bank address HOST:PORT"
    )]
    bank: String,
    #[arg(
        long,
        global = true,
        help = "Accept mock attestation (loopback bank only)"
    )]
    allow_mock: bool,
    #[arg(
        long,
        global = true,
        value_name = "HEX",
        conflicts_with = "allow_mock",
        value_parser = parse_pcr0,
        help = "PCR0 the enclave must attest (Nitro, 48-byte SHA-384 hex)"
    )]
    pcr0: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Create a wallet from a fresh or given seed, pinned to the bank keys")]
    New {
        #[arg(
            long,
            value_name = "HEX",
            help = "32-byte seed; generated when omitted"
        )]
        seed: Option<String>,
        #[arg(
            long,
            value_name = "HEX",
            help = "Bank state public key (tv-bank init, line 1)"
        )]
        state_pk: String,
        #[arg(
            long,
            value_name = "HEX",
            help = "Bank issuance public key (tv-bank init, line 2)"
        )]
        issuance_pk: String,
    },
    #[command(about = "Print the wallet seed (hex)")]
    Seed,
    #[command(about = "Enroll the wallet with a zero balance, then refresh off the public pk_0")]
    Enroll,
    #[command(
        about = "Payee: produce a payment request (re-attests a pending request without --amount)"
    )]
    Request {
        #[arg(long, help = "Amount to receive")]
        amount: Option<u64>,
        #[arg(long, help = "Where to write request.json")]
        out: PathBuf,
    },
    #[command(about = "Payer: answer a request with a sealed offer")]
    Pay {
        #[arg(long, help = "The payee's request.json")]
        request: PathBuf,
        #[arg(
            long,
            help = "Amount agreed with the payee; the request must ask for exactly this"
        )]
        amount: u64,
        #[arg(long, help = "Where to write offer.json")]
        out: PathBuf,
    },
    #[command(about = "Payer: reseal a pending offer to a fresh request from the same payee")]
    Reseal {
        #[arg(long, help = "The payee's fresh request.json")]
        request: PathBuf,
        #[arg(long, help = "Where to write offer.json")]
        out: PathBuf,
    },
    #[command(about = "Pay a request produced by the bank (same as pay)")]
    Redeem {
        #[arg(long, help = "The bank's request.json")]
        request: PathBuf,
        #[arg(
            long,
            help = "Amount agreed with the bank; the request must ask for exactly this"
        )]
        amount: u64,
        #[arg(long, help = "Where to write offer.json")]
        out: PathBuf,
    },
    #[command(about = "Payee: submit an offer to the bank and write the receipt")]
    Receive {
        #[arg(long, help = "The payer's offer.json")]
        offer: PathBuf,
        #[arg(long, help = "Where to write receipt.json")]
        out: PathBuf,
    },
    #[command(about = "Payer: finish a pending operation from a receipt or the public log")]
    Finish {
        #[arg(
            long,
            help = "The payee's receipt.json; looks the serial up in the log when omitted"
        )]
        receipt: Option<PathBuf>,
    },
    #[command(
        about = "Move the balance to a fresh serial (--force abandons a pending payment or request)"
    )]
    Refresh {
        #[arg(
            long,
            help = "Abandon a pending payment or request and burn its serial"
        )]
        force: bool,
    },
    #[command(about = "Print balance, index and pending operation")]
    Balance,
    #[command(about = "Rebuild index and state from the public log using the seed alone")]
    Recover,
}

fn parse_pk(hex_pk: &str, what: &str) -> anyhow::Result<Bytes32> {
    let bytes = hex::decode(hex_pk.trim()).with_context(|| format!("{what} is not hex"))?;
    let pk: Bytes32 = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} is not 32 bytes"))?;
    let key = VerifyingKey::parse(&pk).with_context(|| format!("{what} is not a curve point"))?;
    anyhow::ensure!(
        !key.is_weak(),
        "{what} is a small-order key that no signature verifies under"
    );
    Ok(pk)
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

async fn run(cli: Cli) -> anyhow::Result<String> {
    let trust = Trust {
        pcr0_hex: cli.pcr0.clone(),
        allow_mock: cli.allow_mock,
    };
    let session = || Session::open(&cli.wallet, &cli.bank, &trust);
    Ok(match cli.command {
        Command::New {
            seed,
            state_pk,
            issuance_pk,
        } => {
            let seed = seed.as_deref().map(Seed::from_hex).transpose()?;
            let bank = BankKeys {
                state_pk: parse_pk(&state_pk, "--state-pk")?,
                issuance_pk: parse_pk(&issuance_pk, "--issuance-pk")?,
            };
            create_wallet(&cli.wallet, seed, bank)?
        }
        Command::Seed => seed_hex(&cli.wallet)?,
        Command::Balance => balance(&cli.wallet)?,
        Command::Enroll => session()?.enroll().await?,
        Command::Request { amount, out } => session()?.request(amount, &out).await?,
        Command::Pay {
            request,
            amount,
            out,
        }
        | Command::Redeem {
            request,
            amount,
            out,
        } => session()?.pay(&request, &out, amount)?,
        Command::Reseal { request, out } => session()?.reseal(&request, &out)?,
        Command::Receive { offer, out } => session()?.receive(&offer, &out).await?,
        Command::Finish { receipt } => session()?.finish(receipt.as_deref()).await?,
        Command::Refresh { force } => session()?.refresh(force).await?,
        Command::Recover => session()?.recover().await?,
    })
}

#[tokio::main]
async fn main() {
    init_logging();
    match run(Cli::parse()).await {
        Ok(line) => println!("{line}"),
        Err(err) => {
            eprintln!("Error: {}", describe(err.as_ref()));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_bank_key_must_be_a_full_order_point() {
        let real = tv_core::SigningKey::generate().public_key();
        assert_eq!(parse_pk(&hex::encode(real), "--state-pk").unwrap(), real);
        let zero = parse_pk(&"00".repeat(32), "--state-pk").unwrap_err();
        assert!(zero.to_string().contains("--state-pk"), "{zero}");
        assert!(parse_pk("zz", "--issuance-pk").is_err());
        assert!(parse_pk(&"00".repeat(31), "--issuance-pk").is_err());
    }
}
