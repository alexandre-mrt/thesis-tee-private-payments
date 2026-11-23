use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use tv_client::error::describe;
use tv_client::ops::{Session, balance, create_wallet, seed_hex};
use tv_client::proof::Mode;
use tv_client::verifier::{read_verifier_key, write_verifier_key};
use tv_client::{DEFAULT_BANK, Trust, parse_pcr0};
use tv_core::{BankKeys, Bytes32, Seed, SigningKey, VerifyingKey};

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

#[derive(Debug, clap::Args)]
struct ProveArgs {
    #[arg(long, help = "Position of the payment in the public log")]
    seq: u64,
    #[arg(long, value_parser = ["payer", "payee", "amount", "designated"], help = "What to prove")]
    mode: String,
    #[arg(
        long,
        value_name = "HEX",
        help = "Verifier public key (designated mode)"
    )]
    verifier_pk: Option<String>,
    #[arg(
        long,
        value_name = "HEX",
        help = "32-byte challenge chosen by the verifier"
    )]
    challenge: String,
    #[arg(long, help = "Where to write proof.json")]
    out: PathBuf,
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    #[arg(long, help = "The prover's proof.json")]
    proof: PathBuf,
    #[arg(long, value_name = "HEX", help = "The challenge this verifier chose")]
    challenge: String,
    #[arg(
        long,
        value_name = "PATH",
        help = "File holding the verifier secret key, mode 600 (designated proofs)"
    )]
    verifier_sk_file: Option<PathBuf>,
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
        #[arg(
            long,
            value_name = "HEX",
            help = "Bank receipt public key (tv-bank init, line 3)"
        )]
        receipt_pk: String,
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
        #[arg(
            long,
            help = "Context the payer signs, for example an invoice number (hashed, never sent to the bank)"
        )]
        memo: Option<String>,
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
    #[command(about = "Prove one payment of this wallet from its seed and a full log download")]
    ProvePayment(ProveArgs),
    #[command(about = "Verify a proof of payment against the bank keys pinned in this wallet")]
    VerifyProof(VerifyArgs),
    #[command(
        about = "Write a fresh verifier secret key for designated proofs to a mode 600 file; prints verifier_pk=HEX"
    )]
    VerifierKey {
        #[arg(long, help = "Where to write the secret key (must not exist)")]
        out: PathBuf,
    },
}

fn parse_hex32(text: &str, what: &str) -> anyhow::Result<Bytes32> {
    let bytes = hex::decode(text.trim()).with_context(|| format!("{what} is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} is not 32 bytes"))
}

fn parse_mode(mode: &str, verifier_pk: Option<&str>) -> anyhow::Result<Mode> {
    Ok(match (mode, verifier_pk) {
        ("payer", None) => Mode::Payer,
        ("payee", None) => Mode::Payee,
        ("amount", None) => Mode::Amount,
        ("designated", Some(pk)) => Mode::Designated {
            verifier_pk: parse_pk(pk, "--verifier-pk")?,
        },
        ("designated", None) => anyhow::bail!("--mode designated needs --verifier-pk"),
        _ => anyhow::bail!("--verifier-pk is only for --mode designated"),
    })
}

fn parse_pk(hex_pk: &str, what: &str) -> anyhow::Result<Bytes32> {
    let pk = parse_hex32(hex_pk, what)?;
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

async fn prove(session: &Session, args: &ProveArgs) -> anyhow::Result<String> {
    let mode = parse_mode(&args.mode, args.verifier_pk.as_deref())?;
    let challenge = parse_hex32(&args.challenge, "--challenge")?;
    Ok(session
        .prove_payment(args.seq, mode, challenge, &args.out)
        .await?)
}

fn verify(session: &Session, args: &VerifyArgs) -> anyhow::Result<String> {
    let challenge = parse_hex32(&args.challenge, "--challenge")?;
    let verifier = args
        .verifier_sk_file
        .as_deref()
        .map(read_verifier_key)
        .transpose()?;
    Ok(session.verify_payment(&args.proof, &challenge, verifier.as_ref())?)
}

fn verifier_key(out: &Path) -> anyhow::Result<String> {
    let key = SigningKey::generate();
    write_verifier_key(out, &key)?;
    Ok(format!("verifier_pk={}", hex::encode(key.public_key())))
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
            receipt_pk,
        } => {
            let seed = seed.as_deref().map(Seed::from_hex).transpose()?;
            let bank = BankKeys {
                state_pk: parse_pk(&state_pk, "--state-pk")?,
                issuance_pk: parse_pk(&issuance_pk, "--issuance-pk")?,
            };
            let receipt_pk = parse_pk(&receipt_pk, "--receipt-pk")?;
            create_wallet(&cli.wallet, seed, bank, receipt_pk)?
        }
        Command::Seed => seed_hex(&cli.wallet)?,
        Command::Balance => balance(&cli.wallet)?,
        Command::Enroll => session()?.enroll().await?,
        Command::Request { amount, memo, out } => {
            session()?.request(amount, memo.as_deref(), &out).await?
        }
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
        Command::ProvePayment(args) => prove(&session()?, &args).await?,
        Command::VerifyProof(args) => verify(&session()?, &args)?,
        Command::VerifierKey { out } => verifier_key(&out)?,
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
