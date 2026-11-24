#![forbid(unsafe_code)]

mod client;
mod enclave;
mod latency;
mod party;
mod profile;
mod remote;
mod settle;
mod setup;
mod stats;
mod store;

use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};
use clap::Parser;

use tv_client::Trust;

use crate::setup::{Loopback, Remote};
use crate::stats::{line, ms, percentiles, rate_line};

const UNKNOWN_CPU: &str = "unknown";
const CPUINFO: &str = "/proc/cpuinfo";
const CPUINFO_MODEL: &str = "model name";
const GROUP_WRITERS: usize = 64;
const SETTLE_OVERSUBSCRIPTION: usize = 4;
const PROFILE_SCALE: usize = 10;

#[derive(Debug, Parser)]
#[command(name = "tv-bench", version, about = "tee-pay-v2 benchmarks")]
struct Args {
    #[arg(
        long,
        default_value_t = 1000,
        help = "Payments per latency and settle run"
    )]
    payments: usize,
    #[arg(
        long,
        default_value_t = 4096,
        help = "Enclave checks per throughput run"
    )]
    checks: usize,
    #[arg(long, default_value_t = 1000, help = "Store appends per run")]
    appends: usize,
    #[arg(
        long,
        help = "Concurrent payer/payee pairs for the settle run (default: cores)"
    )]
    pairs: Option<usize>,
    #[arg(
        long,
        default_value_t = 200,
        help = "Iterations of the client-side cost run"
    )]
    iterations: usize,
    #[arg(
        long,
        requires = "bank_data",
        help = "Bank address HOST:PORT of a running bank: measure it instead of local mock setups"
    )]
    remote: Option<String>,
    #[arg(
        long,
        requires = "remote",
        conflicts_with = "allow_mock",
        help = "PCR0 the running bank's enclave must attest"
    )]
    pcr0: Option<String>,
    #[arg(
        long,
        requires = "remote",
        help = "Accept mock attestation from the running bank (loopback bank only)"
    )]
    allow_mock: bool,
    #[arg(
        long,
        requires = "remote",
        help = "Data directory of the running bank (its wallet funds the bench wallets)"
    )]
    bank_data: Option<PathBuf>,
}

struct Workspace(PathBuf);

impl Workspace {
    fn create() -> Result<Self> {
        let root = std::env::temp_dir().join(format!("tv-bench-{}", std::process::id()));
        std::fs::create_dir_all(&root)?;
        Ok(Self(root))
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cores() -> usize {
    std::thread::available_parallelism()
        .map(NonZero::get)
        .unwrap_or(1)
}

fn sysctl_brand() -> Option<String> {
    Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn cpuinfo_brand() -> Option<String> {
    std::fs::read_to_string(CPUINFO)
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix(CPUINFO_MODEL))
        .map(|rest| rest.trim_start_matches([' ', '\t', ':']).trim().to_owned())
}

fn cpu_brand() -> String {
    sysctl_brand()
        .or_else(cpuinfo_brand)
        .unwrap_or_else(|| UNKNOWN_CPU.to_owned())
}

fn print_percentiles(label: &str, samples: &[std::time::Duration]) {
    if let Some(p) = percentiles(samples) {
        println!("{}", line(label, &p));
    }
}

fn sync_benches(args: &Args, root: &Path) -> Result<()> {
    println!("== primitive costs (mean per operation)");
    for (label, per_op) in profile::primitives(args.iterations * PROFILE_SCALE)? {
        println!("{label}: {}", ms(per_op));
    }
    println!("== enclave check throughput (in-process, Pay, mock attestation)");
    for threads in [1, cores()] {
        let run = enclave::check_throughput(args.checks, threads)?;
        println!(
            "{}",
            rate_line(
                &format!("checks with {} thread(s)", run.threads),
                run.checks,
                run.elapsed
            )
        );
    }
    println!("== bank store (log.jsonl)");
    let elapsed = store::append_per_op(root, args.appends)?;
    println!(
        "{}",
        rate_line("append with fsync per op", args.appends, elapsed)
    );
    Ok(())
}

async fn in_process_benches(args: &Args, root: &Path) -> Result<()> {
    println!("== bank store (log.jsonl), group commit");
    for writers in [1, cores(), GROUP_WRITERS] {
        let (count, elapsed) = store::append_group_commit(root, args.appends, writers).await?;
        println!(
            "{}",
            rate_line(
                &format!("stage + commit with {writers} concurrent writer(s)"),
                count,
                elapsed
            )
        );
    }
    println!("== bank settle throughput (in-process bank and enclave, full Receive path)");
    let pairs = args.pairs.unwrap_or_else(cores);
    for pairs in [1, pairs, pairs * SETTLE_OVERSUBSCRIPTION] {
        let per_pair = args.payments.div_ceil(pairs);
        let run = settle::settle_throughput(root, pairs, per_pair).await?;
        println!(
            "{}",
            rate_line(
                &format!("payments with {} concurrent pair(s)", run.pairs),
                run.payments,
                run.elapsed
            )
        );
    }
    Ok(())
}

async fn latency_bench(args: &Args, lb: &Loopback) -> Result<()> {
    let lat = latency::payment_latency(lb, args.payments).await?;
    print_percentiles("attest round trip", &lat.attest);
    print_percentiles("build offer and payee blob", &lat.build);
    print_percentiles("receive round trip", &lat.receive);
    print_percentiles("payment total", &lat.total);
    Ok(())
}

async fn wallet_flow_bench(args: &Args, lb: &Loopback) -> Result<()> {
    let flow = latency::wallet_flow_latency(lb, args.payments).await?;
    print_percentiles(
        "tv-cli flow request+pay+receive+finish with wallet files",
        &flow,
    );
    Ok(())
}

async fn client_cost_bench(args: &Args, lb: &Loopback) -> Result<()> {
    println!("== client-side cost");
    let cost = client::client_cost(lb, args.iterations).await?;
    print_percentiles("verify attestation bundle", &cost.verify);
    print_percentiles("seal payer opening", &cost.seal);
    print_percentiles("build offer (prepare_pay)", &cost.offer);
    Ok(())
}

async fn sizes_bench(lb: &Loopback) -> Result<()> {
    println!("== message sizes");
    for (label, bytes) in client::message_sizes(lb).await? {
        println!("{label}: {bytes} bytes");
    }
    Ok(())
}

async fn loopback_benches(args: &Args, root: &Path) -> Result<()> {
    println!("== loopback TCP latency (user -> bank -> enclave, sequential payments)");
    latency_bench(args, &setup::start_loopback(root, "latency").await?).await?;
    wallet_flow_bench(args, &setup::start_loopback(root, "wallet-flow").await?).await?;
    client_cost_bench(args, &setup::start_loopback(root, "client-cost").await?).await?;
    sizes_bench(&setup::start_loopback(root, "sizes").await?).await
}

async fn remote_benches(args: &Args, root: &Path, remote: &Remote<'_>) -> Result<()> {
    let lb = setup::connect_remote(root, remote)?;
    println!(
        "== remote bank {} (user -> bank -> enclave, sequential payments)",
        remote.bank
    );
    latency_bench(args, &lb).await?;
    wallet_flow_bench(args, &lb).await?;
    client_cost_bench(args, &lb).await?;
    sizes_bench(&lb).await?;
    println!("== remote bank settle throughput (concurrent pairs over TCP, full Receive path)");
    let pairs = args.pairs.unwrap_or_else(cores);
    for pairs in [1, pairs, pairs * SETTLE_OVERSUBSCRIPTION] {
        let run = remote::settle_over_tcp(&lb, pairs, args.payments.div_ceil(pairs)).await?;
        println!(
            "{}",
            rate_line(
                &format!("payments with {} concurrent pair(s)", run.pairs),
                run.payments,
                run.elapsed
            )
        );
    }
    Ok(())
}

fn remote_of(args: &Args) -> Result<Option<Remote<'_>>> {
    let (Some(bank), Some(bank_data)) = (args.remote.as_deref(), args.bank_data.as_deref()) else {
        return Ok(None);
    };
    if args.pcr0.is_none() && !args.allow_mock {
        bail!("--remote needs --pcr0 HEX, or --allow-mock for a local mock bank");
    }
    Ok(Some(Remote {
        bank,
        trust: Trust {
            pcr0_hex: args.pcr0.clone(),
            allow_mock: args.allow_mock,
        },
        bank_data,
    }))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let workspace = Workspace::create()?;
    println!("machine: {} ({} logical cores)", cpu_brand(), cores());
    let remote = remote_of(&args)?;
    if remote.is_none() {
        sync_benches(&args, &workspace.0)?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    if let Some(remote) = remote {
        return runtime.block_on(remote_benches(&args, &workspace.0, &remote));
    }
    runtime.block_on(async {
        in_process_benches(&args, &workspace.0).await?;
        loopback_benches(&args, &workspace.0).await
    })
}
