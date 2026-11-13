#![forbid(unsafe_code)]

mod client;
mod enclave;
mod latency;
mod party;
mod profile;
mod settle;
mod setup;
mod stats;
mod store;

use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use clap::Parser;

use crate::stats::{line, ms, percentiles, rate_line};

const UNKNOWN_CPU: &str = "unknown";
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

fn cpu_brand() -> String {
    Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
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

async fn loopback_benches(args: &Args, root: &Path) -> Result<()> {
    println!("== loopback TCP latency (user -> bank -> enclave, sequential payments)");
    let lb = setup::start_loopback(root, "latency").await?;
    let lat = latency::payment_latency(&lb, args.payments).await?;
    print_percentiles("attest round trip", &lat.attest);
    print_percentiles("build offer and payee blob", &lat.build);
    print_percentiles("receive round trip", &lat.receive);
    print_percentiles("payment total", &lat.total);
    drop(lb);
    let lb = setup::start_loopback(root, "wallet-flow").await?;
    let flow = latency::wallet_flow_latency(&lb, args.payments).await?;
    print_percentiles(
        "tv-cli flow request+pay+receive+finish with wallet files",
        &flow,
    );
    drop(lb);
    println!("== client-side cost");
    let lb = setup::start_loopback(root, "client-cost").await?;
    let cost = client::client_cost(&lb, args.iterations).await?;
    print_percentiles("verify attestation bundle", &cost.verify);
    print_percentiles("seal payer opening", &cost.seal);
    print_percentiles("build offer (prepare_pay)", &cost.offer);
    drop(lb);
    println!("== message sizes");
    let lb = setup::start_loopback(root, "sizes").await?;
    for (label, bytes) in client::message_sizes(&lb).await? {
        println!("{label}: {bytes} bytes");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let workspace = Workspace::create()?;
    println!("machine: {} ({} logical cores)", cpu_brand(), cores());
    sync_benches(&args, &workspace.0)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        in_process_benches(&args, &workspace.0).await?;
        loopback_benches(&args, &workspace.0).await
    })
}
