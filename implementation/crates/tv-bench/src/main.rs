#![forbid(unsafe_code)]

mod profile;
mod stats;
mod store;

use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use clap::Parser;

use crate::stats::{ms, rate_line};

const UNKNOWN_CPU: &str = "unknown";
const GROUP_WRITERS: usize = 64;
const PROFILE_SCALE: usize = 10;

#[derive(Debug, Parser)]
#[command(name = "tv-bench", version, about = "tee-pay-v2 benchmarks")]
struct Args {
    #[arg(long, default_value_t = 1000, help = "Store appends per run")]
    appends: usize,
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

fn sync_benches(args: &Args, root: &Path) -> Result<()> {
    println!("== primitive costs (mean per operation)");
    for (label, per_op) in profile::primitives(args.iterations * PROFILE_SCALE)? {
        println!("{label}: {}", ms(per_op));
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
        in_process_benches(&args, &workspace.0).await
    })
}
