use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::task::JoinSet;
use tv_bank::{Committer, SharedStore, Store};
use tv_core::{LogEntry, OpKind, SIG_LEN, Signature, random_bytes32};

pub fn pay_entry(seq: u64) -> LogEntry {
    LogEntry {
        seq,
        kind: OpKind::Pay,
        serials: vec![random_bytes32(), random_bytes32()],
        commitments: vec![random_bytes32(), random_bytes32()],
        sigs: vec![random_signature(), random_signature()],
        digest: random_bytes32(),
    }
}

fn random_signature() -> Signature {
    let mut bytes = [0u8; SIG_LEN];
    bytes[..32].copy_from_slice(&random_bytes32());
    bytes[32..].copy_from_slice(&random_bytes32());
    Signature(bytes)
}

pub fn append_per_op(root: &Path, count: usize) -> Result<Duration> {
    let dir = root.join("store-per-op");
    std::fs::create_dir_all(&dir)?;
    tv_bank::create_log(&dir)?;
    let mut store = Store::open(&dir)?;
    let entries: Vec<LogEntry> = (0..count as u64).map(pay_entry).collect();
    let start = Instant::now();
    for entry in entries {
        store.append(entry)?;
    }
    Ok(start.elapsed())
}

pub async fn append_group_commit(
    root: &Path,
    count: usize,
    writers: usize,
) -> Result<(usize, Duration)> {
    let dir = root.join(format!("store-group-{writers}"));
    std::fs::create_dir_all(&dir)?;
    tv_bank::create_log(&dir)?;
    let store: SharedStore<std::fs::File> = Arc::new(Mutex::new(Store::open(&dir)?));
    let committer = Arc::new(Committer::default());
    let per_writer = count.div_ceil(writers);
    let start = Instant::now();
    let mut tasks = JoinSet::new();
    for _ in 0..writers {
        let store = Arc::clone(&store);
        let committer = Arc::clone(&committer);
        tasks.spawn(async move {
            for _ in 0..per_writer {
                let ticket = {
                    let mut guard = store.lock().unwrap_or_else(PoisonError::into_inner);
                    let seq = guard.index().len();
                    guard.stage(pay_entry(seq))?
                };
                committer.commit(&store, ticket).await?;
            }
            Ok::<(), anyhow::Error>(())
        });
    }
    while let Some(joined) = tasks.join_next().await {
        joined.context("writer task")??;
    }
    Ok((writers * per_writer, start.elapsed()))
}
