use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::task::JoinSet;

use crate::latency::{enroll_over_tcp, funded_party, pay_over_tcp};
use crate::settle::SettleRun;
use crate::setup::Loopback;

pub async fn settle_over_tcp(lb: &Loopback, pairs: usize, per_pair: usize) -> Result<SettleRun> {
    let mut lanes = Vec::with_capacity(pairs);
    for lane in 0..pairs {
        let payer = funded_party(lb, &format!("tcp-{pairs}-{lane}"), per_pair as u64).await?;
        let payee = enroll_over_tcp(&lb.client).await?;
        lanes.push((payer, payee));
    }
    let start = Instant::now();
    let mut tasks = JoinSet::new();
    for (mut payer, mut payee) in lanes {
        let client = Arc::clone(&lb.client);
        tasks.spawn(async move {
            for _ in 0..per_pair {
                pay_over_tcp(&client, &mut payer, &mut payee, 1).await?;
            }
            Ok::<(), anyhow::Error>(())
        });
    }
    while let Some(joined) = tasks.join_next().await {
        joined.context("settle task")??;
    }
    Ok(SettleRun {
        pairs,
        payments: pairs * per_pair,
        elapsed: start.elapsed(),
    })
}
