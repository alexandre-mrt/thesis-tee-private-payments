use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use pt_tee::attestation::MockProvider;
use tv_core::{B_MAX, BankKeys, CheckOp, EnclaveResponse, SideKind, SigningKey, random_bytes32};
use tv_enclave::{Enclave, MAX_PENDING_KEYS};

use crate::party::{Party, payment};
use crate::setup::{attest_in_process, verifier};

pub struct CheckRun {
    pub threads: usize,
    pub checks: usize,
    pub elapsed: Duration,
}

pub fn check_throughput(total: usize, threads: usize) -> Result<CheckRun> {
    let state_key = SigningKey::generate();
    let issuance_key = SigningKey::generate();
    let keys = BankKeys {
        state_pk: state_key.public_key(),
        issuance_pk: issuance_key.public_key(),
    };
    let enclave = Enclave::boot(keys, Box::new(MockProvider::new()))?;
    let verifier = verifier()?;
    let payer = Party::funded(B_MAX, &state_key, SideKind::User)?;
    let payee = Party::funded(0, &state_key, SideKind::User)?;
    let batch = MAX_PENDING_KEYS / 2;
    let mut checks = 0;
    let mut elapsed = Duration::ZERO;
    while checks < total {
        let ops = (0..batch.min(total - checks))
            .map(|_| {
                let channel_pk = attest_in_process(&enclave, &verifier, &payee.pk()?)?;
                let receive = payment(&payer, &payee, 1, &channel_pk)?.receive;
                Ok(CheckOp::Pay(Box::new(receive)))
            })
            .collect::<Result<Vec<_>>>()?;
        elapsed += run_checks(&enclave, &ops, threads)?;
        checks += ops.len();
    }
    Ok(CheckRun {
        threads,
        checks,
        elapsed,
    })
}

fn run_checks(enclave: &Enclave, ops: &[CheckOp], threads: usize) -> Result<Duration> {
    let chunk = ops.len().div_ceil(threads.max(1)).max(1);
    let start = Instant::now();
    let accepted = std::thread::scope(|scope| {
        let workers: Vec<_> = ops
            .chunks(chunk)
            .map(|ops| {
                scope.spawn(move || {
                    ops.iter()
                        .filter(|op| {
                            matches!(
                                enclave.check(random_bytes32(), op),
                                EnclaveResponse::Result(_)
                            )
                        })
                        .count()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|w| w.join().map_err(|_| anyhow!("a check thread panicked")))
            .sum::<Result<usize>>()
    })?;
    let elapsed = start.elapsed();
    if accepted != ops.len() {
        bail!(
            "{} of {} checks were refused",
            ops.len() - accepted,
            ops.len()
        );
    }
    Ok(elapsed)
}
