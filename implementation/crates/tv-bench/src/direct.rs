use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use pt_tee::channel::PK_LEN;
use tv_bank::keys::read_key;
use tv_bank::{EnclaveLink, STATE_KEY_FILE, TcpLink, parse_enclave};
use tv_core::{B_MAX, Bytes32, CheckOp, EnclaveResponse, SideKind, random_bytes32};

use crate::party::{Party, payment};

pub struct DirectLatency {
    pub round_trip: Vec<Duration>,
    pub attest: Vec<Duration>,
    pub check: Vec<Duration>,
    pub doc: Vec<u8>,
}

struct Attested {
    channel_pk: [u8; PK_LEN],
    doc: Vec<u8>,
}

async fn attest(link: &TcpLink, owner: Bytes32) -> Result<Attested> {
    match link.attest(random_bytes32(), Some(owner)).await? {
        EnclaveResponse::Attestation {
            doc, channel_pk, ..
        } => Ok(Attested { channel_pk, doc }),
        _ => bail!("the enclave refused the attestation"),
    }
}

async fn check(link: &TcpLink, op: CheckOp) -> Result<()> {
    match link.check(random_bytes32(), op).await? {
        EnclaveResponse::Result(_) => Ok(()),
        _ => bail!("the enclave refused the check"),
    }
}

pub async fn direct_latency(
    enclave: &str,
    bank_data: &Path,
    count: usize,
) -> Result<DirectLatency> {
    let link = TcpLink::new(parse_enclave(enclave)?);
    let state_key = read_key(&bank_data.join(STATE_KEY_FILE))?;
    let payer = Party::funded(B_MAX, &state_key, SideKind::User)?;
    let payee = Party::funded(0, &state_key, SideKind::User)?;
    let mut out = DirectLatency {
        round_trip: Vec::with_capacity(count),
        attest: Vec::with_capacity(count),
        check: Vec::with_capacity(count),
        doc: Vec::new(),
    };
    for _ in 0..count {
        let t0 = Instant::now();
        link.cancel(random_bytes32()).await?;
        let t1 = Instant::now();
        let attested = attest(&link, payee.pk()?).await?;
        let t2 = Instant::now();
        let receive = payment(&payer, &payee, 1, &attested.channel_pk)?.receive;
        let t3 = Instant::now();
        check(&link, CheckOp::Pay(Box::new(receive))).await?;
        let t4 = Instant::now();
        out.round_trip.push(t1 - t0);
        out.attest.push(t2 - t1);
        out.check.push(t4 - t3);
        out.doc = attested.doc;
    }
    Ok(out)
}
