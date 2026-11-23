use tv_core::{Bytes32, LogEntry, OpKind, PayPublic, Receipt, Signature, VerifyingKey};

use crate::error::ClientError;
use crate::wallet::Wallet;

pub struct Single {
    pub kind: OpKind,
    pub serial: Bytes32,
    pub com: Bytes32,
    pub sig: Signature,
    pub owner_sig: Signature,
    pub digest: Bytes32,
}

impl Single {
    pub fn new(
        kind: OpKind,
        (serial, com): (Bytes32, Bytes32),
        (sig, owner_sig): (Signature, Signature),
        digest: Bytes32,
    ) -> Self {
        Self {
            kind,
            serial,
            com,
            sig,
            owner_sig,
            digest,
        }
    }
}

pub fn pay_entry(
    public: &PayPublic,
    sig_a_next: Signature,
    sig_b_next: Signature,
    receipt: &Receipt,
) -> LogEntry {
    LogEntry {
        seq: receipt.seq,
        kind: OpKind::Pay,
        serials: vec![public.pk_a, public.pk_b],
        commitments: vec![public.com_a_next, public.com_b_next],
        sigs: vec![sig_a_next, sig_b_next],
        owner_sigs: vec![public.sig_a, public.sig_b],
        digest: public.digest(),
        c_v: Some(public.c_v),
        h_ctx: Some(public.h_ctx),
        epoch: receipt.epoch,
        chain: receipt.chain,
        rcpt: receipt.rcpt,
    }
}

pub fn single_entry(op: &Single, receipt: &Receipt) -> LogEntry {
    LogEntry {
        seq: receipt.seq,
        kind: op.kind,
        serials: vec![op.serial],
        commitments: vec![op.com],
        sigs: vec![op.sig],
        owner_sigs: vec![op.owner_sig],
        digest: op.digest,
        c_v: None,
        h_ctx: None,
        epoch: receipt.epoch,
        chain: receipt.chain,
        rcpt: receipt.rcpt,
    }
}

pub fn check_entry(wallet: &Wallet, entry: &LogEntry) -> Result<(), ClientError> {
    entry.verify_owners().map_err(|_| ClientError::BadReceipt {
        what: "owner signatures",
    })?;
    let key = VerifyingKey::parse(&wallet.receipt_pk())?;
    entry
        .verify_receipt(&key)
        .map_err(|_| ClientError::BadReceipt {
            what: "receipt signature",
        })
}
