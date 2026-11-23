use tracing::{info, warn};
use tv_core::{
    BankResponse, Bytes32, LogEntry, OpKind, SideKind, Signature, SigningKey, sign_state,
};

use super::{Bank, Outcome};
use crate::index::answer_for;
use crate::journal::LogWriter;
use crate::link::EnclaveLink;
use crate::store::Ticket;

pub(crate) struct Settlement {
    pub kind: OpKind,
    pub serials: Vec<Bytes32>,
    pub commitments: Vec<Bytes32>,
    pub owner_sigs: Vec<Signature>,
    pub digest: Bytes32,
    pub evidence: Option<(Bytes32, Bytes32)>,
}

impl<L: EnclaveLink, W: LogWriter> Bank<L, W> {
    fn signer(&self, side: SideKind) -> &SigningKey {
        match side {
            SideKind::User => &self.state_key,
            SideKind::Bank => &self.issuance_key,
        }
    }

    pub(super) async fn settle(&self, settlement: Settlement, sides: Vec<SideKind>) -> Outcome {
        let kind = settlement.kind;
        let sigs = settlement
            .commitments
            .iter()
            .zip(&sides)
            .map(|(com, side)| sign_state(self.signer(*side), com))
            .collect();
        let (ticket, response, staged) = match self.stage(settlement, sigs) {
            Ok(staged) => staged,
            Err(reason) => return Outcome::refuse(reason),
        };
        if let Err(err) = self.committer.commit(&self.store, ticket).await {
            return Outcome::unavailable(&err, "commit failed");
        }
        if staged {
            info!(kind = ?kind, "settled");
        }
        Outcome {
            response,
            appended: staged,
        }
    }

    fn stage(
        &self,
        s: Settlement,
        sigs: Vec<Signature>,
    ) -> Result<(Ticket, BankResponse, bool), &'static str> {
        let mut store = self.store();
        if let Some((ticket, answer)) = store.answer(&s.digest) {
            return Ok((ticket, answer, false));
        }
        let consumed = s.serials.iter().any(|serial| match s.kind {
            OpKind::Enroll => !store.index().is_fresh_serial(serial),
            OpKind::Pay | OpKind::Refresh => store.index().is_spent(serial),
        });
        let reused = s.kind == OpKind::Enroll
            && s.commitments
                .iter()
                .any(|c| !store.index().is_fresh_commitment(c));
        if consumed || reused {
            return Err("serial or commitment consumed concurrently");
        }
        let entry = LogEntry {
            seq: store.index().len(),
            kind: s.kind,
            serials: s.serials,
            commitments: s.commitments,
            sigs,
            owner_sigs: s.owner_sigs,
            digest: s.digest,
            c_v: s.evidence.map(|(c_v, _)| c_v),
            h_ctx: s.evidence.map(|(_, h_ctx)| h_ctx),
        };
        let Some(response) = answer_for(&entry) else {
            return Err("entry shape");
        };
        let ticket = store.stage(entry).map_err(|err| {
            warn!(error = %err, "stage failed; the operation is not settled");
            "storage"
        })?;
        Ok((ticket, response, true))
    }
}
