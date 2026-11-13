use tv_core::{
    Bytes32, CheckOp, EnrollRequest, OpKind, Receive, RefreshRequest, enroll_digest, pay_digest,
    refresh_digest, verify_digest,
};

use super::{Bank, Outcome};
use crate::journal::LogWriter;
use crate::link::EnclaveLink;

impl<L: EnclaveLink, W: LogWriter> Bank<L, W> {
    pub(super) async fn receive(&self, receive: &Receive) -> Outcome {
        let p = &receive.public;
        let digest = pay_digest(&p.pk_a, &p.com_a_next, &p.pk_b, &p.com_b_next);
        let _claim = match self.claim(digest).await {
            Ok(claim) => claim,
            Err(outcome) => return outcome,
        };
        if verify_digest(&p.pk_a, &digest, &p.sig_a).is_err()
            || verify_digest(&p.pk_b, &digest, &p.sig_b).is_err()
        {
            return Outcome::refuse("owner signature");
        }
        if p.pk_a == p.pk_b || !self.serials_unspent(&[p.pk_a, p.pk_b]) {
            return Outcome::refuse("serial spent or repeated");
        }
        let sides = match self
            .checked(&digest, CheckOp::Pay(Box::new(receive.clone())))
            .await
        {
            Ok(sides) if sides.len() == 2 => sides,
            Ok(_) => return Outcome::refuse("enclave result shape"),
            Err(outcome) => return outcome,
        };
        self.settle(
            OpKind::Pay,
            vec![p.pk_a, p.pk_b],
            vec![p.com_a_next, p.com_b_next],
            sides,
            digest,
        )
        .await
    }

    pub(super) async fn enroll(&self, enroll: &EnrollRequest) -> Outcome {
        let digest = enroll_digest(&enroll.pk0, &enroll.com0);
        let _claim = match self.claim(digest).await {
            Ok(claim) => claim,
            Err(outcome) => return outcome,
        };
        if verify_digest(&enroll.pk0, &digest, &enroll.sig).is_err() {
            return Outcome::refuse("owner signature");
        }
        {
            let store = self.store();
            if !store.index().is_fresh_serial(&enroll.pk0)
                || !store.index().is_fresh_commitment(&enroll.com0)
            {
                return Outcome::refuse("serial or commitment not fresh");
            }
        }
        let sides = match self
            .checked(&digest, CheckOp::Enroll(Box::new(enroll.clone())))
            .await
        {
            Ok(sides) if sides.len() == 1 => sides,
            Ok(_) => return Outcome::refuse("enclave result shape"),
            Err(outcome) => return outcome,
        };
        self.settle(
            OpKind::Enroll,
            vec![enroll.pk0],
            vec![enroll.com0],
            sides,
            digest,
        )
        .await
    }

    pub(super) async fn refresh(&self, refresh: &RefreshRequest) -> Outcome {
        let digest = refresh_digest(&refresh.pk, &refresh.com_next);
        let _claim = match self.claim(digest).await {
            Ok(claim) => claim,
            Err(outcome) => return outcome,
        };
        if verify_digest(&refresh.pk, &digest, &refresh.sig).is_err() {
            return Outcome::refuse("owner signature");
        }
        if !self.serials_unspent(&[refresh.pk]) {
            return Outcome::refuse("serial spent");
        }
        let sides = match self
            .checked(&digest, CheckOp::Refresh(Box::new(refresh.clone())))
            .await
        {
            Ok(sides) if sides.len() == 1 => sides,
            Ok(_) => return Outcome::refuse("enclave result shape"),
            Err(outcome) => return outcome,
        };
        self.settle(
            OpKind::Refresh,
            vec![refresh.pk],
            vec![refresh.com_next],
            sides,
            digest,
        )
        .await
    }

    fn serials_unspent(&self, serials: &[Bytes32]) -> bool {
        let store = self.store();
        serials.iter().all(|s| !store.index().is_spent(s))
    }
}
