use anyhow::{Context, Result, bail};
use pt_tee::channel::PK_LEN;
use tv_client::{WalletData, seal_to};
use tv_core::{
    BankResponse, Bytes32, EnrollRequest, EnrollSecret, Opening, PayPublic, PaySecret, Receive,
    Seed, SideKind, Signature, SignedState, SigningKey, State, commitment, derive_r, derive_sk,
    enroll_digest, pay_digest, sign_digest, sign_state, verify_state,
};

pub struct Party {
    seed: Seed,
    index: u64,
    state: Option<SignedState>,
    side: SideKind,
}

impl Party {
    pub fn new() -> Self {
        Self {
            seed: Seed::generate(),
            index: 0,
            state: None,
            side: SideKind::User,
        }
    }

    pub fn from_wallet(data: &WalletData) -> Self {
        let bank_signed = data.state.is_some_and(|s| {
            verify_state(&data.bank.issuance_pk, &s.state.commitment(), &s.sig).is_ok()
        });
        Self {
            seed: data.seed,
            index: data.index,
            state: data.state,
            side: if bank_signed {
                SideKind::Bank
            } else {
                SideKind::User
            },
        }
    }

    pub fn funded(balance: u64, signer: &SigningKey, side: SideKind) -> Result<Self> {
        let mut party = Self::new();
        party.side = side;
        let state = State {
            balance,
            pk: party.pk()?,
            r: party.r()?,
        };
        let sig = sign_state(signer, &state.commitment());
        party.state = Some(SignedState { state, sig });
        Ok(party)
    }

    pub fn balance(&self) -> u64 {
        self.state.map(|s| s.state.balance).unwrap_or(0)
    }

    pub fn key(&self) -> Result<SigningKey> {
        Ok(derive_sk(&self.seed, self.index)?)
    }

    pub fn pk(&self) -> Result<Bytes32> {
        Ok(self.key()?.public_key())
    }

    fn r(&self) -> Result<Bytes32> {
        Ok(derive_r(&self.seed, self.index)?)
    }

    pub fn opening(&self) -> Result<Opening> {
        let signed = self.state.context("party has no state")?;
        Ok(Opening {
            balance: signed.state.balance,
            r: signed.state.r,
            sig: signed.sig,
            side: self.side,
            next_pk: derive_sk(&self.seed, self.index + 1)?.public_key(),
            next_r: derive_r(&self.seed, self.index + 1)?,
        })
    }

    pub fn enroll_request(&self, channel_pk: &[u8; PK_LEN]) -> Result<EnrollRequest> {
        let key = self.key()?;
        let pk0 = key.public_key();
        let r0 = self.r()?;
        let com0 = commitment(0, &pk0, &r0);
        Ok(EnrollRequest {
            channel_pk: *channel_pk,
            pk0,
            com0,
            sig: sign_digest(&key, &enroll_digest(&pk0, &com0)),
            sealed: seal_to(channel_pk, &EnrollSecret { r0 })?,
        })
    }

    pub fn enrolled(&mut self, response: BankResponse) -> Result<()> {
        let BankResponse::Enrolled { sig } = response else {
            bail!("enroll not settled: {response:?}");
        };
        self.state = Some(SignedState {
            state: State {
                balance: 0,
                pk: self.pk()?,
                r: self.r()?,
            },
            sig,
        });
        Ok(())
    }

    fn advance(&mut self, balance: u64, sig: Signature) -> Result<()> {
        self.index += 1;
        self.state = Some(SignedState {
            state: State {
                balance,
                pk: self.pk()?,
                r: self.r()?,
            },
            sig,
        });
        Ok(())
    }
}

pub struct Payment {
    pub receive: Receive,
    a_next: u64,
    b_next: u64,
}

pub fn payment(payer: &Party, payee: &Party, v: u64, channel_pk: &[u8; PK_LEN]) -> Result<Payment> {
    let a_next = payer
        .balance()
        .checked_sub(v)
        .context("payer balance too low")?;
    let b_next = payee
        .balance()
        .checked_add(v)
        .context("payee balance overflow")?;
    let payer_opening = payer.opening()?;
    let payee_opening = payee.opening()?;
    let com_a_next = commitment(a_next, &payer_opening.next_pk, &payer_opening.next_r);
    let com_b_next = commitment(b_next, &payee_opening.next_pk, &payee_opening.next_r);
    let pk_a = payer.pk()?;
    let pk_b = payee.pk()?;
    let digest = pay_digest(&pk_a, &com_a_next, &pk_b, &com_b_next);
    let receive = Receive {
        channel_pk: *channel_pk,
        public: PayPublic {
            pk_a,
            com_a_next,
            sig_a: sign_digest(&payer.key()?, &digest),
            pk_b,
            com_b_next,
            sig_b: sign_digest(&payee.key()?, &digest),
        },
        payer: seal_to(
            channel_pk,
            &PaySecret {
                v,
                opening: payer_opening,
            },
        )?,
        payee: seal_to(
            channel_pk,
            &PaySecret {
                v,
                opening: payee_opening,
            },
        )?,
    };
    Ok(Payment {
        receive,
        a_next,
        b_next,
    })
}

pub fn settle(
    payer: &mut Party,
    payee: &mut Party,
    payment: &Payment,
    response: BankResponse,
) -> Result<()> {
    let BankResponse::Settled {
        sig_a_next,
        sig_b_next,
    } = response
    else {
        bail!("payment not settled: {response:?}");
    };
    payer.advance(payment.a_next, sig_a_next)?;
    payee.advance(payment.b_next, sig_b_next)
}
