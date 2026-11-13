use tv_core::{
    B_MAX, BankVerifiers, Bytes32, EnrollRequest, EnrollSecret, Opening, PayPublic, PaySecret,
    RefreshRequest, RefreshSecret, SideKind, commitment, enroll_digest, pay_digest, refresh_digest,
    verify_digest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Opening,
    ChannelKey,
    OwnerSignature,
    Amount,
    Bounds,
    NextCommitment,
    SameSerial,
    NextSerial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub digest: Bytes32,
    pub sides: Vec<SideKind>,
}

fn first_failure(checks: &[(bool, Refusal)]) -> Result<(), Refusal> {
    checks
        .iter()
        .find(|(failed, _)| *failed)
        .map_or(Ok(()), |(_, refusal)| Err(*refusal))
}

fn opening_is_signed(bank: &BankVerifiers, pk: &Bytes32, opening: &Opening) -> bool {
    let com = commitment(opening.balance, pk, &opening.r);
    let key = match opening.side {
        SideKind::User => &bank.state,
        SideKind::Bank => &bank.issuance,
    };
    key.verify_state(&com, &opening.sig).is_ok()
}

fn openings_are_signed(
    bank: &BankVerifiers,
    public: &PayPublic,
    payer: &Opening,
    payee: &Opening,
) -> bool {
    let a = opening_is_signed(bank, &public.pk_a, payer);
    let b = opening_is_signed(bank, &public.pk_b, payee);
    a && b
}

fn owners_signed(public: &PayPublic, digest: &Bytes32) -> bool {
    let a = verify_digest(&public.pk_a, digest, &public.sig_a).is_ok();
    let b = verify_digest(&public.pk_b, digest, &public.sig_b).is_ok();
    a && b
}

fn within_bounds(v: u64, payer: &Opening, payee: &Opening) -> bool {
    let payee_next = payee.balance.checked_add(v);
    v != 0
        && v <= payer.balance
        && payee_next.is_some_and(|next| payee.side.is_bank() || next <= B_MAX)
}

fn next_serials_are_fresh(public: &PayPublic, payer: &Opening, payee: &Opening) -> bool {
    let current = [public.pk_a, public.pk_b];
    payer.next_pk != payee.next_pk
        && !current.contains(&payer.next_pk)
        && !current.contains(&payee.next_pk)
}

pub fn check_pay(
    bank: &BankVerifiers,
    public: &PayPublic,
    payer: &PaySecret,
    payee: &PaySecret,
) -> Result<Checked, Refusal> {
    let digest = pay_digest(
        &public.pk_a,
        &public.com_a_next,
        &public.pk_b,
        &public.com_b_next,
    );
    let a_next = payer.opening.balance.wrapping_sub(payer.v);
    let b_next = payee.opening.balance.wrapping_add(payer.v);
    let expected_a = commitment(a_next, &payer.opening.next_pk, &payer.opening.next_r);
    let expected_b = commitment(b_next, &payee.opening.next_pk, &payee.opening.next_r);
    let checks = [
        (public.pk_a == public.pk_b, Refusal::SameSerial),
        (
            !next_serials_are_fresh(public, &payer.opening, &payee.opening),
            Refusal::NextSerial,
        ),
        (payer.v != payee.v, Refusal::Amount),
        (
            !openings_are_signed(bank, public, &payer.opening, &payee.opening),
            Refusal::Opening,
        ),
        (!owners_signed(public, &digest), Refusal::OwnerSignature),
        (
            !within_bounds(payer.v, &payer.opening, &payee.opening),
            Refusal::Bounds,
        ),
        (
            expected_a != public.com_a_next || expected_b != public.com_b_next,
            Refusal::NextCommitment,
        ),
    ];
    first_failure(&checks)?;
    Ok(Checked {
        digest,
        sides: vec![payer.opening.side, payee.opening.side],
    })
}

pub fn check_enroll(request: &EnrollRequest, secret: &EnrollSecret) -> Result<Checked, Refusal> {
    let digest = enroll_digest(&request.pk0, &request.com0);
    let checks = [
        (
            commitment(0, &request.pk0, &secret.r0) != request.com0,
            Refusal::Opening,
        ),
        (
            verify_digest(&request.pk0, &digest, &request.sig).is_err(),
            Refusal::OwnerSignature,
        ),
    ];
    first_failure(&checks)?;
    Ok(Checked {
        digest,
        sides: vec![SideKind::User],
    })
}

pub fn check_refresh(
    bank: &BankVerifiers,
    request: &RefreshRequest,
    secret: &RefreshSecret,
) -> Result<Checked, Refusal> {
    let opening = &secret.opening;
    let digest = refresh_digest(&request.pk, &request.com_next);
    let expected = commitment(opening.balance, &opening.next_pk, &opening.next_r);
    let checks = [
        (opening.next_pk == request.pk, Refusal::NextSerial),
        (
            !opening_is_signed(bank, &request.pk, opening),
            Refusal::Opening,
        ),
        (
            verify_digest(&request.pk, &digest, &request.sig).is_err(),
            Refusal::OwnerSignature,
        ),
        (expected != request.com_next, Refusal::NextCommitment),
    ];
    first_failure(&checks)?;
    Ok(Checked {
        digest,
        sides: vec![opening.side],
    })
}
