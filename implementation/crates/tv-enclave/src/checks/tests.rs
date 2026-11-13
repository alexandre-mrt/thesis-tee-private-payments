use tv_core::{BankKeys, Signature, SigningKey, sign_digest, sign_state};

use super::*;

struct Party {
    sk: SigningKey,
    pk: Bytes32,
    r: Bytes32,
    next_pk: Bytes32,
    next_r: Bytes32,
    balance: u64,
}

fn party(balance: u64, seed: u8) -> Party {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    Party {
        pk: sk.public_key(),
        sk,
        r: [seed + 1; 32],
        next_pk: SigningKey::from_bytes(&[seed + 2; 32]).public_key(),
        next_r: [seed + 3; 32],
        balance,
    }
}

fn opening(p: &Party, signer: &SigningKey, side: SideKind) -> Opening {
    Opening {
        balance: p.balance,
        r: p.r,
        sig: sign_state(signer, &commitment(p.balance, &p.pk, &p.r)),
        side,
        next_pk: p.next_pk,
        next_r: p.next_r,
    }
}

struct Fixture {
    bank: BankVerifiers,
    public: PayPublic,
    payer: PaySecret,
    payee: PaySecret,
}

fn fixture(v: u64, a_balance: u64, b_balance: u64) -> (Fixture, SigningKey, SigningKey) {
    let state_key = SigningKey::generate();
    let issuance_key = SigningKey::generate();
    let bank = BankVerifiers::parse(&BankKeys {
        state_pk: state_key.public_key(),
        issuance_pk: issuance_key.public_key(),
    })
    .unwrap();
    let a = party(a_balance, 10);
    let b = party(b_balance, 20);
    let com_a_next = commitment(a_balance - v, &a.next_pk, &a.next_r);
    let com_b_next = commitment(b_balance + v, &b.next_pk, &b.next_r);
    let digest = pay_digest(&a.pk, &com_a_next, &b.pk, &com_b_next);
    let public = PayPublic {
        pk_a: a.pk,
        com_a_next,
        sig_a: sign_digest(&a.sk, &digest),
        pk_b: b.pk,
        com_b_next,
        sig_b: sign_digest(&b.sk, &digest),
    };
    let payer = PaySecret {
        v,
        opening: opening(&a, &state_key, SideKind::User),
    };
    let payee = PaySecret {
        v,
        opening: opening(&b, &state_key, SideKind::User),
    };
    (
        Fixture {
            bank,
            public,
            payer,
            payee,
        },
        state_key,
        issuance_key,
    )
}

#[test]
fn valid_payment_passes_with_user_sides() {
    let (f, _, _) = fixture(30, 100, 50);
    let checked = check_pay(&f.bank, &f.public, &f.payer, &f.payee).unwrap();
    assert_eq!(checked.sides, vec![SideKind::User, SideKind::User]);
    assert_eq!(
        checked.digest,
        pay_digest(
            &f.public.pk_a,
            &f.public.com_a_next,
            &f.public.pk_b,
            &f.public.com_b_next
        )
    );
}

#[test]
fn issuance_signed_side_is_a_bank_side_and_escapes_b_max() {
    let (mut f, _, issuance) = fixture(30, 100, B_MAX);
    let b = party(B_MAX, 20);
    f.payee.opening = opening(&b, &issuance, SideKind::Bank);
    let checked = check_pay(&f.bank, &f.public, &f.payer, &f.payee).unwrap();
    assert_eq!(checked.sides, vec![SideKind::User, SideKind::Bank]);
    let (f, _, _) = fixture(30, 100, B_MAX);
    assert_eq!(
        check_pay(&f.bank, &f.public, &f.payer, &f.payee),
        Err(Refusal::Bounds)
    );
}

#[test]
fn an_opening_claiming_the_other_side_is_refused() {
    let (mut f, state_key, issuance) = fixture(30, 100, 50);
    let b = party(50, 20);
    f.payee.opening = opening(&b, &issuance, SideKind::User);
    assert_eq!(
        check_pay(&f.bank, &f.public, &f.payer, &f.payee),
        Err(Refusal::Opening)
    );
    f.payee.opening = opening(&b, &state_key, SideKind::Bank);
    assert_eq!(
        check_pay(&f.bank, &f.public, &f.payer, &f.payee),
        Err(Refusal::Opening)
    );
    f.payee.opening = opening(&b, &state_key, SideKind::User);
    assert!(check_pay(&f.bank, &f.public, &f.payer, &f.payee).is_ok());
}

#[test]
fn zero_and_more_than_the_balance_are_out_of_bounds() {
    let (f, _, _) = fixture(0, 100, 50);
    assert_eq!(
        check_pay(&f.bank, &f.public, &f.payer, &f.payee),
        Err(Refusal::Bounds)
    );
    let (f, state_key, _) = fixture(101, 200, 50);
    let mut over = f.payer;
    over.opening = opening(&party(100, 10), &state_key, SideKind::User);
    assert_eq!(
        check_pay(&f.bank, &f.public, &over, &f.payee),
        Err(Refusal::Bounds)
    );
}

#[test]
fn every_check_refuses() {
    let (f, _, _) = fixture(30, 100, 50);
    let mut bad = f.payer;
    bad.v = 31;
    assert_eq!(
        check_pay(&f.bank, &f.public, &bad, &f.payee),
        Err(Refusal::Amount)
    );
    let mut both = f.payee;
    both.v = 31;
    assert_eq!(
        check_pay(&f.bank, &f.public, &bad, &both),
        Err(Refusal::NextCommitment)
    );
    let mut forged = f.payer;
    forged.opening.balance = 200;
    assert_eq!(
        check_pay(&f.bank, &f.public, &forged, &f.payee),
        Err(Refusal::Opening)
    );
    let mut unsigned = f.payer;
    unsigned.opening.sig = Signature([0u8; 64]);
    assert_eq!(
        check_pay(&f.bank, &f.public, &unsigned, &f.payee),
        Err(Refusal::Opening)
    );
    let mut public = f.public;
    public.sig_a = f.public.sig_b;
    assert_eq!(
        check_pay(&f.bank, &public, &f.payer, &f.payee),
        Err(Refusal::OwnerSignature)
    );
    let mut same = f.public;
    same.pk_b = same.pk_a;
    assert_eq!(
        check_pay(&f.bank, &same, &f.payer, &f.payee),
        Err(Refusal::SameSerial)
    );
}

#[test]
fn a_next_serial_equal_to_a_current_serial_or_to_the_other_next_serial_is_refused() {
    let (f, _, _) = fixture(30, 100, 50);
    let mut payee_reuses_payer = f.payee;
    payee_reuses_payer.opening.next_pk = f.public.pk_a;
    assert_eq!(
        check_pay(&f.bank, &f.public, &f.payer, &payee_reuses_payer),
        Err(Refusal::NextSerial)
    );
    let mut payee_stays = f.payee;
    payee_stays.opening.next_pk = f.public.pk_b;
    assert_eq!(
        check_pay(&f.bank, &f.public, &f.payer, &payee_stays),
        Err(Refusal::NextSerial)
    );
    let mut payer_reuses_payee = f.payer;
    payer_reuses_payee.opening.next_pk = f.public.pk_b;
    assert_eq!(
        check_pay(&f.bank, &f.public, &payer_reuses_payee, &f.payee),
        Err(Refusal::NextSerial)
    );
    let mut payer_shares = f.payer;
    payer_shares.opening.next_pk = f.payee.opening.next_pk;
    assert_eq!(
        check_pay(&f.bank, &f.public, &payer_shares, &f.payee),
        Err(Refusal::NextSerial)
    );
    assert!(check_pay(&f.bank, &f.public, &f.payer, &f.payee).is_ok());
}

#[test]
fn state_signed_by_another_key_is_refused() {
    let (mut f, _, _) = fixture(30, 100, 50);
    let a = party(100, 10);
    f.payer.opening = opening(&a, &SigningKey::generate(), SideKind::User);
    assert_eq!(
        check_pay(&f.bank, &f.public, &f.payer, &f.payee),
        Err(Refusal::Opening)
    );
}

fn empty_blob() -> tv_core::SealedBlob {
    tv_core::SealedBlob {
        client_pk: [0u8; 32],
        nonce: [0u8; 12],
        ciphertext: vec![],
    }
}

#[test]
fn enroll_checks() {
    let p = party(0, 40);
    let com0 = commitment(0, &p.pk, &p.r);
    let enroll = EnrollRequest {
        channel_pk: [0u8; 32],
        pk0: p.pk,
        com0,
        sig: sign_digest(&p.sk, &enroll_digest(&p.pk, &com0)),
        sealed: empty_blob(),
    };
    assert!(check_enroll(&enroll, &EnrollSecret { r0: p.r }).is_ok());
    assert_eq!(
        check_enroll(&enroll, &EnrollSecret { r0: [9u8; 32] }),
        Err(Refusal::Opening)
    );
    let mut bad_sig = enroll.clone();
    bad_sig.sig = Signature([1u8; 64]);
    assert_eq!(
        check_enroll(&bad_sig, &EnrollSecret { r0: p.r }),
        Err(Refusal::OwnerSignature)
    );
}

#[test]
fn refresh_checks() {
    let state_key = SigningKey::generate();
    let bank = BankVerifiers::parse(&BankKeys {
        state_pk: state_key.public_key(),
        issuance_pk: SigningKey::generate().public_key(),
    })
    .unwrap();
    let p = party(77, 50);
    let com_next = commitment(77, &p.next_pk, &p.next_r);
    let refresh = RefreshRequest {
        channel_pk: [0u8; 32],
        pk: p.pk,
        com_next,
        sig: sign_digest(&p.sk, &refresh_digest(&p.pk, &com_next)),
        sealed: empty_blob(),
    };
    let secret = RefreshSecret {
        opening: opening(&p, &state_key, SideKind::User),
    };
    assert_eq!(
        check_refresh(&bank, &refresh, &secret).unwrap().sides,
        vec![SideKind::User]
    );
    let mut more = secret;
    more.opening.balance = 78;
    assert_eq!(check_refresh(&bank, &refresh, &more), Err(Refusal::Opening));
    let mut other_owner = refresh.clone();
    other_owner.sig = sign_digest(&SigningKey::generate(), &refresh_digest(&p.pk, &com_next));
    assert_eq!(
        check_refresh(&bank, &other_owner, &secret),
        Err(Refusal::OwnerSignature)
    );
    let mut stays = secret;
    stays.opening.next_pk = p.pk;
    assert_eq!(
        check_refresh(&bank, &refresh, &stays),
        Err(Refusal::NextSerial)
    );
    let mut wrong_next = refresh;
    wrong_next.com_next = commitment(76, &p.next_pk, &p.next_r);
    wrong_next.sig = sign_digest(&p.sk, &refresh_digest(&p.pk, &wrong_next.com_next));
    assert_eq!(
        check_refresh(&bank, &wrong_next, &secret),
        Err(Refusal::NextCommitment)
    );
}
