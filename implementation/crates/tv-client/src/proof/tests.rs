use super::*;

fn facts(holder: Option<(Role, Bytes32)>, transferable: bool) -> ProofFacts {
    ProofFacts {
        seq: 3,
        epoch: 7,
        v: 120,
        memo: Some("invoice 42".to_owned()),
        holder,
        transferable,
    }
}

#[test]
fn a_designated_proof_is_never_described_as_deniable_for_the_amount() {
    let line = describe(&facts(Some((Role::Payee, [9u8; 32])), false));
    assert!(line.contains("moved 120"), "{line}");
    assert!(line.contains(DESIGNATED_SCOPE), "{line}");
    assert!(!line.contains("not transferable"), "{line}");
}

#[test]
fn a_signed_proof_is_described_as_transferable() {
    let line = describe(&facts(Some((Role::Payer, [9u8; 32])), true));
    assert!(line.contains("(transferable)"), "{line}");
    assert!(!line.contains(DESIGNATED_SCOPE), "{line}");
}
