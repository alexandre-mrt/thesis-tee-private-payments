use proptest::prelude::*;
use tv_bank::BankError;
use tv_bank::flight::{header, replay, trailer};
use tv_core::{
    LogEntry, OpKind, Signature, SigningKey, VerifyingKey, chain_genesis, is_fork, sign_digest,
};

const MAX_ENTRIES: u64 = 6;

fn body(seq: u64) -> LogEntry {
    let owner = SigningKey::from_bytes(&[seq as u8 + 1; 32]);
    let digest = [seq as u8 + 50; 32];
    LogEntry {
        seq,
        kind: OpKind::Refresh,
        serials: vec![owner.public_key()],
        commitments: vec![[seq as u8 + 100; 32]],
        sigs: vec![Signature([seq as u8; 64])],
        owner_sigs: vec![sign_digest(&owner, &digest)],
        digest,
        c_v: None,
        h_ctx: None,
        epoch: 5,
        chain: [0u8; 32],
        rcpt: Signature([0u8; 64]),
    }
}

fn sealed_log(key: &SigningKey, count: u64) -> Vec<LogEntry> {
    let mut head = chain_genesis(&key.public_key());
    (0..count)
        .map(|seq| {
            let entry = body(seq).sealed(&head, key);
            head = entry.chain;
            entry
        })
        .collect()
}

fn framed(key: &SigningKey, entries: &[LogEntry]) -> Vec<u8> {
    let flights = entries.iter().flat_map(|entry| {
        let mut line = serde_json::to_vec(entry).unwrap();
        line.push(b'\n');
        let frame = trailer(&line);
        [line, frame].concat()
    });
    header(&key.public_key())
        .into_iter()
        .chain(flights)
        .collect()
}

fn flipped(entry: &LogEntry, field: usize, byte: usize) -> LogEntry {
    let mut out = entry.clone();
    match field {
        0 => out.chain[byte % 32] ^= 1,
        1 => out.rcpt.0[byte % 64] ^= 1,
        2 => out.commitments[0][byte % 32] ^= 1,
        3 => out.epoch ^= 1 << (byte % 64),
        _ => out.sigs[0].0[byte % 64] ^= 1,
    }
    out
}

proptest! {
    #[test]
    fn nr6_a_reframed_log_with_one_changed_field_is_refused(
        count in 1..=MAX_ENTRIES,
        target in 0..MAX_ENTRIES,
        field in 0usize..5,
        byte in 0usize..64,
    ) {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut entries = sealed_log(&key, count);
        let target = usize::try_from(target % count).unwrap();
        entries[target] = flipped(&entries[target], field, byte);
        let refused = matches!(
            replay(&framed(&key, &entries)),
            Err(BankError::Corrupt { .. })
        );
        prop_assert!(refused);
    }

    #[test]
    fn nr6_a_flipped_byte_never_yields_a_changed_entry(
        count in 1..=MAX_ENTRIES,
        position in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let entries = sealed_log(&key, count);
        let mut bytes = framed(&key, &entries);
        let head = header(&key.public_key()).len();
        let at = head + position.index(bytes.len() - head);
        bytes[at] ^= mask;
        if let Ok((index, _)) = replay(&bytes) {
            let kept = index.entries();
            prop_assert!(kept.len() < entries.len());
            prop_assert_eq!(kept, &entries[..kept.len()]);
        }
    }
}

#[test]
fn nr6_an_intact_log_replays_and_two_receipts_for_one_seq_are_a_fork() {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let entries = sealed_log(&key, 4);
    let (index, consumed) = replay(&framed(&key, &entries)).unwrap();
    assert_eq!(index.entries(), &entries[..]);
    assert_eq!(index.head(), entries[3].chain);
    assert_eq!(consumed, framed(&key, &entries).len());
    let pk = VerifyingKey::parse(&key.public_key()).unwrap();
    let rewritten = flipped(&entries[2], 2, 0).sealed(&entries[1].chain, &key);
    assert!(is_fork(&pk, &entries[2], &rewritten));
    assert!(!is_fork(&pk, &entries[2], &entries[2]));
}
