use tv_bank::{AuditError, audit_entries, read_log_entries};
use tv_client::{Wallet, flows};
use tv_core::{LogEntry, OpKind, Signature};
use tv_tests::Harness;

async fn busy_log(h: &Harness) -> (Wallet, Wallet) {
    let mut alice = h.wallet("alice");
    let mut bob = h.wallet("bob");
    h.enroll(&mut alice).await;
    h.enroll(&mut bob).await;
    h.issue(&mut alice, 500).await.unwrap();
    h.transfer(&mut alice, &mut bob, 120).await.unwrap();
    flows::refresh(&mut bob, &h.client, false).await.unwrap();
    h.transfer(&mut bob, &mut alice, 20).await.unwrap();
    (alice, bob)
}

fn first_pay(entries: &[LogEntry]) -> LogEntry {
    entries
        .iter()
        .find(|e| e.kind == OpKind::Pay)
        .cloned()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_log_replays_b2_and_b4_on_the_live_log_and_on_disk() {
    let h = Harness::new().await;
    busy_log(&h).await;
    let entries = h.bank().entries();
    let audit = audit_entries(&entries).unwrap();
    assert_eq!(audit.entries, entries.len() as u64);
    assert_eq!(audit.payments, 3);
    assert!(
        entries
            .iter()
            .all(|e| e.owner_sigs.len() == e.serials.len())
    );
    assert!(
        entries
            .iter()
            .all(|e| (e.kind == OpKind::Pay) == (e.c_v.is_some() && e.h_ctx.is_some()))
    );
    assert_eq!(read_log_entries(h.dir()).unwrap(), entries);
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_log_fails_on_a_serial_spent_twice_or_a_replaced_owner_signature() {
    let h = Harness::new().await;
    busy_log(&h).await;
    let entries = h.bank().entries();
    let replayed = LogEntry {
        seq: entries.len() as u64,
        ..first_pay(&entries)
    };
    let twice: Vec<LogEntry> = entries.iter().cloned().chain([replayed]).collect();
    assert!(matches!(
        audit_entries(&twice),
        Err(AuditError::Serial {
            reason: "was already spent",
            ..
        })
    ));

    let pay = first_pay(&entries);
    let replaced: Vec<LogEntry> = entries
        .iter()
        .map(|e| match e.seq == pay.seq {
            true => LogEntry {
                owner_sigs: vec![e.owner_sigs[0], Signature([1u8; 64])],
                ..e.clone()
            },
            false => e.clone(),
        })
        .collect();
    assert!(matches!(
        audit_entries(&replaced),
        Err(AuditError::Owners { seq, .. }) if seq == pay.seq
    ));

    let gap: Vec<LogEntry> = entries.iter().skip(1).cloned().collect();
    assert!(matches!(
        audit_entries(&gap),
        Err(AuditError::Sequence { position: 0, .. })
    ));
}
