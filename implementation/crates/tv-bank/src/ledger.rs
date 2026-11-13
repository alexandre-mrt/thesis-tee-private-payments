use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use tv_client::ops::Session;
use tv_client::{OfferFile, RequestFile};
use tv_core::{Bytes32, pay_digest};

use crate::error::BankError;
use crate::journal::is_zeroed_tail;
use crate::registry::now_unix_secs;

pub const ISSUANCE_LEDGER_FILE: &str = "issuance.jsonl";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRecord {
    pub unix_secs: u64,
    pub amount: u64,
    pub payee: Bytes32,
    pub digest: Bytes32,
}

pub fn ledger_path(dir: &Path) -> PathBuf {
    dir.join(ISSUANCE_LEDGER_FILE)
}

fn open_ledger(path: &Path) -> Result<File, BankError> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(BankError::file(path))
}

fn parse_records(bytes: &[u8]) -> Result<(Vec<IssuanceRecord>, usize), BankError> {
    let mut records = Vec::new();
    let mut consumed = 0usize;
    for (line, raw) in bytes.split(|b| *b == b'\n').enumerate() {
        let end = consumed + raw.len() + 1;
        if end > bytes.len() {
            break;
        }
        let record = match serde_json::from_slice(raw) {
            Ok(record) => record,
            Err(_) if is_zeroed_tail::<IssuanceRecord>(raw, &bytes[end..]) => break,
            Err(e) => {
                return Err(BankError::LedgerCorrupt {
                    line,
                    reason: e.to_string(),
                });
            }
        };
        records.push(record);
        consumed = end;
    }
    Ok((records, consumed))
}

pub fn record_issuance(dir: &Path, record: &IssuanceRecord) -> Result<bool, BankError> {
    let path = ledger_path(dir);
    let mut file = open_ledger(&path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(BankError::file(&path))?;
    let (records, durable) = parse_records(&bytes)?;
    if records.iter().any(|known| known.digest == record.digest) {
        return Ok(false);
    }
    if durable < bytes.len() {
        warn!(
            dropped = bytes.len() - durable,
            "torn issuance ledger tail truncated"
        );
        file.set_len(durable as u64)
            .and_then(|()| file.sync_all())
            .map_err(BankError::file(&path))?;
    }
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    file.write_all(&line)
        .and_then(|()| file.sync_all())
        .map_err(BankError::file(&path))?;
    Ok(true)
}

pub fn read_issuances(dir: &Path) -> Result<Vec<IssuanceRecord>, BankError> {
    let path = ledger_path(dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).map_err(BankError::file(&path))?;
    let (records, _) = parse_records(&bytes)?;
    Ok(records)
}

fn record_of(request: &RequestFile, offer: &OfferFile) -> Result<IssuanceRecord, BankError> {
    Ok(IssuanceRecord {
        unix_secs: u64::try_from(now_unix_secs()?).map_err(|_| BankError::Clock)?,
        amount: request.v,
        payee: request.pk_b,
        digest: pay_digest(
            &offer.pk_a,
            &offer.com_a_next,
            &offer.pk_b,
            &offer.com_b_next,
        ),
    })
}

pub fn issue(
    dir: &Path,
    session: &Session,
    to_request: &Path,
    out: &Path,
    agreed: u64,
) -> Result<String, BankError> {
    let (request, _) = session.pay_offer_with(to_request, out, false, |request, offer| {
        if request.v != agreed {
            return Err(BankError::IssueAmount {
                agreed,
                requested: request.v,
            });
        }
        let record = record_of(request, offer)?;
        let recorded = record_issuance(dir, &record)?;
        info!(amount = record.amount, payee = %hex::encode(record.payee), recorded, "issuance");
        Ok::<(), BankError>(())
    })?;
    Ok(format!(
        "issued {} to {}: offer written to {}, recorded in {}",
        request.v,
        hex::encode(request.pk_b),
        out.display(),
        ledger_path(dir).display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tv-ledger-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn record(n: u8, amount: u64) -> IssuanceRecord {
        IssuanceRecord {
            unix_secs: u64::from(n),
            amount,
            payee: [n; 32],
            digest: [n + 1; 32],
        }
    }

    #[test]
    fn an_unreadable_ledger_error_names_the_ledger_file() {
        let dir = ledger_dir("unreadable");
        std::fs::create_dir(ledger_path(&dir)).unwrap();
        for err in [
            record_issuance(&dir, &record(1, 5)).unwrap_err(),
            read_issuances(&dir).unwrap_err(),
        ] {
            assert!(matches!(err, BankError::File { .. }));
            assert!(err.to_string().contains(ISSUANCE_LEDGER_FILE), "{err}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn records_append_and_read_back_in_order() {
        let dir = ledger_dir("order");
        assert!(read_issuances(&dir).unwrap().is_empty());
        let first = record(1, 500);
        let second = record(3, 7);
        assert!(record_issuance(&dir, &first).unwrap());
        assert!(record_issuance(&dir, &second).unwrap());
        assert_eq!(
            read_issuances(&dir).unwrap(),
            vec![first.clone(), second.clone()]
        );
        assert!(!record_issuance(&dir, &first).unwrap());
        assert_eq!(read_issuances(&dir).unwrap(), vec![first, second]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_ledger_is_private_and_a_corrupt_line_is_fatal() {
        let dir = ledger_dir("private");
        assert!(record_issuance(&dir, &record(1, 500)).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ledger_path(&dir))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(ledger_path(&dir), b"{\n").unwrap();
        assert!(matches!(
            read_issuances(&dir),
            Err(BankError::LedgerCorrupt { line: 0, .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_torn_tail_is_dropped_and_the_next_record_starts_on_its_own_line() {
        let dir = ledger_dir("torn");
        let first = record(1, 50);
        let second = record(3, 7);
        assert!(record_issuance(&dir, &first).unwrap());
        let path = ledger_path(&dir);
        let whole = std::fs::read(&path).unwrap();
        let mut torn = whole.clone();
        torn.extend_from_slice(&whole[..40]);
        std::fs::write(&path, &torn).unwrap();
        assert_eq!(read_issuances(&dir).unwrap(), vec![first.clone()]);
        assert!(record_issuance(&dir, &second).unwrap());
        assert_eq!(read_issuances(&dir).unwrap(), vec![first, second]);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        for line in text.lines() {
            serde_json::from_str::<IssuanceRecord>(line).unwrap();
        }
        assert!(text.ends_with('\n'));
        std::fs::remove_dir_all(dir).unwrap();
    }

    const ZEROED_LINE: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\n";

    fn two_records(tag: &str) -> (PathBuf, Vec<u8>) {
        let dir = ledger_dir(tag);
        assert!(record_issuance(&dir, &record(1, 50)).unwrap());
        assert!(record_issuance(&dir, &record(3, 7)).unwrap());
        let good = std::fs::read(ledger_path(&dir)).unwrap();
        (dir, good)
    }

    #[test]
    fn a_zeroed_newline_terminated_tail_is_dropped_and_the_next_issue_lands() {
        let (dir, good) = two_records("zeroed");
        let path = ledger_path(&dir);
        let third = record(5, 90);
        std::fs::write(&path, [good.as_slice(), ZEROED_LINE].concat()).unwrap();
        assert_eq!(
            read_issuances(&dir).unwrap(),
            vec![record(1, 50), record(3, 7)]
        );
        assert!(record_issuance(&dir, &third).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(!text.contains('\0'));
        assert_eq!(
            read_issuances(&dir).unwrap(),
            vec![record(1, 50), record(3, 7), third]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_zeroed_line_followed_by_a_record_is_fatal_and_names_the_ledger() {
        let (dir, good) = two_records("zeroed-then-landed");
        let mut landed = serde_json::to_vec(&record(5, 90)).unwrap();
        landed.push(b'\n');
        std::fs::write(
            ledger_path(&dir),
            [good.as_slice(), ZEROED_LINE, landed.as_slice()].concat(),
        )
        .unwrap();
        let err = read_issuances(&dir).unwrap_err();
        assert!(matches!(err, BankError::LedgerCorrupt { line: 2, .. }));
        assert!(
            err.to_string()
                .starts_with("issuance ledger line 2 is corrupt"),
            "{err}"
        );
        assert!(matches!(
            record_issuance(&dir, &record(7, 1)),
            Err(BankError::LedgerCorrupt { line: 2, .. })
        ));
        assert_eq!(
            std::fs::read_to_string(ledger_path(&dir))
                .unwrap()
                .lines()
                .count(),
            4
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
