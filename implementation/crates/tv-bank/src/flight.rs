use serde::Deserialize;
use sha2::{Digest, Sha256};
use tv_core::LogEntry;

use crate::error::BankError;
use crate::index::Index;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trailer {
    flight: Frame,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    len: usize,
    sha256: String,
}

impl Frame {
    fn sealed_start(&self, before: &[u8]) -> Option<usize> {
        let start = before.len().checked_sub(self.len)?;
        (hex::encode(Sha256::digest(&before[start..])) == self.sha256).then_some(start)
    }
}

pub const LOG_FORMAT: &str = "flights";

pub fn header() -> Vec<u8> {
    format!("{{\"log\":\"{LOG_FORMAT}\"}}\n").into_bytes()
}

pub fn trailer(lines: &[u8]) -> Vec<u8> {
    format!(
        "{{\"flight\":{{\"len\":{},\"sha256\":\"{}\"}}}}\n",
        lines.len(),
        hex::encode(Sha256::digest(lines))
    )
    .into_bytes()
}

enum Line {
    Entry(Box<LogEntry>),
    Trailer(Frame),
    Zeroed,
    Garbage,
}

fn parse(raw: &[u8]) -> Line {
    if let Ok(entry) = serde_json::from_slice::<LogEntry>(raw) {
        return Line::Entry(Box::new(entry));
    }
    match serde_json::from_slice::<Trailer>(raw) {
        Ok(trailer) => Line::Trailer(trailer.flight),
        Err(_) if raw.contains(&0) => Line::Zeroed,
        Err(_) => Line::Garbage,
    }
}

fn corrupt(line: usize, reason: &str) -> BankError {
    BankError::Corrupt {
        line,
        reason: reason.to_owned(),
    }
}

struct Tail {
    start: usize,
    first_line: Option<usize>,
    entries: Vec<LogEntry>,
    damage: Option<usize>,
    garbage: Option<usize>,
    bad_trailer: Option<usize>,
}

impl Tail {
    fn at(start: usize) -> Self {
        Self {
            start,
            first_line: None,
            entries: Vec::new(),
            damage: None,
            garbage: None,
            bad_trailer: None,
        }
    }

    fn unconfirmed_flight(&self, next_seq: u64) -> bool {
        self.damage.is_none()
            && self
                .entries
                .iter()
                .zip(next_seq..)
                .all(|(entry, seq)| entry.seq == seq)
    }

    fn note(&mut self, line: usize, parsed: Line) {
        match parsed {
            Line::Entry(entry) => return self.entries.push(*entry),
            Line::Trailer(_) => {
                self.bad_trailer.get_or_insert(line);
            }
            Line::Garbage => {
                self.garbage.get_or_insert(line);
            }
            Line::Zeroed => {}
        }
        self.damage.get_or_insert(line);
    }

    fn seal(self, sealed: usize, line: usize) -> Result<Vec<LogEntry>, BankError> {
        if let Some(damaged) = self.damage {
            return Err(corrupt(
                damaged,
                "damaged before a later flight that landed whole",
            ));
        }
        if sealed != self.start {
            let first = self.first_line.unwrap_or(line);
            return Err(corrupt(first, "not covered by a flight trailer"));
        }
        Ok(self.entries)
    }

    fn check_torn(&self, bytes: &[u8], next_seq: u64) -> Result<(), BankError> {
        let rest = &bytes[self.start..];
        let zeroed = rest.contains(&0);
        let fragment = !rest.is_empty() && !rest.ends_with(b"\n");
        if let Some(line) = self.garbage {
            return Err(corrupt(line, "undecodable line without zero bytes"));
        }
        match (self.bad_trailer, self.first_line) {
            (Some(line), _) if !zeroed => {
                Err(corrupt(line, "flight trailer does not match its lines"))
            }
            (_, Some(line)) if !zeroed && !fragment && !self.unconfirmed_flight(next_seq) => {
                Err(corrupt(
                    line,
                    "the lines after the last flight trailer are not a torn flight",
                ))
            }
            _ => Ok(()),
        }
    }
}

pub fn replay(bytes: &[u8]) -> Result<(Index, usize), BankError> {
    let head = header();
    if !bytes.starts_with(&head) {
        return Err(corrupt(0, "log header missing or damaged"));
    }
    let mut index = Index::default();
    let mut tail = Tail::at(head.len());
    let mut start = head.len();
    for (line, raw) in bytes[start..].split(|b| *b == b'\n').enumerate() {
        let line = line + 1;
        let end = start + raw.len() + 1;
        if end > bytes.len() {
            break;
        }
        tail.first_line.get_or_insert(line);
        match parse(raw) {
            Line::Trailer(frame) => match frame.sealed_start(&bytes[..start]) {
                Some(sealed) => {
                    let flight = std::mem::replace(&mut tail, Tail::at(end));
                    for entry in flight.seal(sealed, line)? {
                        index.apply(entry)?;
                    }
                }
                None => tail.note(line, Line::Trailer(frame)),
            },
            parsed => tail.note(line, parsed),
        }
        start = end;
    }
    tail.check_torn(bytes, index.len())?;
    Ok((index, tail.start))
}

#[cfg(test)]
mod tests;
