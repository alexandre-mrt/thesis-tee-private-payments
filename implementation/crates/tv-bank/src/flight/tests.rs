use tv_core::OpKind;

use super::*;
use crate::journal::LOG_FILE;
use crate::journal::testing::{entry, temp_dir};
use crate::store::Store;

const PAGE: usize = 4096;

fn line(seq: u64, serial: u8) -> Vec<u8> {
    let mut line = serde_json::to_vec(&entry(seq, OpKind::Pay, seq as u8 + serial)).unwrap();
    line.push(b'\n');
    line
}

fn flight(lines: &[Vec<u8>]) -> Vec<u8> {
    let body = lines.concat();
    [body.clone(), trailer(&body)].concat()
}

fn single_flights(count: u64) -> Vec<u8> {
    let flights = (0..count).flat_map(|seq| flight(&[line(seq, 1)]));
    header().into_iter().chain(flights).collect()
}

fn torn_two_entry_flight() -> (Vec<u8>, Vec<u8>, u64) {
    for count in 1..64 {
        let prior = single_flights(count);
        let first = line(count, 1);
        let boundary = prior.len().div_ceil(PAGE) * PAGE;
        if boundary > prior.len() && boundary < prior.len() + first.len() {
            let mut torn = [prior.clone(), flight(&[first, line(count + 1, 1)])].concat();
            torn[prior.len()..boundary].fill(0);
            return (prior, torn, count);
        }
    }
    unreachable!("no flight crosses a page boundary")
}

fn open_bytes(tag: &str, bytes: &[u8]) -> (usize, u64) {
    let dir = temp_dir(tag);
    std::fs::write(dir.join(LOG_FILE), bytes).unwrap();
    let entries = Store::open(&dir).unwrap().entries().len();
    let len = std::fs::metadata(dir.join(LOG_FILE)).unwrap().len();
    std::fs::remove_dir_all(dir).unwrap();
    (entries, len)
}

#[test]
fn a_trailer_round_trips_and_seals_only_its_own_lines() {
    let lines = [line(0, 1), line(1, 1)].concat();
    let Line::Trailer(frame) = parse(trailer(&lines).strip_suffix(b"\n").unwrap()) else {
        panic!("the trailer does not parse as a trailer");
    };
    assert_eq!(frame.sealed_start(&lines), Some(0));
    let mut flipped = lines.clone();
    flipped[3] ^= 1;
    assert_eq!(frame.sealed_start(&flipped), None);
    assert!(matches!(parse(&line(0, 1)[..10]), Line::Garbage));
}

#[test]
fn a_torn_multi_line_flight_whose_later_page_landed_is_dropped() {
    let (prior, torn, kept) = torn_two_entry_flight();
    let (index, consumed) = replay(&torn).unwrap();
    assert_eq!(index.len(), kept);
    assert_eq!(consumed, prior.len());
    let (entries, len) = open_bytes("torn-flight", &torn);
    assert_eq!(entries as u64, kept);
    assert_eq!(len, prior.len() as u64);
}

#[test]
fn a_zeroed_single_line_flight_and_an_unterminated_one_are_dropped() {
    let good = single_flights(2);
    let mut zeroed = [good.clone(), flight(&[line(2, 1)])].concat();
    zeroed[good.len()..good.len() + 40].fill(0);
    let (index, consumed) = replay(&zeroed).unwrap();
    assert_eq!((index.len(), consumed), (2, good.len()));
    let mut cut = [good.clone(), flight(&[line(2, 1)])].concat();
    cut.truncate(cut.len() - 7);
    assert_eq!(replay(&cut).unwrap().1, good.len());
    let landed_lines_only = [good.clone(), line(2, 1), line(3, 1)[..10].to_vec()].concat();
    assert_eq!(replay(&landed_lines_only).unwrap().1, good.len());
}

#[test]
fn zeros_before_a_valid_trailer_are_fatal() {
    let (_, torn, kept) = torn_two_entry_flight();
    let later = flight(&[line(kept + 2, 1)]);
    let damaged_prefix = [torn, later].concat();
    assert!(matches!(
        replay(&damaged_prefix),
        Err(BankError::Corrupt { .. })
    ));
    let mut zeroed_first = single_flights(3);
    zeroed_first[header().len()..header().len() + 8].fill(0);
    assert!(matches!(
        replay(&zeroed_first),
        Err(BankError::Corrupt { line: 1, .. })
    ));
}

#[test]
fn damage_without_zero_bytes_is_fatal() {
    let good = single_flights(2);
    let mut garbage = good.clone();
    garbage.extend(b"{\"seq\":2,\"kind\":\"Pay\"}\n");
    assert!(matches!(
        replay(&garbage),
        Err(BankError::Corrupt { line: 5, .. })
    ));
    let mut rotten_tail = [good.clone(), flight(&[line(2, 1)])].concat();
    let digit = rotten_tail.len() - 5;
    rotten_tail[digit] = if rotten_tail[digit] == b'a' {
        b'b'
    } else {
        b'a'
    };
    assert!(matches!(
        replay(&rotten_tail),
        Err(BankError::Corrupt { line: 6, .. })
    ));
    let mut flipped = single_flights(3);
    let at = flipped.iter().position(|b| *b == b'7').unwrap();
    flipped[at] = b'8';
    assert!(matches!(replay(&flipped), Err(BankError::Corrupt { .. })));
}

#[test]
fn entries_without_a_trailer_are_fatal_unless_torn() {
    let flights = single_flights(2)[header().len()..].to_vec();
    let unframed = [header(), line(0, 1), line(1, 1), flights.clone()].concat();
    assert!(matches!(
        replay(&unframed),
        Err(BankError::Corrupt { line: 1, .. })
    ));
    let missing_trailer = [header(), line(0, 1), flights].concat();
    assert!(replay(&missing_trailer).is_err());
    let headed_legacy = [header(), line(0, 1)].concat();
    assert!(replay(&headed_legacy).is_ok());
    let gap_after = [single_flights(2), line(3, 1)].concat();
    assert!(matches!(
        replay(&gap_after),
        Err(BankError::Corrupt { line: 5, .. })
    ));
    let repeat_after = [single_flights(2), line(1, 1)].concat();
    assert!(matches!(
        replay(&repeat_after),
        Err(BankError::Corrupt { line: 5, .. })
    ));
    let late_header = [single_flights(2), header(), line(2, 1)].concat();
    assert!(matches!(
        replay(&late_header),
        Err(BankError::Corrupt { line: 5, .. })
    ));
}

#[test]
fn a_final_flight_cut_at_a_newline_before_its_trailer_is_dropped() {
    let good = single_flights(3);
    let one_line = [good.clone(), line(3, 1)].concat();
    let two_lines = [good.clone(), line(3, 1), line(4, 1)].concat();
    for torn in [&one_line, &two_lines] {
        let (index, consumed) = replay(torn).unwrap();
        assert_eq!((index.len(), consumed), (3, good.len()));
        let (entries, len) = open_bytes("cut-at-newline", torn);
        assert_eq!((entries, len), (3, good.len() as u64));
    }
    let first_flight = [header(), line(0, 1), line(1, 1)].concat();
    let (index, consumed) = replay(&first_flight).unwrap();
    assert_eq!((index.len(), consumed), (0, header().len()));
}

#[test]
fn a_fresh_log_holds_only_its_header_and_a_cut_first_flight_reopens() {
    let dir = temp_dir("fresh-header");
    crate::journal::create_log(&dir).unwrap();
    let path = dir.join(LOG_FILE);
    assert_eq!(std::fs::read(&path).unwrap(), header());
    let mut store = Store::open(&dir).unwrap();
    store.append(entry(0, OpKind::Enroll, 1)).unwrap();
    store.append(entry(1, OpKind::Pay, 2)).unwrap();
    drop(store);
    let full = std::fs::read(&path).unwrap();
    let mut last = serde_json::to_vec(&entry(1, OpKind::Pay, 2)).unwrap();
    last.push(b'\n');
    let cut = full.len() - trailer(&last).len();
    std::fs::write(&path, &full[..cut]).unwrap();
    assert_eq!(Store::open(&dir).unwrap().entries().len(), 1);
    let kept = std::fs::metadata(&path).unwrap().len() as usize;
    assert_eq!(kept, cut - last.len());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_log_without_its_whole_header_is_refused_and_never_truncated() {
    let flights = single_flights(2)[header().len()..].to_vec();
    let unterminated = header()[..header().len() - 1].to_vec();
    for damaged in [
        Vec::new(),
        b"{\"log\":\"fl".to_vec(),
        unterminated.clone(),
        [unterminated, flights.clone()].concat(),
        flights,
    ] {
        assert!(matches!(
            replay(&damaged),
            Err(BankError::Corrupt { line: 0, .. })
        ));
        let dir = temp_dir("headerless");
        let path = dir.join(LOG_FILE);
        std::fs::write(&path, &damaged).unwrap();
        assert!(Store::open(&dir).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), damaged);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
