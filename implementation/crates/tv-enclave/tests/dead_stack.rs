use std::hint::black_box;
use std::thread;

use tv_core::{BankKeys, EnclaveResponse, SigningKey};
use tv_enclave::{ENCLAVE_ALLOCATOR, Enclave, EnclaveAllocator, attestation_provider};

mod common;

use common::{
    AMOUNT, PAYEE_NEXT_PK, PAYEE_NEXT_R, PAYER_BALANCE, PAYER_NEXT_PK, PAYER_NEXT_R, pay_op,
};

#[global_allocator]
static ALLOCATOR: EnclaveAllocator = ENCLAVE_ALLOCATOR;

const THREAD_STACK: usize = 4 * 1024 * 1024;
const SCANNED: usize = 512 * 1024;
const CALLER_MARGIN: usize = 4096;
const PLANT_DEPTH: usize = 16 * 1024;

fn secrets() -> Vec<Vec<u8>> {
    vec![
        PAYER_NEXT_R.to_vec(),
        PAYEE_NEXT_R.to_vec(),
        PAYER_NEXT_PK.to_vec(),
        PAYEE_NEXT_PK.to_vec(),
        AMOUNT.to_le_bytes().to_vec(),
        PAYER_BALANCE.to_le_bytes().to_vec(),
    ]
}

fn read(address: usize) -> u8 {
    unsafe { std::ptr::read_volatile(address as *const u8) }
}

fn matches_at(address: usize, needle: &[u8]) -> bool {
    needle
        .iter()
        .enumerate()
        .all(|(i, byte)| read(address + i) == *byte)
}

#[inline(never)]
fn dead_stack_hits(needles: &[Vec<u8>]) -> usize {
    let marker = 0u8;
    let top = black_box(&marker as *const u8 as usize) - CALLER_MARGIN;
    let bottom = top - SCANNED;
    let mut hits = 0;
    for needle in needles {
        for address in bottom..top - needle.len() {
            if matches_at(address, needle) {
                hits += 1;
            }
        }
    }
    hits
}

#[inline(never)]
fn plant(needle: &[u8]) {
    let mut frame = [0u8; PLANT_DEPTH];
    frame[..needle.len()].copy_from_slice(needle);
    black_box(&mut frame);
}

#[test]
fn a_checked_request_leaves_no_opening_on_the_dead_stack_of_its_thread() {
    let bank = BankKeys {
        state_pk: SigningKey::generate().public_key(),
        issuance_pk: SigningKey::generate().public_key(),
    };
    let enclave = Enclave::boot(bank, attestation_provider(true).unwrap()).unwrap();
    let op = pay_op(&enclave);
    let needles = secrets();
    thread::scope(|scope| {
        let worker = thread::Builder::new()
            .stack_size(THREAD_STACK)
            .spawn_scoped(scope, || {
                plant(&PAYER_NEXT_R);
                let planted = dead_stack_hits(&needles);
                plant(&[0u8; 32]);
                let answer = enclave.check([9u8; 32], &op);
                (planted, answer, dead_stack_hits(&needles))
            })
            .unwrap();
        let (planted, answer, residue) = worker.join().unwrap();
        assert_eq!(planted, 1);
        assert!(matches!(answer, EnclaveResponse::Refused));
        assert_eq!(enclave.pending_keys(), 0);
        assert_eq!(residue, 0);
    });
}
