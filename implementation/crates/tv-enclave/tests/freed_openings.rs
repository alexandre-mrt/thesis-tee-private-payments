use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use tv_core::{BankKeys, EnclaveResponse, SigningKey};
use tv_enclave::{Enclave, ZeroAlloc, attestation_provider};

mod common;

use common::{PAYEE_NEXT_R, PAYER_NEXT_R, pay_op};

const PAYER_MARK: [u8; 66] = cbor_array_of(PAYER_NEXT_R[0]);
const PAYEE_MARK: [u8; 66] = cbor_array_of(PAYEE_NEXT_R[0]);

const fn cbor_array_of(byte: u8) -> [u8; 66] {
    let mut mark = [0u8; 66];
    mark[0] = 0x98;
    mark[1] = 0x20;
    let mut i = 0;
    while i < 32 {
        mark[2 + 2 * i] = 0x18;
        mark[3 + 2 * i] = byte;
        i += 1;
    }
    mark
}

static ARMED: AtomicBool = AtomicBool::new(false);
static FREED: AtomicUsize = AtomicUsize::new(0);
static HITS: AtomicUsize = AtomicUsize::new(0);

fn holds_an_opening(block: &[u8]) -> bool {
    [PAYER_MARK, PAYEE_MARK]
        .iter()
        .any(|mark| block.windows(mark.len()).any(|window| window == mark))
}

struct Scanner;

unsafe impl GlobalAlloc for Scanner {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(SeqCst) {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            FREED.fetch_add(1, SeqCst);
            if holds_an_opening(block) {
                HITS.fetch_add(1, SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ZeroAlloc<Scanner> = ZeroAlloc(Scanner);

fn scanner_sees_an_unwiped_opening() -> bool {
    let layout = Layout::from_size_align(PAYER_MARK.len(), 1).unwrap();
    let before = HITS.load(SeqCst);
    unsafe {
        let ptr = System.alloc(layout);
        ptr.copy_from_nonoverlapping(PAYER_MARK.as_ptr(), PAYER_MARK.len());
        Scanner.dealloc(ptr, layout);
    }
    HITS.swap(before, SeqCst) == before + 1
}

#[test]
fn the_enclave_allocator_wipes_decrypted_openings_before_freeing_them() {
    let bank = BankKeys {
        state_pk: SigningKey::generate().public_key(),
        issuance_pk: SigningKey::generate().public_key(),
    };
    let enclave = Enclave::boot(bank, attestation_provider(true).unwrap()).unwrap();
    let op = pay_op(&enclave);
    ARMED.store(true, SeqCst);
    let detector_works = scanner_sees_an_unwiped_opening();
    let answer = enclave.check([9u8; 32], &op);
    ARMED.store(false, SeqCst);
    assert!(detector_works);
    assert!(matches!(answer, EnclaveResponse::Refused));
    assert_eq!(enclave.pending_keys(), 0);
    assert!(FREED.load(SeqCst) > 0);
    assert_eq!(HITS.load(SeqCst), 0);
}
