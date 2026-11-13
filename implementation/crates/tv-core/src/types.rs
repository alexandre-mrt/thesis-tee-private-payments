use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::commit::commitment;
use crate::sig::Signature;

pub type Bytes32 = [u8; 32];

pub fn random_bytes32() -> Bytes32 {
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BankKeys {
    pub state_pk: Bytes32,
    pub issuance_pk: Bytes32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub result_pk: Bytes32,
    pub bank: BankKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SideKind {
    User,
    Bank,
}

impl SideKind {
    pub fn is_bank(self) -> bool {
        matches!(self, SideKind::Bank)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub balance: u64,
    pub pk: Bytes32,
    pub r: Bytes32,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "State(pk={}, ..)", hex::encode(self.pk))
    }
}

impl State {
    pub fn commitment(&self) -> Bytes32 {
        commitment(self.balance, &self.pk, &self.r)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedState {
    pub state: State,
    pub sig: Signature,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opening {
    pub balance: u64,
    pub r: Bytes32,
    pub sig: Signature,
    pub side: SideKind,
    pub next_pk: Bytes32,
    pub next_r: Bytes32,
}

impl std::fmt::Debug for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opening(..)")
    }
}
