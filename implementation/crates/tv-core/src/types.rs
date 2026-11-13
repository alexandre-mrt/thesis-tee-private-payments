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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_secrets() {
        let state = State {
            balance: 42,
            pk: [1u8; 32],
            r: [2u8; 32],
        };
        let text = format!("{state:?}");
        assert!(!text.contains("42"));
        assert!(!text.contains(&hex::encode([2u8; 32])));
        let opening = Opening {
            balance: 42,
            r: [2u8; 32],
            sig: Signature([0u8; 64]),
            side: SideKind::User,
            next_pk: [3u8; 32],
            next_r: [4u8; 32],
        };
        assert_eq!(format!("{opening:?}"), "Opening(..)");
        assert_ne!(random_bytes32(), random_bytes32());
    }
}
