use std::collections::BTreeMap;

use tv_core::{B_MAX, Bytes32, LogEntry, OpKind, SignedState, State, commitment};

use crate::bank::BankClient;
use crate::error::ClientError;
use crate::wallet::Wallet;

pub type Debits = BTreeMap<Bytes32, u64>;

fn matching_balance(
    previous: u64,
    hint: Option<u64>,
    pk: &Bytes32,
    r: &Bytes32,
    commitments: &[Bytes32],
) -> Option<(u64, Bytes32)> {
    let hit = |balance: u64| {
        let com = commitment(balance, pk, r);
        commitments.contains(&com).then_some((balance, com))
    };
    if let Some(found) = hint.and_then(hit).or_else(|| hit(previous)) {
        return Some(found);
    }
    (1..=B_MAX).find_map(|delta| {
        previous
            .checked_add(delta)
            .and_then(hit)
            .or_else(|| previous.checked_sub(delta).and_then(hit))
    })
}

fn step(
    wallet: &Wallet,
    index: u64,
    previous: u64,
    debits: &Debits,
    entry: &LogEntry,
) -> Result<SignedState, ClientError> {
    let pk = wallet.key_at(index + 1)?.public_key();
    let r = wallet.r_at(index + 1)?;
    let hint = debits
        .get(&entry.digest)
        .and_then(|amount| previous.checked_sub(*amount));
    let (balance, com) =
        matching_balance(previous, hint, &pk, &r, &entry.commitments).ok_or_else(|| {
            ClientError::Recover(format!(
                "entry {} spends serial {} but none of its commitments opens with the next key",
                entry.seq, index
            ))
        })?;
    let sig = entry.sig_for(&com).ok_or_else(|| {
        ClientError::Recover(format!(
            "entry {} has no signature for the commitment",
            entry.seq
        ))
    })?;
    wallet.verify_new_state(&com, &sig)?;
    Ok(SignedState {
        state: State { balance, pk, r },
        sig,
    })
}

fn enrolled_state(wallet: &Wallet, entry: &LogEntry) -> Result<SignedState, ClientError> {
    let pk = wallet.key_at(0)?.public_key();
    let r = wallet.r_at(0)?;
    let com = commitment(0, &pk, &r);
    let sig = entry
        .sig_for(&com)
        .ok_or_else(|| ClientError::Recover("enroll entry does not open with pk_0".to_owned()))?;
    wallet.verify_new_state(&com, &sig)?;
    Ok(SignedState {
        state: State { balance: 0, pk, r },
        sig,
    })
}

fn by_serial(log: &[LogEntry]) -> BTreeMap<Bytes32, &LogEntry> {
    let mut map = BTreeMap::new();
    for entry in log {
        for serial in &entry.serials {
            map.insert(*serial, entry);
        }
    }
    map
}

fn walk(
    wallet: &Wallet,
    log: &[LogEntry],
    mut state: Option<SignedState>,
    debits: &Debits,
) -> Result<(u64, Option<SignedState>), ClientError> {
    let spending = by_serial(log);
    let mut index = 0u64;
    loop {
        let pk = wallet.key_at(index)?.public_key();
        let Some(entry) = spending.get(&pk) else {
            break;
        };
        match entry.kind {
            OpKind::Enroll => {
                if index == 0 && state.is_none() {
                    state = Some(enrolled_state(wallet, entry)?);
                }
                break;
            }
            OpKind::Pay | OpKind::Refresh => {
                let previous = state.map_or(0, |s| s.state.balance);
                state = Some(step(wallet, index, previous, debits, entry)?);
                index += 1;
            }
        }
    }
    Ok((index, state))
}

pub async fn recover(wallet: &mut Wallet, bank: &BankClient) -> Result<u64, ClientError> {
    let log = bank.full_log().await?;
    let (index, state) = walk(wallet, &log, None, &Debits::new())?;
    wallet.restore(index, state)?;
    Ok(index)
}

fn check_genesis(wallet: &Wallet, genesis: &SignedState) -> Result<(), ClientError> {
    let expected_pk = wallet.key_at(0)?.public_key();
    if genesis.state.pk != expected_pk || genesis.state.r != wallet.r_at(0)? {
        return Err(ClientError::Recover(
            "the genesis state does not open with pk_0 of this wallet".to_owned(),
        ));
    }
    wallet.verify_new_state(&genesis.state.commitment(), &genesis.sig)
}

pub async fn recover_from_genesis(
    wallet: &mut Wallet,
    bank: &BankClient,
    genesis: SignedState,
    debits: &Debits,
) -> Result<u64, ClientError> {
    check_genesis(wallet, &genesis)?;
    let log = bank.full_log().await?;
    let (index, state) = walk(wallet, &log, Some(genesis), debits)?;
    wallet.restore(index, state)?;
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_search_walks_outward_from_the_previous_balance() {
        let pk = [1u8; 32];
        let r = [2u8; 32];
        let coms = vec![commitment(500, &pk, &r), [9u8; 32]];
        assert_eq!(
            matching_balance(620, None, &pk, &r, &coms),
            Some((500, coms[0]))
        );
        assert_eq!(
            matching_balance(380, None, &pk, &r, &coms),
            Some((500, coms[0]))
        );
        assert_eq!(
            matching_balance(500, None, &pk, &r, &coms),
            Some((500, coms[0]))
        );
        assert_eq!(matching_balance(0, None, &pk, &r, &[[7u8; 32]]), None);
        let far = vec![commitment(10, &pk, &r)];
        assert_eq!(
            matching_balance(5 * B_MAX, Some(10), &pk, &r, &far),
            Some((10, far[0]))
        );
        assert_eq!(matching_balance(5 * B_MAX, Some(11), &pk, &r, &far), None);
    }
}
