use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use pt_tee::channel::{EnclaveKeypair, PK_LEN};
use tv_core::Bytes32;
pub use tv_core::{MAX_KEY_AGE, MAX_PENDING_KEYS};

type Pk = [u8; PK_LEN];

struct Pending {
    keypair: Arc<EnclaveKeypair>,
    created: Instant,
    owner: Bytes32,
}

pub struct ChannelKey {
    pub keypair: Arc<EnclaveKeypair>,
    pub owner: Bytes32,
}

#[derive(Default)]
pub struct ChannelKeys {
    pending: BTreeMap<Pk, Pending>,
    by_age: BTreeSet<(Instant, Pk)>,
}

impl ChannelKeys {
    pub fn issue(&mut self, now: Instant, owner: Bytes32) -> Arc<EnclaveKeypair> {
        self.evict(now);
        let keypair = Arc::new(EnclaveKeypair::generate());
        let pk = keypair.public_key();
        self.pending.insert(
            pk,
            Pending {
                keypair: Arc::clone(&keypair),
                created: now,
                owner,
            },
        );
        self.by_age.insert((now, pk));
        keypair
    }

    pub fn peek(&mut self, pk: &Pk, now: Instant) -> Option<ChannelKey> {
        self.evict(now);
        self.pending.get(pk).map(|p| ChannelKey {
            keypair: Arc::clone(&p.keypair),
            owner: p.owner,
        })
    }

    pub fn take(&mut self, pk: &Pk, now: Instant) -> Option<Arc<EnclaveKeypair>> {
        self.evict(now);
        self.remove(pk)
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn snapshot(&self) -> Vec<Arc<EnclaveKeypair>> {
        self.pending
            .values()
            .map(|p| Arc::clone(&p.keypair))
            .collect()
    }

    fn remove(&mut self, pk: &Pk) -> Option<Arc<EnclaveKeypair>> {
        let pending = self.pending.remove(pk)?;
        self.by_age.remove(&(pending.created, *pk));
        Some(pending.keypair)
    }

    fn evict(&mut self, now: Instant) {
        while let Some(&(created, pk)) = self.by_age.first() {
            let expired = now.duration_since(created) >= MAX_KEY_AGE;
            let full = self.pending.len() >= MAX_PENDING_KEYS;
            if !expired && !full {
                return;
            }
            self.remove(&pk);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const OWNER: Bytes32 = [9u8; 32];

    #[test]
    fn keys_are_single_use_and_bounded() {
        let mut keys = ChannelKeys::default();
        let now = Instant::now();
        let kp = keys.issue(now, OWNER);
        let pk = kp.public_key();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.peek(&pk, now).map(|k| k.owner), Some(OWNER));
        assert_eq!(keys.len(), 1);
        assert!(keys.take(&pk, now).is_some());
        assert!(keys.peek(&pk, now).is_none());
        assert!(keys.take(&pk, now).is_none());
        assert!(keys.is_empty());
        assert!(keys.by_age.is_empty());
        let old = keys.issue(now, OWNER).public_key();
        for i in 0..MAX_PENDING_KEYS {
            keys.issue(now + Duration::from_millis(1 + i as u64), OWNER);
        }
        assert_eq!(keys.len(), MAX_PENDING_KEYS);
        assert_eq!(keys.by_age.len(), MAX_PENDING_KEYS);
        assert!(keys.take(&old, now).is_none());
    }

    #[test]
    fn keys_expire() {
        let mut keys = ChannelKeys::default();
        let now = Instant::now();
        let pk = keys.issue(now, OWNER).public_key();
        assert!(keys.take(&pk, now + MAX_KEY_AGE).is_none());
        let pk = keys.issue(now, OWNER).public_key();
        assert!(
            keys.take(&pk, now + MAX_KEY_AGE - Duration::from_secs(1))
                .is_some()
        );
        assert_eq!(keys.snapshot().len(), 0);
        assert!(keys.by_age.is_empty());
    }

    #[test]
    fn eviction_removes_the_oldest_live_key_first() {
        let mut keys = ChannelKeys::default();
        let now = Instant::now();
        let first = keys.issue(now, OWNER).public_key();
        let second = keys
            .issue(now + Duration::from_millis(1), OWNER)
            .public_key();
        assert!(keys.take(&first, now).is_some());
        for i in 0..MAX_PENDING_KEYS - 2 {
            keys.issue(now + Duration::from_millis(2 + i as u64), OWNER);
        }
        assert_eq!(keys.len(), MAX_PENDING_KEYS - 1);
        assert!(keys.peek(&second, now).is_some());
        keys.issue(now + Duration::from_secs(1), OWNER);
        assert_eq!(keys.len(), MAX_PENDING_KEYS);
        assert!(keys.peek(&second, now).is_none());
        assert_eq!(keys.len(), MAX_PENDING_KEYS - 1);
    }
}
