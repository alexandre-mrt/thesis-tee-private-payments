use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use pt_tee::channel::PK_LEN;
use tv_core::{MAX_KEY_AGE, MAX_PENDING_KEYS};

pub const MAX_PENDING_KEYS_PER_SOURCE: usize = 256;

type Pk = [u8; PK_LEN];

struct Tracked {
    created: Instant,
    source: String,
}

#[derive(Default)]
pub struct AttestQuota {
    pending: BTreeMap<Pk, Tracked>,
    by_age: BTreeSet<(Instant, Pk)>,
    by_source: BTreeMap<String, BTreeSet<(Instant, Pk)>>,
}

impl AttestQuota {
    pub fn record(&mut self, now: Instant, source: &str, pk: Pk) -> Vec<Pk> {
        self.expire(now);
        self.remove(&pk);
        self.pending.insert(
            pk,
            Tracked {
                created: now,
                source: source.to_owned(),
            },
        );
        self.by_age.insert((now, pk));
        self.by_source
            .entry(source.to_owned())
            .or_default()
            .insert((now, pk));
        self.over_quota(source)
    }

    pub fn consumed(&mut self, pk: &Pk) {
        self.remove(pk);
    }

    pub fn pending_for(&self, source: &str) -> usize {
        self.by_source.get(source).map_or(0, BTreeSet::len)
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    fn over_quota(&mut self, source: &str) -> Vec<Pk> {
        let mut evicted = Vec::new();
        while let Some(&(_, pk)) = self
            .by_source
            .get(source)
            .filter(|keys| keys.len() > MAX_PENDING_KEYS_PER_SOURCE)
            .and_then(BTreeSet::first)
        {
            self.remove(&pk);
            evicted.push(pk);
        }
        evicted
    }

    fn expire(&mut self, now: Instant) {
        while let Some(&(created, pk)) = self.by_age.first() {
            let expired = now.duration_since(created) >= MAX_KEY_AGE;
            let full = self.pending.len() >= MAX_PENDING_KEYS;
            if !expired && !full {
                return;
            }
            self.remove(&pk);
        }
    }

    fn remove(&mut self, pk: &Pk) {
        let Some(tracked) = self.pending.remove(pk) else {
            return;
        };
        self.by_age.remove(&(tracked.created, *pk));
        if let Some(keys) = self.by_source.get_mut(&tracked.source) {
            keys.remove(&(tracked.created, *pk));
            if keys.is_empty() {
                self.by_source.remove(&tracked.source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const FLOODER: &str = "198.51.100.7";
    const HONEST: &str = "203.0.113.9";

    fn pk(n: usize) -> Pk {
        let mut out = [0u8; PK_LEN];
        out[..8].copy_from_slice(&(n as u64).to_be_bytes());
        out
    }

    #[test]
    fn a_source_over_its_quota_evicts_only_its_own_oldest_key() {
        let mut quota = AttestQuota::default();
        let now = Instant::now();
        assert!(quota.record(now, HONEST, pk(0)).is_empty());
        for i in 1..=MAX_PENDING_KEYS_PER_SOURCE {
            let at = now + Duration::from_millis(i as u64);
            assert!(quota.record(at, FLOODER, pk(i)).is_empty());
        }
        let newest = MAX_PENDING_KEYS_PER_SOURCE + 1;
        let evicted = quota.record(now + Duration::from_secs(1), FLOODER, pk(newest));
        assert_eq!(evicted, vec![pk(1)]);
        assert_eq!(quota.pending_for(FLOODER), MAX_PENDING_KEYS_PER_SOURCE);
        assert_eq!(quota.pending_for(HONEST), 1);
        quota.consumed(&pk(0));
        assert_eq!(quota.pending_for(HONEST), 0);
        assert_eq!(quota.len(), MAX_PENDING_KEYS_PER_SOURCE);
    }

    #[test]
    fn expired_keys_leave_the_quota() {
        let mut quota = AttestQuota::default();
        let now = Instant::now();
        quota.record(now, HONEST, pk(1));
        quota.record(now + MAX_KEY_AGE, FLOODER, pk(2));
        assert_eq!(quota.pending_for(HONEST), 0);
        assert_eq!(quota.len(), 1);
        quota.consumed(&pk(2));
        assert!(quota.is_empty());
        assert!(quota.by_age.is_empty());
        assert!(quota.by_source.is_empty());
    }
}
