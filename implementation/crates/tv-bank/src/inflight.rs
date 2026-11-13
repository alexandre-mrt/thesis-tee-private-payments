use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::sync::watch;
use tv_core::Bytes32;

pub struct InFlight {
    active: Mutex<HashSet<Bytes32>>,
    released: watch::Sender<u64>,
}

pub struct Claim<'a> {
    gate: &'a InFlight,
    digest: Bytes32,
}

impl Default for InFlight {
    fn default() -> Self {
        Self {
            active: Mutex::new(HashSet::new()),
            released: watch::channel(0).0,
        }
    }
}

impl InFlight {
    fn active(&self) -> MutexGuard<'_, HashSet<Bytes32>> {
        self.active.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn len(&self) -> usize {
        self.active().len()
    }

    pub fn is_empty(&self) -> bool {
        self.active().is_empty()
    }

    pub fn try_claim(&self, digest: Bytes32) -> Result<Claim<'_>, watch::Receiver<u64>> {
        let released = self.released.subscribe();
        if self.active().insert(digest) {
            Ok(Claim { gate: self, digest })
        } else {
            Err(released)
        }
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.gate.active().remove(&self.digest);
        self.gate.released.send_modify(|n| *n = n.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    async fn claim_or_stored<'a>(
        gate: &'a InFlight,
        answer: &Mutex<Option<u32>>,
    ) -> Result<Claim<'a>, u32> {
        loop {
            if let Some(stored) = *answer.lock().unwrap() {
                return Err(stored);
            }
            match gate.try_claim([1u8; 32]) {
                Ok(claim) => return Ok(claim),
                Err(mut released) => released.changed().await.unwrap(),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn duplicates_wait_for_the_first_claim_and_then_read_the_stored_answer() {
        let gate = Arc::new(InFlight::default());
        let answer = Arc::new(Mutex::new(None::<u32>));
        let ran = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let gate = Arc::clone(&gate);
            let answer = Arc::clone(&answer);
            let ran = Arc::clone(&ran);
            tasks.spawn(async move {
                match claim_or_stored(&gate, &answer).await {
                    Ok(claim) => {
                        ran.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        *answer.lock().unwrap() = Some(7);
                        drop(claim);
                        7
                    }
                    Err(stored) => stored,
                }
            });
        }
        let mut results = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            results.push(joined.unwrap());
        }
        assert_eq!(results, vec![7; 8]);
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert!(gate.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_claim_without_a_stored_answer_lets_the_next_waiter_run() {
        let gate = InFlight::default();
        let none = Mutex::new(None::<u32>);
        let first = claim_or_stored(&gate, &none).await;
        assert!(first.is_ok());
        assert_eq!(gate.len(), 1);
        let waiter = claim_or_stored(&gate, &none);
        tokio::pin!(waiter);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), waiter.as_mut())
                .await
                .is_err()
        );
        drop(first);
        let second = waiter.await;
        assert!(second.is_ok());
        assert_eq!(gate.len(), 1);
        drop(second);
        assert!(gate.is_empty());
    }
}
