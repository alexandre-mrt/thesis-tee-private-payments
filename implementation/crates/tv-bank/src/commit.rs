use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{OwnedMutexGuard, watch};
use tracing::warn;

use crate::error::BankError;
use crate::journal::LogWriter;
use crate::store::{Durability, Store, Ticket};

pub type SharedStore<W> = Arc<Mutex<Store<W>>>;

pub struct Committer {
    lead: Arc<tokio::sync::Mutex<()>>,
    durable: watch::Sender<usize>,
}

impl Default for Committer {
    fn default() -> Self {
        Self {
            lead: Arc::new(tokio::sync::Mutex::new(())),
            durable: watch::channel(0).0,
        }
    }
}

fn lock<W: LogWriter>(store: &Mutex<Store<W>>) -> MutexGuard<'_, Store<W>> {
    store.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Committer {
    pub async fn commit<W: LogWriter>(
        &self,
        store: &SharedStore<W>,
        ticket: Ticket,
    ) -> Result<(), BankError> {
        let mut changes = self.durable.subscribe();
        loop {
            match lock(store).durability(ticket)? {
                Durability::Durable => return Ok(()),
                Durability::RolledBack => return Err(BankError::RolledBack),
                Durability::Staged => {}
            }
            match Arc::clone(&self.lead).try_lock_owned() {
                Ok(leader) => {
                    let flush = flush(Arc::clone(store), leader, self.durable.clone());
                    if tokio::spawn(flush).await.is_err() {
                        warn!("the log flush task was cancelled; waiting for the next flush");
                    }
                }
                Err(_) => changes
                    .changed()
                    .await
                    .map_err(|_| BankError::StorePoisoned)?,
            }
        }
    }
}

async fn flush<W: LogWriter>(
    store: SharedStore<W>,
    leader: OwnedMutexGuard<()>,
    durable: watch::Sender<usize>,
) {
    let (flight, journal) = {
        let mut store = lock(&store);
        (store.take_flight(), store.journal())
    };
    let Some(flight) = flight else {
        return;
    };
    let written = flight.bytes.len();
    let end = flight.end;
    let outcome = tokio::task::spawn_blocking(move || {
        journal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .append(&flight.bytes)
    })
    .await;
    let count = {
        let mut store = lock(&store);
        match outcome {
            Ok(Ok(())) => store.confirm(written, end),
            Ok(Err(err)) => {
                store.roll_back(err);
            }
            Err(join) => {
                store.roll_back(std::io::Error::other(join));
            }
        }
        store.durable()
    };
    drop(leader);
    durable.send_replace(count);
}

#[cfg(test)]
mod tests {
    use tv_core::OpKind;

    use super::*;
    use crate::journal::testing::{Fault, appends, entry, faulty, set_fault, temp_dir};

    const ORDER_PROBES: usize = 150;
    const PROBE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    fn lead_free_when_durability_is_published(
        committer: &Committer,
        changes: watch::Receiver<usize>,
    ) -> bool {
        let deadline = std::time::Instant::now() + PROBE_DEADLINE;
        while !changes.has_changed().unwrap_or(true) {
            assert!(
                std::time::Instant::now() < deadline,
                "no flush was published"
            );
            std::hint::spin_loop();
        }
        committer.lead.try_lock().is_ok()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_flush_makes_every_staged_entry_durable() {
        let dir = temp_dir("group");
        let store = Arc::new(Mutex::new(faulty(&dir, Fault::None)));
        let committer = Committer::default();
        let tickets: Vec<Ticket> = (0..8u64)
            .map(|seq| lock(&store).stage(entry(seq, OpKind::Refresh, seq as u8)))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(lock(&store).entries().len(), 0);
        for ticket in &tickets {
            committer.commit(&store, *ticket).await.unwrap();
        }
        assert_eq!(appends(&lock(&store)), 1);
        assert_eq!(lock(&store).durable(), 8);
        assert_eq!(lock(&store).entries().len(), 8);
        drop(store);
        let reopened = Store::open(&dir).unwrap();
        assert_eq!(reopened.entries().len(), 8);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_commits_all_land_and_the_log_replays() {
        let dir = temp_dir("concurrent");
        let store = Arc::new(Mutex::new(faulty(&dir, Fault::None)));
        let committer = Arc::new(Committer::default());
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let store = Arc::clone(&store);
            let committer = Arc::clone(&committer);
            tasks.spawn(async move {
                let ticket = {
                    let mut guard = lock(&store);
                    let seq = guard.index().len();
                    guard.stage(entry(seq, OpKind::Refresh, seq as u8))
                }
                .unwrap();
                committer.commit(&store, ticket).await
            });
        }
        while let Some(joined) = tasks.join_next().await {
            joined.unwrap().unwrap();
        }
        assert!(appends(&lock(&store)) >= 1);
        assert_eq!(lock(&store).durable(), 32);
        drop(store);
        assert_eq!(Store::open(&dir).unwrap().entries().len(), 32);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_leader_releases_the_lead_before_it_publishes_durability() {
        let dir = temp_dir("lead-order");
        let store = Arc::new(Mutex::new(faulty(&dir, Fault::None)));
        let committer = Arc::new(Committer::default());
        for seq in 0..ORDER_PROBES {
            let ticket = lock(&store)
                .stage(entry(seq as u64, OpKind::Refresh, seq as u8))
                .unwrap();
            let observer = Arc::clone(&committer);
            let changes = committer.durable.subscribe();
            let probe = std::thread::spawn(move || {
                lead_free_when_durability_is_published(&observer, changes)
            });
            committer.commit(&store, ticket).await.unwrap();
            assert!(
                probe.join().unwrap(),
                "probe {seq}: a woken waiter found the lead still held"
            );
        }
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_flight_rolls_back_every_ticket_of_its_generation() {
        let dir = temp_dir("rolled-back");
        let store = Arc::new(Mutex::new(faulty(&dir, Fault::WriteThenFail)));
        let committer = Committer::default();
        let first = lock(&store).stage(entry(0, OpKind::Refresh, 1)).unwrap();
        let second = lock(&store).stage(entry(1, OpKind::Refresh, 2)).unwrap();
        assert!(matches!(
            committer.commit(&store, first).await,
            Err(BankError::RolledBack)
        ));
        assert!(matches!(
            committer.commit(&store, second).await,
            Err(BankError::RolledBack)
        ));
        assert_eq!(lock(&store).index().len(), 0);
        assert!(!lock(&store).index().is_spent(&[1u8; 32]));
        set_fault(&lock(&store), Fault::None);
        let again = lock(&store).stage(entry(0, OpKind::Refresh, 1)).unwrap();
        committer.commit(&store, again).await.unwrap();
        assert!(matches!(
            committer.commit(&store, first).await,
            Err(BankError::RolledBack)
        ));
        assert_eq!(lock(&store).entries().len(), 1);
        drop(store);
        assert_eq!(Store::open(&dir).unwrap().entries().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_later_failed_flight_leaves_an_earlier_durable_ticket_durable() {
        let dir = temp_dir("durable-survives");
        let store = Arc::new(Mutex::new(faulty(&dir, Fault::None)));
        let committer = Committer::default();
        let first = lock(&store).stage(entry(0, OpKind::Refresh, 1)).unwrap();
        committer.commit(&store, first).await.unwrap();
        set_fault(&lock(&store), Fault::WriteThenFail);
        let second = lock(&store).stage(entry(1, OpKind::Refresh, 2)).unwrap();
        assert!(matches!(
            committer.commit(&store, second).await,
            Err(BankError::RolledBack)
        ));
        committer.commit(&store, first).await.unwrap();
        set_fault(&lock(&store), Fault::None);
        let reused = lock(&store).stage(entry(1, OpKind::Refresh, 3)).unwrap();
        committer.commit(&store, reused).await.unwrap();
        assert!(matches!(
            committer.commit(&store, second).await,
            Err(BankError::RolledBack)
        ));
        committer.commit(&store, first).await.unwrap();
        drop(store);
        assert_eq!(Store::open(&dir).unwrap().entries().len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
