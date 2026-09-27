use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openraft::storage::{LogFlushed, LogState, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    Entry, EntryPayload, LogId, OptionalSend, RaftLogReader, RaftSnapshotBuilder, SnapshotMeta,
    StorageError, StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::types::{Applied, Command, Config, NodeId};

pub const MOVED_KEPT: usize = 4096;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Machine {
    pub last_applied: Option<LogId<NodeId>>,
    pub membership: StoredMembership<NodeId, openraft::BasicNode>,
    pub toml: Option<String>,
    #[serde(default)]
    pub moved: Vec<(u64, Vec<u8>)>,
    #[serde(default)]
    pub moved_seq: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Durable {
    vote: Option<Vote<NodeId>>,
    entries: BTreeMap<u64, Entry<Config>>,
    purged: Option<LogId<NodeId>>,
    machine: Machine,
}

pub struct Store {
    path: PathBuf,
    inner: Arc<RwLock<Durable>>,
    snapshot: Arc<RwLock<Option<Snapshot<Config>>>>,
    counter: Arc<RwLock<u64>>,
    writing: tokio::sync::Mutex<()>,
}

impl Store {
    pub async fn open(path: &Path) -> Result<Arc<Self>, std::io::Error> {
        let durable = match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Durable::default(),
        };
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            inner: Arc::new(RwLock::new(durable)),
            snapshot: Arc::new(RwLock::new(None)),
            counter: Arc::new(RwLock::new(0)),
            writing: tokio::sync::Mutex::new(()),
        }))
    }

    pub async fn topology_toml(&self) -> Option<String> {
        self.inner.read().await.machine.toml.clone()
    }

    pub async fn moved_since(&self, seq: u64) -> (Vec<Vec<u8>>, u64) {
        let machine = &self.inner.read().await.machine;
        let keys = machine
            .moved
            .iter()
            .filter(|(at, _key)| *at > seq)
            .map(|(_at, key)| key.clone())
            .collect();
        (keys, machine.moved_seq)
    }

    async fn flush(&self, durable: &Durable) -> Result<(), StorageError<NodeId>> {
        let bytes =
            serde_json::to_vec(durable).map_err(|cause| StorageIOError::write(&cause))?;
        let _order = self.writing.lock().await;
        let temporary = self.path.with_extension(format!("tmp{}", std::process::id()));
        tokio::fs::write(&temporary, &bytes)
            .await
            .map_err(|cause| StorageIOError::write(&cause))?;
        tokio::fs::rename(&temporary, &self.path)
            .await
            .map_err(|cause| StorageIOError::write(&cause))?;
        Ok(())
    }
}

impl RaftLogReader<Config> for Arc<Store> {
    async fn try_get_log_entries<R: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: R,
    ) -> Result<Vec<Entry<Config>>, StorageError<NodeId>> {
        let guard = self.inner.read().await;
        Ok(guard
            .entries
            .range(range)
            .map(|(_index, entry)| entry.clone())
            .collect())
    }
}

impl RaftSnapshotBuilder<Config> for Arc<Store> {
    async fn build_snapshot(&mut self) -> Result<Snapshot<Config>, StorageError<NodeId>> {
        let machine = self.inner.read().await.machine.clone();
        let data =
            serde_json::to_vec(&machine).map_err(|cause| StorageIOError::read_state_machine(&cause))?;

        let mut counter = self.counter.write().await;
        *counter = counter.saturating_add(1);
        let id = format!("{}-{}", machine.last_applied.map_or(0, |log| log.index), counter);
        drop(counter);

        let meta = SnapshotMeta {
            last_log_id: machine.last_applied,
            last_membership: machine.membership.clone(),
            snapshot_id: id,
        };
        *self.snapshot.write().await = Some(Snapshot {
            meta: meta.clone(),
            snapshot: Box::new(Cursor::new(data.clone())),
        });
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftLogStorage<Config> for Arc<Store> {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<Config>, StorageError<NodeId>> {
        let guard = self.inner.read().await;
        let last = guard
            .entries
            .iter()
            .next_back()
            .map(|(_index, entry)| entry.log_id)
            .or(guard.purged);
        Ok(LogState {
            last_purged_log_id: guard.purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        Arc::clone(self)
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut guard = self.inner.write().await;
        guard.vote = Some(*vote);
        let copy = Durable {
            vote: guard.vote,
            entries: guard.entries.clone(),
            purged: guard.purged,
            machine: guard.machine.clone(),
        };
        let outcome = self.flush(&copy).await;
        drop(guard);
        outcome
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.read().await.vote)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<Config>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<Config>> + OptionalSend,
    {
        {
            let mut guard = self.inner.write().await;
            for entry in entries {
                guard.entries.insert(entry.log_id.index, entry);
            }
            let copy = Durable {
                vote: guard.vote,
                entries: guard.entries.clone(),
                purged: guard.purged,
                machine: guard.machine.clone(),
            };
            let outcome = self.flush(&copy).await;
            drop(guard);
            outcome?;
        }
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut guard = self.inner.write().await;
        guard.entries.retain(|index, _entry| *index < log_id.index);
        let copy = Durable {
            vote: guard.vote,
            entries: guard.entries.clone(),
            purged: guard.purged,
            machine: guard.machine.clone(),
        };
        let outcome = self.flush(&copy).await;
        drop(guard);
        outcome
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut guard = self.inner.write().await;
        guard.purged = Some(log_id);
        guard.entries.retain(|index, _entry| *index > log_id.index);
        let copy = Durable {
            vote: guard.vote,
            entries: guard.entries.clone(),
            purged: guard.purged,
            machine: guard.machine.clone(),
        };
        let outcome = self.flush(&copy).await;
        drop(guard);
        outcome
    }
}

impl RaftStateMachine<Config> for Arc<Store> {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<NodeId>>,
            StoredMembership<NodeId, openraft::BasicNode>,
        ),
        StorageError<NodeId>,
    > {
        let machine = &self.inner.read().await.machine;
        Ok((machine.last_applied, machine.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Applied>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<Config>> + OptionalSend,
    {
        let mut results = Vec::new();
        let mut guard = self.inner.write().await;
        for entry in entries {
            guard.machine.last_applied = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => results.push(Applied::default()),
                EntryPayload::Normal(Command::SetTopology { toml }) => {
                    guard.machine.toml = Some(toml);
                    results.push(Applied {
                        applied: true,
                        message: "topology stored".to_owned(),
                    });
                }
                EntryPayload::Normal(Command::KeyMoved { key }) => {
                    guard.machine.moved_seq = guard.machine.moved_seq.saturating_add(1);
                    let at = guard.machine.moved_seq;
                    guard.machine.moved.push((at, key));
                    let extra = guard.machine.moved.len().saturating_sub(MOVED_KEPT);
                    if extra > 0 {
                        guard.machine.moved.drain(..extra);
                    }
                    results.push(Applied {
                        applied: true,
                        message: "key move announced".to_owned(),
                    });
                }
                EntryPayload::Membership(membership) => {
                    guard.machine.membership =
                        StoredMembership::new(Some(entry.log_id), membership);
                    results.push(Applied {
                        applied: true,
                        message: "membership stored".to_owned(),
                    });
                }
            }
        }
        let copy = Durable {
            vote: guard.vote,
            entries: guard.entries.clone(),
            purged: guard.purged,
            machine: guard.machine.clone(),
        };
        let outcome = self.flush(&copy).await;
        drop(guard);
        outcome?;
        Ok(results)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        Arc::clone(self)
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, openraft::BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let machine: Machine = serde_json::from_slice(snapshot.get_ref())
            .map_err(|cause| StorageIOError::read_snapshot(Some(meta.signature()), &cause))?;
        let mut guard = self.inner.write().await;
        guard.machine = machine;
        let copy = Durable {
            vote: guard.vote,
            entries: guard.entries.clone(),
            purged: guard.purged,
            machine: guard.machine.clone(),
        };
        let outcome = self.flush(&copy).await;
        drop(guard);
        outcome
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<Config>>, StorageError<NodeId>> {
        let guard = self.snapshot.read().await;
        Ok(guard.as_ref().map(|snapshot| Snapshot {
            meta: snapshot.meta.clone(),
            snapshot: Box::new(Cursor::new(snapshot.snapshot.as_ref().get_ref().clone())),
        }))
    }
}
