use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use openraft::{BasicNode, Config as RaftConfig};
use thiserror::Error;
use tracing::info;

use crate::network::{serve, Directory, Network, Reporter, Validator};
use crate::store::Store;
use crate::types::{Command, NodeId, Raft};

pub const LOCAL_ELECTION_MIN_MS: u64 = 300;
pub const LOCAL_ELECTION_MAX_MS: u64 = 600;
pub const LOCAL_HEARTBEAT_MS: u64 = 100;

pub const WIDE_ELECTION_MIN_MS: u64 = 3_000;
pub const WIDE_ELECTION_MAX_MS: u64 = 6_000;
pub const WIDE_HEARTBEAT_MS: u64 = 1_000;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("raft could not start: {0}")]
    Start(String),

    #[error("raft rejected the request: {0}")]
    Request(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spread {
    Local,
    CrossRegion,
}

impl Spread {
    #[must_use]
    pub const fn timings(self) -> (u64, u64, u64) {
        match self {
            Self::Local => (
                LOCAL_ELECTION_MIN_MS,
                LOCAL_ELECTION_MAX_MS,
                LOCAL_HEARTBEAT_MS,
            ),
            Self::CrossRegion => (
                WIDE_ELECTION_MIN_MS,
                WIDE_ELECTION_MAX_MS,
                WIDE_HEARTBEAT_MS,
            ),
        }
    }
}

pub struct Node {
    pub id: NodeId,
    pub raft: Raft,
    pub store: Arc<Store>,
    pub directory: Directory,
    listening: tokio::task::JoinHandle<()>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.listening.abort();
    }
}

impl Node {
    pub async fn start(
        id: NodeId,
        listen: &str,
        state_path: &Path,
        spread: Spread,
        validate: Validator,
        report: Reporter,
    ) -> Result<Self, NodeError> {
        let (election_min, election_max, heartbeat) = spread.timings();
        let config = Arc::new(
            RaftConfig {
                cluster_name: "shahrah".to_owned(),
                election_timeout_min: election_min,
                election_timeout_max: election_max,
                heartbeat_interval: heartbeat,
                max_in_snapshot_log_to_keep: 128,
                snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(256),
                ..RaftConfig::default()
            }
            .validate()
            .map_err(|cause| NodeError::Start(cause.to_string()))?,
        );

        let store = Store::open(state_path).await?;
        let directory = Directory::new();
        directory.insert(id, listen.to_owned()).await;

        let network = Network {
            directory: directory.clone(),
        };

        let raft = Raft::new(
            id,
            config,
            network,
            Arc::clone(&store),
            Arc::clone(&store),
        )
        .await
        .map_err(|cause| NodeError::Start(cause.to_string()))?;

        let listener = tokio::net::TcpListener::bind(listen).await.map_err(|cause| {
            NodeError::Start(format!("the raft listener could not bind {listen}: {cause}"))
        })?;
        let serving = raft.clone();
        let served_store = Arc::clone(&store);
        let listening = tokio::spawn(async move {
            if let Err(cause) = serve(listener, serving, served_store, validate, report).await {
                tracing::error!(%cause, "raft listener stopped");
            }
        });

        info!(
            id,
            listen,
            election_min,
            election_max,
            heartbeat,
            spread = ?spread,
            "raft node started"
        );

        Ok(Self {
            id,
            raft,
            store,
            directory,
            listening,
        })
    }

    pub async fn bootstrap(&self, members: &BTreeMap<NodeId, String>) -> Result<(), NodeError> {
        let mut nodes = BTreeMap::new();
        for (id, address) in members {
            self.directory.insert(*id, address.clone()).await;
            nodes.insert(*id, BasicNode::new(address.clone()));
        }
        self.raft
            .initialize(nodes)
            .await
            .map_err(|cause| NodeError::Request(cause.to_string()))
    }

    pub async fn add_learner(&self, id: NodeId, address: String) -> Result<(), NodeError> {
        self.directory.insert(id, address.clone()).await;
        self.raft
            .add_learner(id, BasicNode::new(address), true)
            .await
            .map(|_response| ())
            .map_err(|cause| NodeError::Request(cause.to_string()))
    }

    pub async fn promote_to_voter(&self, members: BTreeSet<NodeId>) -> Result<(), NodeError> {
        self.raft
            .change_membership(members, false)
            .await
            .map(|_response| ())
            .map_err(|cause| NodeError::Request(cause.to_string()))
    }

    pub async fn set_topology(&self, toml: String) -> Result<(), NodeError> {
        self.raft
            .client_write(Command::SetTopology { toml })
            .await
            .map(|_response| ())
            .map_err(|cause| NodeError::Request(cause.to_string()))
    }

    pub async fn topology_toml(&self) -> Option<String> {
        self.store.topology_toml().await
    }

    pub async fn announce_move(&self, key: Vec<u8>) -> Result<(), NodeError> {
        crate::network::announce(&self.raft, key, true)
            .await
            .map_err(NodeError::Request)
    }

    pub async fn moved_since(&self, seq: u64) -> (Vec<Vec<u8>>, u64) {
        self.store.moved_since(seq).await
    }

    pub async fn peers(&self) -> Vec<(NodeId, String)> {
        let members: Vec<(NodeId, String)> = {
            let metrics = self.raft.metrics();
            let held = metrics.borrow();
            held.membership_config
                .membership()
                .nodes()
                .map(|(id, node)| (*id, node.addr.clone()))
                .collect()
        };
        let mut out = Vec::with_capacity(members.len());
        for (id, address) in members {
            let address = if address.is_empty() {
                self.directory.get(id).await.unwrap_or_default()
            } else {
                address
            };
            out.push((id, address));
        }
        out.sort_by_key(|(id, _address)| *id);
        out
    }

    pub async fn wait_for_leader(&self, within: Duration) -> Option<NodeId> {
        self.raft
            .wait(Some(within))
            .metrics(
                |metrics| metrics.current_leader.is_some(),
                "a leader was elected",
            )
            .await
            .ok()
            .and_then(|metrics| metrics.current_leader)
    }

    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.raft.metrics().borrow().current_leader == Some(self.id)
    }
}
