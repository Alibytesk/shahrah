use openraft::BasicNode;
use serde::{Deserialize, Serialize};

pub type NodeId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    SetTopology { toml: String },
    KeyMoved { key: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Applied {
    pub applied: bool,
    pub message: String,
}

openraft::declare_raft_types!(
    pub Config:
        D = Command,
        R = Applied,
        NodeId = NodeId,
        Node = BasicNode,
        Entry = openraft::Entry<Config>,
        SnapshotData = std::io::Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

pub type Raft = openraft::Raft<Config>;
