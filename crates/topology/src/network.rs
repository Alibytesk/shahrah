use std::collections::BTreeMap;
use std::sync::Arc;

use openraft::error::{InstallSnapshotError, RaftError, Unreachable};
use openraft::network::{RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::BasicNode;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::types::{Config, NodeId, Raft};

#[derive(Debug, Serialize, Deserialize)]
pub enum Rpc {
    Append(AppendEntriesRequest<Config>),
    Vote(VoteRequest<NodeId>),
    Snapshot(InstallSnapshotRequest<Config>),
    Write(String),
    WriteDirect(String),
    Read,
    Moved(Vec<u8>),
    MovedSince(u64),
    Fleet(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Reply {
    Append(Result<AppendEntriesResponse<NodeId>, String>),
    Vote(Result<VoteResponse<NodeId>, String>),
    Snapshot(Result<InstallSnapshotResponse<NodeId>, String>),
    Write(Result<(), String>),
    Read(Option<String>),
    Moved(Result<(), String>),
    MovedSince(Vec<Vec<u8>>, u64),
    Fleet(String),
}

#[derive(Clone, Default)]
pub struct Directory {
    entries: Arc<RwLock<BTreeMap<NodeId, String>>>,
}

impl Directory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(&self, id: NodeId, address: String) {
        self.entries.write().await.insert(id, address);
    }

    pub async fn get(&self, id: NodeId) -> Option<String> {
        self.entries.read().await.get(&id).cloned()
    }
}

#[derive(Clone)]
pub struct Network {
    pub directory: Directory,
}

impl RaftNetworkFactory<Config> for Network {
    type Network = Peer;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        let address = if node.addr.is_empty() {
            self.directory.get(target).await.unwrap_or_default()
        } else {
            node.addr.clone()
        };
        Peer { target, address }
    }
}

pub struct Peer {
    target: NodeId,
    address: String,
}

impl Peer {
    async fn call(&self, request: &Rpc) -> Result<Reply, Unreachable> {
        let line = serde_json::to_string(request)
            .map_err(|cause| Unreachable::new(&std::io::Error::other(cause.to_string())))?;
        let mut stream = TcpStream::connect(&self.address)
            .await
            .map_err(|cause| Unreachable::new(&cause))?;
        stream
            .write_all(line.as_bytes())
            .await
            .map_err(|cause| Unreachable::new(&cause))?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|cause| Unreachable::new(&cause))?;

        let mut reader = BufReader::new(stream);
        let mut answer = String::new();
        reader
            .read_line(&mut answer)
            .await
            .map_err(|cause| Unreachable::new(&cause))?;
        serde_json::from_str(&answer)
            .map_err(|cause| Unreachable::new(&std::io::Error::other(cause.to_string())))
    }
}

impl RaftNetwork<Config> for Peer {
    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<Config>,
        _option: openraft::network::RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError> {
        match self
            .call(&Rpc::Append(request))
            .await
            .map_err(openraft::error::RPCError::Unreachable)?
        {
            Reply::Append(Ok(answer)) => Ok(answer),
            other => Err(remote(self.target, format!("{other:?}"))),
        }
    }

    async fn vote(
        &mut self,
        request: VoteRequest<NodeId>,
        _option: openraft::network::RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError> {
        match self
            .call(&Rpc::Vote(request))
            .await
            .map_err(openraft::error::RPCError::Unreachable)?
        {
            Reply::Vote(Ok(answer)) => Ok(answer),
            other => Err(remote(self.target, format!("{other:?}"))),
        }
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<Config>,
        _option: openraft::network::RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        openraft::error::RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        match self
            .call(&Rpc::Snapshot(request))
            .await
            .map_err(openraft::error::RPCError::Unreachable)?
        {
            Reply::Snapshot(Ok(answer)) => Ok(answer),
            other => Err(openraft::error::RPCError::Unreachable(Unreachable::new(
                &std::io::Error::other(format!("{other:?}")),
            ))),
        }
    }
}

type RPCError = openraft::error::RPCError<NodeId, BasicNode, RaftError<NodeId>>;

fn remote(target: NodeId, message: String) -> RPCError {
    openraft::error::RPCError::Unreachable(Unreachable::new(&std::io::Error::other(format!(
        "node {target}: {message}"
    ))))
}

pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub type Validator = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

pub type Reporter = Arc<dyn Fn(&str) -> String + Send + Sync>;

pub async fn serve(
    listener: TcpListener,
    raft: Raft,
    store: Arc<crate::store::Store>,
    validate: Validator,
    report: Reporter,
) -> Result<(), std::io::Error> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let raft = raft.clone();
        let store = Arc::clone(&store);
        let validate = Arc::clone(&validate);
        let report = Arc::clone(&report);
        tokio::spawn(async move {
            if let Err(cause) = handle(stream, raft, store, validate, report).await {
                warn!(%cause, "raft rpc failed");
            }
        });
    }
}

pub async fn announce(raft: &Raft, key: Vec<u8>, may_forward: bool) -> Result<(), String> {
    let attempt = raft
        .client_write(crate::types::Command::KeyMoved { key: key.clone() })
        .await;
    let cause = match attempt {
        Ok(_accepted) => return Ok(()),
        Err(cause) => cause,
    };
    if !may_forward {
        return Err(cause.to_string());
    }
    let leader = {
        let metrics = raft.metrics();
        let held = metrics.borrow();
        let who = held.current_leader;
        held.membership_config
            .membership()
            .nodes()
            .find(|(id, _node)| Some(**id) == who)
            .map(|(_id, node)| node.addr.clone())
    };
    match leader {
        Some(address) if !address.is_empty() => forward_move(&address, key).await,
        _ => Err(format!("{cause}; this node does not know the leader")),
    }
}

async fn forward_move(address: &str, key: Vec<u8>) -> Result<(), String> {
    let line = serde_json::to_string(&Rpc::Moved(key)).map_err(|c| c.to_string())?;
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(address),
    )
    .await
    .map_err(|_elapsed| "the leader did not answer in time".to_owned())?
    .map_err(|cause| cause.to_string())?;
    stream.write_all(line.as_bytes()).await.map_err(|c| c.to_string())?;
    stream.write_all(b"\n").await.map_err(|c| c.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut answer = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reader.read_line(&mut answer),
    )
    .await
    .map_err(|_elapsed| "the leader did not answer in time".to_owned())?
    .map_err(|cause| cause.to_string())?;
    match serde_json::from_str::<Reply>(&answer).map_err(|c| c.to_string())? {
        Reply::Moved(result) => result,
        other => Err(format!("the leader answered with {other:?}")),
    }
}

pub async fn ask_peer(address: &str, subject: &str) -> Result<String, String> {
    let line = serde_json::to_string(&Rpc::Fleet(subject.to_owned())).map_err(|c| c.to_string())?;
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(address),
    )
    .await
    .map_err(|_elapsed| "did not answer in time".to_owned())?
    .map_err(|cause| cause.to_string())?;
    stream.write_all(line.as_bytes()).await.map_err(|c| c.to_string())?;
    stream.write_all(b"\n").await.map_err(|c| c.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut answer = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reader.read_line(&mut answer),
    )
    .await
    .map_err(|_elapsed| "did not answer in time".to_owned())?
    .map_err(|cause| cause.to_string())?;
    match serde_json::from_str::<Reply>(&answer).map_err(|c| c.to_string())? {
        Reply::Fleet(rows) => Ok(rows),
        other => Err(format!("answered with {other:?}")),
    }
}

async fn forward_to_leader(address: &str, toml: String) -> Result<(), String> {
    let line = serde_json::to_string(&Rpc::WriteDirect(toml)).map_err(|c| c.to_string())?;
    let mut stream = TcpStream::connect(address).await.map_err(|c| c.to_string())?;
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|c| c.to_string())?;
    stream.write_all(b"\n").await.map_err(|c| c.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut answer = String::new();
    reader
        .read_line(&mut answer)
        .await
        .map_err(|c| c.to_string())?;
    match serde_json::from_str::<Reply>(&answer).map_err(|c| c.to_string())? {
        Reply::Write(result) => result,
        other => Err(format!("the leader answered with {other:?}")),
    }
}

async fn commit(raft: &Raft, toml: String, may_forward: bool) -> Result<(), String> {
    let attempt = raft
        .client_write(crate::types::Command::SetTopology { toml: toml.clone() })
        .await;
    let cause = match attempt {
        Ok(_accepted) => return Ok(()),
        Err(cause) => cause,
    };
    if !may_forward {
        return Err(cause.to_string());
    }
    let leader = raft
        .metrics()
        .borrow()
        .membership_config
        .membership()
        .nodes()
        .find(|(id, _node)| Some(**id) == raft.metrics().borrow().current_leader)
        .map(|(_id, node)| node.addr.clone());
    match leader {
        Some(address) if !address.is_empty() => {
            debug!(address, "forwarding a topology write to the leader");
            forward_to_leader(&address, toml).await
        }
        _ => Err(format!("{cause}; this node does not know the leader")),
    }
}

async fn handle(
    stream: TcpStream,
    raft: Raft,
    store: Arc<crate::store::Store>,
    validate: Validator,
    report: Reporter,
) -> Result<(), std::io::Error> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    tokio::time::timeout(REQUEST_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_elapsed| {
            std::io::Error::other(format!(
                "a raft rpc sent no complete request within {REQUEST_TIMEOUT:?}"
            ))
        })??;
    let request: Rpc = serde_json::from_str(&line).map_err(std::io::Error::other)?;

    let reply = match request {
        Rpc::Append(request) => Reply::Append(
            raft.append_entries(request)
                .await
                .map_err(|cause| cause.to_string()),
        ),
        Rpc::Vote(request) => Reply::Vote(
            raft.vote(request)
                .await
                .map_err(|cause| cause.to_string()),
        ),
        Rpc::Snapshot(request) => Reply::Snapshot(
            raft.install_snapshot(request)
                .await
                .map_err(|cause| cause.to_string()),
        ),
        Rpc::Write(toml) => Reply::Write(match validate(&toml) {
            Ok(()) => commit(&raft, toml, true).await,
            Err(cause) => Err(format!("the group refuses a topology it cannot use: {cause}")),
        }),
        Rpc::WriteDirect(toml) => Reply::Write(match validate(&toml) {
            Ok(()) => commit(&raft, toml, false).await,
            Err(cause) => Err(format!("the group refuses a topology it cannot use: {cause}")),
        }),
        Rpc::Read => Reply::Read(store.topology_toml().await),
        Rpc::Moved(key) => Reply::Moved(announce(&raft, key, false).await),
        Rpc::Fleet(subject) => Reply::Fleet(report(&subject)),
        Rpc::MovedSince(seq) => {
            let (keys, at) = store.moved_since(seq).await;
            Reply::MovedSince(keys, at)
        }
    };

    let mut answer = serde_json::to_string(&reply).map_err(std::io::Error::other)?;
    answer.push('\n');
    reader.into_inner().write_all(answer.as_bytes()).await
}
