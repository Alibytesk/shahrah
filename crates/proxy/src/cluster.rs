use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use shahrah_topology::node::{Node, Spread};
use tracing::{error, info, warn};

pub const RAFT_ID_ENV: &str = "SHAHRAH_RAFT_ID";
pub const RAFT_LISTEN_ENV: &str = "SHAHRAH_RAFT_LISTEN";
pub const RAFT_STATE_ENV: &str = "SHAHRAH_RAFT_STATE";
pub const RAFT_PEERS_ENV: &str = "SHAHRAH_RAFT_PEERS";
pub const RAFT_SPREAD_ENV: &str = "SHAHRAH_RAFT_SPREAD";
pub const RAFT_BOOTSTRAP_ENV: &str = "SHAHRAH_RAFT_BOOTSTRAP";

pub const WATCH_INTERVAL: Duration = Duration::from_millis(500);

pub struct Settings {
    pub id: u64,
    pub listen: String,
    pub state: PathBuf,
    pub peers: BTreeMap<u64, String>,
    pub spread: Spread,
    pub bootstrap: bool,
}

pub fn settings_from_env() -> Result<Option<Settings>, String> {
    let Ok(named) = std::env::var(RAFT_ID_ENV) else {
        return Ok(None);
    };
    let id: u64 = named.trim().parse().map_err(|_not_a_number| {
        format!(
            "{RAFT_ID_ENV} is set to \"{}\", which is not a proxy number. shahrah will not start \
             rather than run alone while a group was asked for",
            named.trim()
        )
    })?;
    let listen = std::env::var(RAFT_LISTEN_ENV).map_err(|_unset| {
        format!("{RAFT_ID_ENV} is set but {RAFT_LISTEN_ENV} is not, so peers have nowhere to reach this proxy")
    })?;
    let state = std::env::var(RAFT_STATE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(format!("shahrah-raft-{id}.json")));

    let mut peers = BTreeMap::new();
    if let Ok(list) = std::env::var(RAFT_PEERS_ENV) {
        for entry in list.split(',').filter(|item| !item.trim().is_empty()) {
            if let Some((left, right)) = entry.split_once('=')
                && let Ok(peer) = left.trim().parse::<u64>()
            {
                peers.insert(peer, right.trim().to_owned());
            }
        }
    }
    peers.entry(id).or_insert_with(|| listen.clone());

    Ok(Some(Settings {
        id,
        listen,
        state,
        peers,
        spread: match std::env::var(RAFT_SPREAD_ENV).as_deref() {
            Ok("cross-region") => Spread::CrossRegion,
            Ok("local") | Err(_) => Spread::Local,
            Ok(other) => {
                tracing::warn!(
                    value = other,
                    "{RAFT_SPREAD_ENV} names no spread shahrah knows, so the group carries the \
                     topology locally"
                );
                Spread::Local
            }
        },
        bootstrap: crate::settings::flag(RAFT_BOOTSTRAP_ENV)?,
    }))
}

pub async fn start(
    settings: Settings,
    routing: Arc<arc_swap::ArcSwapOption<crate::config::Loaded>>,
    lost: tokio::sync::watch::Sender<bool>,
    directory: Arc<shahrah_routing::directory::Directory>,
    reporting: Arc<std::sync::OnceLock<crate::session::Shared>>,
) -> Result<Arc<Node>, crate::error::SessionError> {
    let validate: shahrah_topology::network::Validator = Arc::new(|toml: &str| {
        crate::config::parse(toml)
            .map(|_usable| ())
            .map_err(|cause| cause.to_string())
    });
    let report: shahrah_topology::network::Reporter = Arc::new(move |subject: &str| {
        reporting.get().map_or_else(
            || "[]".to_owned(),
            |shared| crate::admin::report(shared, subject),
        )
    });
    let node = Node::start(
        settings.id,
        &settings.listen,
        &settings.state,
        settings.spread,
        validate,
        report,
    )
    .await
    .map_err(|cause| crate::error::SessionError::Cluster(cause.to_string()))?;
    let node = Arc::new(node);

    if settings.bootstrap {
        match node.bootstrap(&settings.peers).await {
            Ok(()) => info!(members = settings.peers.len(), "raft group bootstrapped"),
            Err(cause) => warn!(%cause, "bootstrap skipped, the group already exists"),
        }
    }

    let watcher = Arc::clone(&node);
    tokio::spawn(async move {
        let mut seen: Option<String> = None;
        let mut moved_seq = 0u64;
        loop {
            let (moved, at) = watcher.moved_since(moved_seq).await;
            if !moved.is_empty() {
                for key in &moved {
                    directory.forget(key);
                }
                info!(
                    keys = moved.len(),
                    "the group says these keys moved region, so this proxy forgot where it \
                     thought they lived"
                );
            }
            moved_seq = at;

            if let Err(cause) = watcher.raft.is_initialized().await {
                error!(
                    %cause,
                    "this node is no longer part of the raft group and would keep routing on a \
                     topology the cluster has moved past; shahrah stops rather than answer from \
                     a map it can no longer refresh"
                );
                let _told = lost.send(true);
                return;
            }
            if let Some(toml) = watcher.topology_toml().await
                && seen.as_deref() != Some(toml.as_str())
            {
                match crate::config::parse(&toml) {
                    Ok(loaded) => {
                        info!(
                            shards = loaded.topology.len(),
                            "topology adopted from the raft group"
                        );
                        routing.store(Some(Arc::new(loaded)));
                        seen = Some(toml);
                    }
                    Err(cause) => {
                        warn!(%cause, "the raft group holds a topology shahrah cannot use");
                        seen = Some(toml);
                    }
                }
            }
            tokio::time::sleep(WATCH_INTERVAL).await;
        }
    });

    Ok(node)
}
