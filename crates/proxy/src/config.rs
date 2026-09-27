use std::path::Path;

use serde::Deserialize;
use shahrah_routing::topology::{Topology, TopologySpec};
use shahrah_sql::analysis::Policy;
use thiserror::Error;

pub const CONFIG_ENV: &str = "SHAHRAH_CONFIG";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read {path}: {cause}")]
    Read { path: String, cause: std::io::Error },

    #[error("{path} is not valid TOML: {cause}")]
    Parse {
        path: String,
        cause: toml::de::Error,
    },

    #[error("topology in {path} is not usable: {cause}")]
    Topology {
        path: String,
        cause: shahrah_routing::topology::TopologyError,
    },

    #[error("the placement policy in {path} is not usable: {cause}")]
    Policy {
        path: String,
        cause: shahrah_sql::analysis::PolicyError,
    },
}

#[derive(Debug, Deserialize)]
pub struct FileSpec {
    #[serde(flatten)]
    pub topology: TopologySpec,
    #[serde(default)]
    pub policy: Policy,
}

pub struct Loaded {
    pub topology: Topology,
    pub policy: Policy,
    pub generation: u64,
}

static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_generation() -> u64 {
    GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub fn parse(text: &str) -> Result<Loaded, ConfigError> {
    let spec: FileSpec = toml::from_str(text).map_err(|cause| ConfigError::Parse {
        path: "<raft>".to_owned(),
        cause,
    })?;
    let topology = Topology::build(spec.topology).map_err(|cause| ConfigError::Topology {
        path: "<raft>".to_owned(),
        cause,
    })?;
    spec.policy
        .check(&topology.regions())
        .map_err(|cause| ConfigError::Policy {
            path: "<raft>".to_owned(),
            cause,
        })?;
    Ok(Loaded {
        topology,
        policy: spec.policy,
        generation: next_generation(),
    })
}

pub fn load(path: &Path) -> Result<Loaded, ConfigError> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|cause| ConfigError::Read {
        path: shown.clone(),
        cause,
    })?;
    let spec: FileSpec = toml::from_str(&text).map_err(|cause| ConfigError::Parse {
        path: shown.clone(),
        cause,
    })?;
    let topology = Topology::build(spec.topology).map_err(|cause| ConfigError::Topology {
        path: shown.clone(),
        cause,
    })?;
    spec.policy
        .check(&topology.regions())
        .map_err(|cause| ConfigError::Policy { path: shown, cause })?;
    Ok(Loaded {
        topology,
        policy: spec.policy,
        generation: next_generation(),
    })
}
