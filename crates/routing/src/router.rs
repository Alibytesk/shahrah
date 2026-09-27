use shahrah_hash::key::ShardKey;
use shahrah_hash::shard::{HashVersion, LogicalShard};
use thiserror::Error;

use crate::shard::PhysicalShard;
use crate::topology::{Endpoint, Shard, Topology};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RouteError {
    #[error("the map names shard {number}, which the topology does not hold")]
    UnknownShard { number: u16 },

    #[error("this topology places no shards in region \"{region}\"")]
    UnknownRegion { region: String },

    #[error(
        "endpoint {endpoint} is draining and this shard has no other endpoint that can serve \
         the statement, so shahrah refuses it rather than send work somewhere an operator has \
         taken out of service"
    )]
    Draining { endpoint: String },

    #[error("shard {number} has no endpoint that can serve a {intent}")]
    NoEndpoint { number: u16, intent: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Read,
    Write,
}

impl Intent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Replica,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    WriteNeedsPrimary,
    LocalReplica,
    RemoteReplica,
    NoReplicaConfigured,
    PinnedByHint,
}

impl Why {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WriteNeedsPrimary => "a write must reach the primary",
            Self::LocalReplica => "a replica in the local region was available",
            Self::RemoteReplica => "the only replicas are outside the local region",
            Self::NoReplicaConfigured => "this shard declares no replica, so the read fell back to the primary",
            Self::PinnedByHint => "the statement carried a hint naming this shard",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub logical: Option<LogicalShard>,
    pub physical: PhysicalShard,
    pub role: Role,
    pub address: String,
    pub region: Option<String>,
    pub local_region: bool,
    pub why: Why,
}

#[must_use]
pub fn logical_for(key: ShardKey<'_>, version: HashVersion) -> LogicalShard {
    LogicalShard::of(key, version)
}

pub fn route(
    topology: &Topology,
    logical: LogicalShard,
    intent: Intent,
) -> Result<Decision, RouteError> {
    route_in(topology, topology.region(), logical, intent)
}

pub fn route_in(
    topology: &Topology,
    region: Option<&str>,
    logical: LogicalShard,
    intent: Intent,
) -> Result<Decision, RouteError> {
    let map = topology
        .map_for(region)
        .ok_or_else(|| RouteError::UnknownRegion {
            region: region.unwrap_or_default().to_owned(),
        })?;
    let physical = map.get(logical);
    let mut decision = route_to_shard(topology, physical, intent)?;
    decision.logical = Some(logical);
    Ok(decision)
}

pub fn anywhere_order<'a>(
    topology: &'a Topology,
    region: Option<&'a str>,
) -> impl Iterator<Item = PhysicalShard> + 'a {
    let local = move |shard: &&Shard| match region {
        Some(wanted) => shard.region.as_deref() == Some(wanted),
        None => false,
    };
    topology
        .shards()
        .iter()
        .filter(local)
        .chain(topology.shards().iter().filter(move |shard| !local(shard)))
        .map(|shard| shard.id)
}

pub fn anywhere(
    topology: &Topology,
    intent: Intent,
    usable: &dyn Fn(&str) -> bool,
) -> Option<Decision> {
    anywhere_in(topology, topology.region(), intent, usable)
}

pub fn anywhere_in(
    topology: &Topology,
    region: Option<&str>,
    intent: Intent,
    usable: &dyn Fn(&str) -> bool,
) -> Option<Decision> {
    let mut first: Option<Decision> = None;
    for physical in anywhere_order(topology, region) {
        let Ok(decision) = route_to_shard(topology, physical, intent) else {
            continue;
        };
        if usable(&decision.address) {
            return Some(decision);
        }
        if intent == Intent::Read
            && let Ok(primary) = route_to_shard(topology, physical, Intent::Write)
            && usable(&primary.address)
        {
            return Some(primary);
        }
        if first.is_none() {
            first = Some(decision);
        }
    }
    first
}

pub fn route_to_shard(
    topology: &Topology,
    physical: PhysicalShard,
    intent: Intent,
) -> Result<Decision, RouteError> {
    let shard = topology
        .shard(physical)
        .ok_or(RouteError::UnknownShard {
            number: physical.number(),
        })?;

    let (endpoint, role, why) = match intent {
        Intent::Write => (&shard.primary, Role::Primary, Why::WriteNeedsPrimary),
        Intent::Read => match pick_replica(&shard.replicas, topology.region()) {
            Some((replica, local)) => (
                replica,
                Role::Replica,
                if local {
                    Why::LocalReplica
                } else {
                    Why::RemoteReplica
                },
            ),
            None => (
                &shard.primary,
                Role::Primary,
                Why::NoReplicaConfigured,
            ),
        },
    };

    if endpoint.address.is_empty() {
        return Err(RouteError::NoEndpoint {
            number: physical.number(),
            intent: intent.as_str(),
        });
    }

    let local_region = match (topology.region(), endpoint.region.as_deref()) {
        (Some(local), Some(theirs)) => local == theirs,
        _ => false,
    };

    Ok(Decision {
        logical: None,
        physical,
        role,
        address: endpoint.address.clone(),
        region: endpoint.region.clone(),
        local_region,
        why,
    })
}

fn pick_replica<'a>(replicas: &'a [Endpoint], local: Option<&str>) -> Option<(&'a Endpoint, bool)> {
    if let Some(local) = local
        && let Some(near) = replicas
            .iter()
            .find(|replica| replica.region.as_deref() == Some(local))
    {
        return Some((near, true));
    }
    replicas.first().map(|replica| (replica, false))
}
