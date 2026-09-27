use std::collections::BTreeMap;
use std::num::NonZeroU16;

use serde::Deserialize;
use thiserror::Error;

use crate::map::{ShardMap, ShardMapBuilder, ShardMapError};
use crate::shard::PhysicalShard;

#[derive(Debug, Error)]
pub enum TopologyError {
    #[error("no shards are declared")]
    NoShards,

    #[error("shard numbers must start at 1 and be contiguous; {number} breaks that")]
    NonContiguous { number: u16 },

    #[error("shard {number} declares no primary")]
    NoPrimary { number: u16 },

    #[error("logical range {start}..={end} is out of order")]
    BadRange { start: u16, end: u16 },

    #[error(
        "logical shard {logical} in region \"{region}\" is claimed by shard {first} and shard \
         {second}; overlapping ranges would send the same key to two shards"
    )]
    Overlap {
        region: String,
        logical: u16,
        first: u16,
        second: u16,
    },

    #[error("region \"{region}\" is not covered: {cause}")]
    Region {
        region: String,
        cause: ShardMapError,
    },

    #[error(
        "this topology places shards in more than one region, so shard {number} has to say \
         which region it is in; only a single-region topology may leave it out"
    )]
    RegionNotNamed { number: u16 },

    #[error(transparent)]
    Map(#[from] ShardMapError),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    pub address: String,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShardSpec {
    pub number: u16,
    #[serde(default)]
    pub region: Option<String>,
    pub primary: Endpoint,
    #[serde(default)]
    pub replicas: Vec<Endpoint>,
    #[serde(default)]
    pub logical: Vec<RangeSpec>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct RangeSpec {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TopologySpec {
    #[serde(default)]
    pub region: Option<String>,
    pub shards: Vec<ShardSpec>,
}

#[derive(Debug)]
pub struct Shard {
    pub id: PhysicalShard,
    pub region: Option<String>,
    pub primary: Endpoint,
    pub replicas: Vec<Endpoint>,
}

#[derive(Debug)]
pub struct Topology {
    region: Option<String>,
    shards: Vec<Shard>,
    maps: BTreeMap<String, ShardMap>,
}

pub const UNNAMED_REGION: &str = "";

impl Topology {
    pub fn build(spec: TopologySpec) -> Result<Self, TopologyError> {
        if spec.shards.is_empty() {
            return Err(TopologyError::NoShards);
        }

        let mut ordered: BTreeMap<u16, ShardSpec> = BTreeMap::new();
        for shard in spec.shards {
            if shard.primary.address.is_empty() {
                return Err(TopologyError::NoPrimary {
                    number: shard.number,
                });
            }
            ordered.insert(shard.number, shard);
        }

        let count = u16::try_from(ordered.len()).unwrap_or(u16::MAX);
        let declared = NonZeroU16::new(count).ok_or(TopologyError::NoShards)?;
        let topology_region = spec.region.clone();

        let named: BTreeMap<u16, String> = ordered
            .iter()
            .filter_map(|(number, spec)| {
                spec.region
                    .clone()
                    .or_else(|| spec.primary.region.clone())
                    .map(|region| (*number, region))
            })
            .collect();
        let distinct: BTreeMap<&String, ()> = named.values().map(|region| (region, ())).collect();
        let many_regions = distinct.len() > 1;
        if many_regions && named.len() != ordered.len() {
            let missing = ordered
                .keys()
                .find(|number| !named.contains_key(number))
                .copied()
                .unwrap_or(0);
            return Err(TopologyError::RegionNotNamed { number: missing });
        }

        let mut expected: u16 = 1;
        let mut shards = Vec::with_capacity(ordered.len());
        let mut builders: BTreeMap<String, ShardMapBuilder> = BTreeMap::new();
        let mut claimed: BTreeMap<String, Vec<Option<u16>>> = BTreeMap::new();
        let mut explicit: BTreeMap<String, bool> = BTreeMap::new();

        for (number, spec) in &ordered {
            if *number != expected {
                return Err(TopologyError::NonContiguous { number: *number });
            }
            expected = expected.saturating_add(1);

            let id = PhysicalShard::from_number(*number)
                .ok_or(TopologyError::NonContiguous { number: *number })?;
            let region = spec
                .region
                .clone()
                .or_else(|| spec.primary.region.clone())
                .or_else(|| spec.region.clone().or(topology_region.clone()))
                .unwrap_or_else(|| UNNAMED_REGION.to_owned());

            let builder = builders
                .entry(region.clone())
                .or_insert_with(|| ShardMapBuilder::new(declared));
            let taken = claimed
                .entry(region.clone())
                .or_insert_with(|| vec![None; 65536]);

            for range in &spec.logical {
                if range.start > range.end {
                    return Err(TopologyError::BadRange {
                        start: range.start,
                        end: range.end,
                    });
                }
                explicit.insert(region.clone(), true);
                for index in range.start..=range.end {
                    if let Some(other) = taken.get(usize::from(index)).copied().flatten()
                        && other != *number
                    {
                        return Err(TopologyError::Overlap {
                            region: region.clone(),
                            logical: index,
                            first: other,
                            second: *number,
                        });
                    }
                    if let Some(slot) = taken.get_mut(usize::from(index)) {
                        *slot = Some(*number);
                    }
                    builder.assign(shahrah_hash::shard::LogicalShard::from_index(index), id)?;
                }
            }

            shards.push(Shard {
                id,
                region: Some(region.clone()).filter(|name| name != UNNAMED_REGION),
                primary: spec.primary.clone(),
                replicas: spec.replicas.clone(),
            });
        }

        for (region, builder) in &mut builders {
            if explicit.get(region).copied().unwrap_or(false) {
                continue;
            }
            let members: Vec<PhysicalShard> = shards
                .iter()
                .filter(|shard| {
                    shard.region.as_deref().unwrap_or(UNNAMED_REGION) == region.as_str()
                })
                .map(|shard| shard.id)
                .collect();
            let width = u32::try_from(members.len()).unwrap_or(1).max(1);
            for index in 0..=u32::from(u16::MAX) {
                let slot = index
                    .checked_mul(width)
                    .and_then(|scaled| scaled.checked_div(65536))
                    .and_then(|slot| usize::try_from(slot).ok())
                    .unwrap_or(0);
                let owner = members.get(slot).copied().ok_or(TopologyError::NoShards)?;
                let logical = u16::try_from(index).unwrap_or(u16::MAX);
                builder.assign(shahrah_hash::shard::LogicalShard::from_index(logical), owner)?;
            }
        }

        let mut maps = BTreeMap::new();
        for (region, builder) in builders {
            let map = builder.build().map_err(|cause| TopologyError::Region {
                region: region.clone(),
                cause,
            })?;
            maps.insert(region, map);
        }

        Ok(Self {
            region: spec.region,
            shards,
            maps,
        })
    }

    #[must_use]
    pub fn map_for(&self, region: Option<&str>) -> Option<&ShardMap> {
        let wanted = region.unwrap_or(UNNAMED_REGION);
        self.maps
            .get(wanted)
            .or_else(|| (self.maps.len() == 1).then(|| self.maps.values().next()).flatten())
    }

    #[must_use]
    pub fn placed_regions(&self) -> Vec<&str> {
        self.maps.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn map(&self) -> Option<&ShardMap> {
        self.map_for(self.region.as_deref())
    }

    #[must_use]
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    #[must_use]
    pub fn regions(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for shard in &self.shards {
            for endpoint in core::iter::once(&shard.primary).chain(shard.replicas.iter()) {
                if let Some(region) = &endpoint.region
                    && !seen.contains(region)
                {
                    seen.push(region.clone());
                }
            }
        }
        seen.sort();
        seen
    }

    #[must_use]
    pub fn shards(&self) -> &[Shard] {
        &self.shards
    }

    #[must_use]
    pub fn shard(&self, id: PhysicalShard) -> Option<&Shard> {
        self.shards
            .iter()
            .find(|candidate| candidate.id.number() == id.number())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }
}
