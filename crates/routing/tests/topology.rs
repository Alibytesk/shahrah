use shahrah_hash::shard::LogicalShard;
use shahrah_routing::map::{ShardMap, ShardMapError};
use shahrah_routing::topology::{Topology, TopologyError, TopologySpec};

fn spec(text: &str) -> TopologySpec {
    match toml::from_str(text) {
        Ok(spec) => spec,
        Err(error) => panic!("config did not parse: {error}"),
    }
}

fn build(text: &str) -> Topology {
    match Topology::build(spec(text)) {
        Ok(topology) => topology,
        Err(error) => panic!("topology did not build: {error}"),
    }
}

const THREE: &str = r#"
region = "eu-central"

[[shards]]
number = 1
primary = { address = "10.0.0.1:5432", region = "eu-central" }
replicas = [{ address = "10.0.0.2:5432", region = "eu-central" }]

[[shards]]
number = 2
primary = { address = "10.0.0.3:5432" }

[[shards]]
number = 3
primary = { address = "10.0.0.4:5432" }
"#;

#[test]
fn an_even_split_covers_every_logical_shard() {
    let topology = build(THREE);
    assert_eq!(topology.len(), 3);
    assert_eq!(topology.region(), Some("eu-central"));

    let mut counts = [0u32; 4];
    for index in 0..=u16::MAX {
        let physical = map_of(&topology).get(LogicalShard::from_index(index));
        let slot = usize::from(physical.number());
        match counts.get_mut(slot) {
            Some(count) => *count = count.saturating_add(1),
            None => panic!("shard {slot} is outside the declared set"),
        }
    }

    assert_eq!(counts[0], 0, "shard numbers start at 1");
    let total: u32 = counts.iter().sum();
    assert_eq!(total, 65536);
    for (number, count) in counts.iter().enumerate().skip(1) {
        assert!(
            (21845..=21846).contains(count),
            "shard {number} owns {count} logical shards, expected an even third"
        );
    }
}

#[test]
fn replicas_and_regions_survive_the_round_trip() {
    let topology = build(THREE);
    let first = match topology.shards().first() {
        Some(shard) => shard,
        None => panic!("no shards"),
    };
    assert_eq!(first.primary.address, "10.0.0.1:5432");
    assert_eq!(first.primary.region.as_deref(), Some("eu-central"));
    assert_eq!(first.replicas.len(), 1);

    let second = match topology.shards().get(1) {
        Some(shard) => shard,
        None => panic!("missing shard 2"),
    };
    assert!(second.replicas.is_empty());
    assert_eq!(second.primary.region, None);
}

#[test]
fn an_explicit_range_assignment_is_honoured() {
    let topology = build(
        r#"
[[shards]]
number = 1
primary = { address = "a:5432" }
logical = [{ start = 0, end = 39999 }]

[[shards]]
number = 2
primary = { address = "b:5432" }
logical = [{ start = 40000, end = 65535 }]
"#,
    );
    assert_eq!(map_of(&topology).get(LogicalShard::from_index(0)).number(), 1);
    assert_eq!(
        map_of(&topology).get(LogicalShard::from_index(39_999)).number(),
        1
    );
    assert_eq!(
        map_of(&topology).get(LogicalShard::from_index(40_000)).number(),
        2
    );
    assert_eq!(
        map_of(&topology).get(LogicalShard::from_index(65_535)).number(),
        2
    );
}

#[test]
fn a_partial_explicit_assignment_is_refused() {
    let error = Topology::build(spec(
        r#"
[[shards]]
number = 1
primary = { address = "a:5432" }
logical = [{ start = 0, end = 100 }]

[[shards]]
number = 2
primary = { address = "b:5432" }
"#,
    ));
    match error {
        Err(TopologyError::Region { .. } | TopologyError::Map(_)) => {}
        other => panic!("a map with a hole must be refused, got {other:?}"),
    }
}

#[test]
fn shard_numbers_must_be_contiguous_from_one() {
    let error = Topology::build(spec(
        r#"
[[shards]]
number = 1
primary = { address = "a:5432" }

[[shards]]
number = 3
primary = { address = "c:5432" }
"#,
    ));
    match error {
        Err(TopologyError::NonContiguous { number: 3 }) => {}
        other => panic!("expected a contiguity error, got {other:?}"),
    }
}

#[test]
fn an_empty_topology_is_refused() {
    match Topology::build(spec("shards = []")) {
        Err(TopologyError::NoShards) => {}
        other => panic!("expected NoShards, got {other:?}"),
    }
}

#[test]
fn a_shard_without_a_primary_is_refused() {
    match Topology::build(spec(
        r#"
[[shards]]
number = 1
primary = { address = "" }
"#,
    )) {
        Err(TopologyError::NoPrimary { number: 1 }) => {}
        other => panic!("expected NoPrimary, got {other:?}"),
    }
}

#[test]
fn a_backwards_range_is_refused() {
    match Topology::build(spec(
        r#"
[[shards]]
number = 1
primary = { address = "a:5432" }
logical = [{ start = 500, end = 100 }]
"#,
    )) {
        Err(TopologyError::BadRange {
            start: 500,
            end: 100,
        }) => {}
        other => panic!("expected BadRange, got {other:?}"),
    }
}

#[test]
fn one_shard_owns_everything() {
    let topology = build(
        r#"
[[shards]]
number = 1
primary = { address = "only:5432" }
"#,
    );
    for index in [0u16, 1, 12_345, 65_535] {
        assert_eq!(map_of(&topology).get(LogicalShard::from_index(index)).number(), 1);
    }
}

#[test]
fn a_shard_can_be_looked_up_by_id() {
    let topology = build(THREE);
    let physical = map_of(&topology).get(LogicalShard::from_index(0));
    let shard = match topology.shard(physical) {
        Some(shard) => shard,
        None => panic!("the map named a shard the topology does not hold"),
    };
    assert_eq!(shard.id.number(), physical.number());
}

#[test]
fn overlapping_logical_ranges_are_refused() {
    let overlapping = spec(
        r#"
[[shards]]
number = 1
primary = { address = "a:5432" }
logical = [{ start = 0, end = 65535 }]

[[shards]]
number = 2
primary = { address = "b:5432" }
logical = [{ start = 0, end = 65535 }]
"#,
    );
    match Topology::build(overlapping) {
        Err(TopologyError::Overlap {
            logical: 0,
            first: 1,
            second: 2,
            ..
        }) => {}
        other => panic!("overlapping ranges must be refused, got {other:?}"),
    }
}

#[test]
fn adjacent_ranges_that_do_not_overlap_still_build() {
    let adjacent = spec(
        r#"
[[shards]]
number = 1
primary = { address = "a:5432" }
logical = [{ start = 0, end = 32767 }]

[[shards]]
number = 2
primary = { address = "b:5432" }
logical = [{ start = 32768, end = 65535 }]
"#,
    );
    if let Err(error) = Topology::build(adjacent) {
        panic!("adjacent ranges must build: {error}");
    }
}

fn map_of(topology: &Topology) -> &ShardMap {
    match topology.map() {
        Some(map) => map,
        None => panic!("this topology has no map for its own region"),
    }
}

const THREE_REGIONS: &str = r#"
region = "na-east"

[[shards]]
number = 1
region = "na-east"
primary = { address = "a:5432" }
logical = [{ start = 0, end = 32767 }]

[[shards]]
number = 2
region = "na-east"
primary = { address = "b:5432" }
logical = [{ start = 32768, end = 65535 }]

[[shards]]
number = 3
region = "eu-central"
primary = { address = "c:5432" }
logical = [{ start = 0, end = 21844 }]

[[shards]]
number = 4
region = "eu-central"
primary = { address = "d:5432" }
logical = [{ start = 21845, end = 65535 }]
"#;

#[test]
fn every_region_carries_its_own_complete_map() {
    let topology = build(THREE_REGIONS);
    assert_eq!(topology.placed_regions(), vec!["eu-central", "na-east"]);

    for region in ["na-east", "eu-central"] {
        let Some(map) = topology.map_for(Some(region)) else {
            panic!("region {region} has no map");
        };
        let mut seen = 0u32;
        for index in 0..=u16::MAX {
            let owner = map.get(LogicalShard::from_index(index)).number();
            let placed = topology
                .shards()
                .iter()
                .find(|shard| shard.id.number() == owner)
                .and_then(|shard| shard.region.as_deref());
            assert_eq!(
                placed,
                Some(region),
                "region {region} maps logical {index} to shard {owner}, which is not in it"
            );
            seen = seen.saturating_add(1);
        }
        assert_eq!(seen, 65_536);
    }
}

#[test]
fn the_same_key_lands_on_a_different_shard_in_each_region() {
    let topology = build(THREE_REGIONS);
    let mut differed = 0u32;
    for index in 0..=u16::MAX {
        let logical = LogicalShard::from_index(index);
        let Some(here) = topology.map_for(Some("na-east")) else {
            panic!("na-east has no map");
        };
        let Some(there) = topology.map_for(Some("eu-central")) else {
            panic!("eu-central has no map");
        };
        assert_ne!(
            here.get(logical).number(),
            there.get(logical).number(),
            "a logical shard cannot resolve to the same physical shard in two regions"
        );
        differed = differed.saturating_add(1);
    }
    assert_eq!(differed, 65_536);
}

#[test]
fn a_region_a_shard_does_not_name_is_refused_once_there_are_two() {
    let mixed = spec(
        r#"
[[shards]]
number = 1
region = "na-east"
primary = { address = "a:5432" }
logical = [{ start = 0, end = 65535 }]

[[shards]]
number = 2
region = "eu-central"
primary = { address = "b:5432" }
logical = [{ start = 0, end = 65535 }]

[[shards]]
number = 3
primary = { address = "c:5432" }
logical = [{ start = 0, end = 65535 }]
"#,
    );
    match Topology::build(mixed) {
        Err(TopologyError::RegionNotNamed { number: 3 }) => {}
        other => panic!("an unplaced shard beside two regions must be refused, got {other:?}"),
    }
}

#[test]
fn a_hole_is_reported_against_the_region_it_is_in() {
    let holed = spec(
        r#"
region = "na-east"

[[shards]]
number = 1
region = "na-east"
primary = { address = "a:5432" }
logical = [{ start = 0, end = 65535 }]

[[shards]]
number = 2
region = "eu-central"
primary = { address = "b:5432" }
logical = [{ start = 0, end = 60000 }]
"#,
    );
    match Topology::build(holed) {
        Err(TopologyError::Region { region, cause }) => {
            assert_eq!(region, "eu-central");
            assert!(
                matches!(cause, ShardMapError::Unassigned { first: 60_001, .. }),
                "the hole has to name where it starts, got {cause:?}"
            );
        }
        other => panic!("a region with a hole must be refused, got {other:?}"),
    }
}

#[test]
fn a_shard_that_names_no_region_joins_the_one_the_topology_is_in() {
    let topology = build(THREE);
    assert_eq!(topology.placed_regions(), vec!["eu-central"]);
    for shard in topology.shards() {
        assert_eq!(shard.region.as_deref(), Some("eu-central"));
    }
}
