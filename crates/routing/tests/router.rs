use shahrah_hash::key::ShardKey;
use shahrah_hash::shard::{HashVersion, LogicalShard};
use shahrah_routing::router::{
    anywhere, anywhere_in, anywhere_order, logical_for, route, Intent, RouteError, Role,
};
use shahrah_routing::map::ShardMap;
use shahrah_routing::topology::{Topology, TopologySpec};

const THREE: &str = r#"
region = "eu-central"

[[shards]]
number = 1
primary = { address = "s1-primary:5432", region = "eu-central" }
replicas = [
  { address = "s1-replica-us:5432", region = "na-east" },
  { address = "s1-replica-eu:5432", region = "eu-central" },
]

[[shards]]
number = 2
primary = { address = "s2-primary:5432", region = "eu-central" }

[[shards]]
number = 3
primary = { address = "s3-primary:5432", region = "eu-central" }
replicas = [{ address = "s3-replica-us:5432", region = "na-east" }]
"#;

fn topology(text: &str) -> Topology {
    let spec: TopologySpec = match toml::from_str(text) {
        Ok(spec) => spec,
        Err(error) => panic!("config did not parse: {error}"),
    };
    match Topology::build(spec) {
        Ok(topology) => topology,
        Err(error) => panic!("topology did not build: {error}"),
    }
}

#[test]
fn the_same_key_always_reaches_the_same_shard() {
    let topology = topology(THREE);
    let first = logical_for(ShardKey::Int(42), HashVersion::V1);
    for _repeat in 0..100 {
        assert_eq!(logical_for(ShardKey::Int(42), HashVersion::V1), first);
    }
    let decision = match route(&topology, first, Intent::Write) {
        Ok(decision) => decision,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(decision.logical.map(|shard| shard.get()), Some(10_184));
    assert_eq!(decision.role, Role::Primary);
}

#[test]
fn writes_always_go_to_the_primary() {
    let topology = topology(THREE);
    for index in [0u16, 1, 10_184, 40_000, 65_535] {
        let decision = match route(&topology, LogicalShard::from_index(index), Intent::Write) {
            Ok(decision) => decision,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(decision.role, Role::Primary, "logical {index}");
        assert!(decision.address.ends_with("-primary:5432"), "logical {index}");
    }
}

#[test]
fn a_read_prefers_a_replica_in_the_local_region() {
    let topology = topology(THREE);
    let logical = LogicalShard::from_index(0);
    let physical = map_of(&topology).get(logical);
    if physical.number() != 1 {
        return;
    }
    let decision = match route(&topology, logical, Intent::Read) {
        Ok(decision) => decision,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(decision.address, "s1-replica-eu:5432");
    assert!(decision.local_region);
}

#[test]
fn a_read_falls_back_to_the_primary_when_a_shard_has_no_replica() {
    let topology = topology(THREE);
    let mut checked = false;
    for index in 0..=u16::MAX {
        let logical = LogicalShard::from_index(index);
        if map_of(&topology).get(logical).number() != 2 {
            continue;
        }
        let decision = match route(&topology, logical, Intent::Read) {
            Ok(decision) => decision,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(decision.role, Role::Primary);
        assert_eq!(decision.address, "s2-primary:5432");
        checked = true;
        break;
    }
    assert!(checked, "shard 2 owns no logical shard, which cannot happen");
}

#[test]
fn a_remote_replica_is_used_but_marked_remote() {
    let topology = topology(THREE);
    for index in 0..=u16::MAX {
        let logical = LogicalShard::from_index(index);
        if map_of(&topology).get(logical).number() != 3 {
            continue;
        }
        let decision = match route(&topology, logical, Intent::Read) {
            Ok(decision) => decision,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(decision.address, "s3-replica-us:5432");
        assert!(
            !decision.local_region,
            "a replica in na-east is not local to eu-central"
        );
        return;
    }
    panic!("shard 3 owns no logical shard, which cannot happen");
}

#[test]
fn every_logical_shard_routes_somewhere() {
    let topology = topology(THREE);
    for index in 0..=u16::MAX {
        let logical = LogicalShard::from_index(index);
        match route(&topology, logical, Intent::Write) {
            Ok(decision) => assert!(!decision.address.is_empty()),
            Err(error) => panic!("logical {index} did not route: {error}"),
        }
    }
}

#[test]
fn a_shard_the_topology_does_not_hold_is_an_error_not_a_panic() {
    let single = topology(
        r#"
[[shards]]
number = 1
primary = { address = "only:5432" }
"#,
    );
    let decision = route(&single, LogicalShard::from_index(7), Intent::Write);
    match decision {
        Ok(decision) => assert_eq!(decision.address, "only:5432"),
        Err(error) => panic!("{error}"),
    }

    let missing = RouteError::UnknownShard { number: 9 };
    assert_eq!(
        missing.to_string(),
        "the map names shard 9, which the topology does not hold"
    );
}

#[test]
fn keys_of_different_types_land_where_the_frozen_vectors_say() {
    let topology = topology(THREE);
    let cases: [(ShardKey<'_>, u16); 3] = [
        (ShardKey::Int(42), 10_184),
        (ShardKey::Text("ali"), 36_933),
        (ShardKey::Bytes(&[0x00, 0xFF]), 35_827),
    ];
    for (key, expected) in cases {
        let logical = logical_for(key, HashVersion::V1);
        assert_eq!(logical.get(), expected, "{key:?}");
        assert!(route(&topology, logical, Intent::Read).is_ok());
    }
}

const ONE_PER_REGION: &str = r#"
region = "eu-central"

[[shards]]
number = 1
primary = { address = "na:5432", region = "na-east" }
logical = [{ start = 0, end = 65535 }]

[[shards]]
number = 2
primary = { address = "eu:5432", region = "eu-central" }
logical = [{ start = 0, end = 65535 }]

[[shards]]
number = 3
primary = { address = "asia:5432", region = "asia-west" }
logical = [{ start = 0, end = 65535 }]
"#;

const TWO_IN_THE_LOCAL_REGION: &str = r#"
region = "eu-central"

[[shards]]
number = 1
primary = { address = "na:5432", region = "na-east" }
logical = [{ start = 0, end = 65535 }]

[[shards]]
number = 2
primary = { address = "eu-a:5432", region = "eu-central" }
logical = [{ start = 0, end = 32767 }]

[[shards]]
number = 3
primary = { address = "eu-b:5432", region = "eu-central" }
logical = [{ start = 32768, end = 65535 }]
"#;

const WITH_REPLICAS: &str = r#"
region = "eu-central"

[[shards]]
number = 1
primary = { address = "na:5432", region = "na-east" }
replicas = [{ address = "na-replica:5432", region = "na-east" }]
logical = [{ start = 0, end = 65535 }]

[[shards]]
number = 2
primary = { address = "eu:5432", region = "eu-central" }
replicas = [{ address = "eu-replica:5432", region = "eu-central" }]
logical = [{ start = 0, end = 65535 }]
"#;

fn everything_is_usable(_address: &str) -> bool {
    true
}

fn chosen(topology: &Topology, intent: Intent, usable: &dyn Fn(&str) -> bool) -> String {
    match anywhere(topology, intent, usable) {
        Some(decision) => decision.address,
        None => panic!("a topology with shards in it named no endpoint at all"),
    }
}

#[test]
fn a_statement_that_names_no_shard_stays_in_the_local_region() {
    let topology = topology(ONE_PER_REGION);
    assert_eq!(
        chosen(&topology, Intent::Write, &everything_is_usable),
        "eu:5432"
    );
}

#[test]
fn the_lowest_numbered_local_shard_is_the_one_chosen() {
    let topology = topology(TWO_IN_THE_LOCAL_REGION);
    assert_eq!(
        chosen(&topology, Intent::Write, &everything_is_usable),
        "eu-a:5432"
    );
}

#[test]
fn each_region_gets_its_own_endpoint_for_a_statement_that_names_no_shard() {
    let topology = topology(ONE_PER_REGION);
    let cases = [
        ("na-east", "na:5432"),
        ("eu-central", "eu:5432"),
        ("asia-west", "asia:5432"),
    ];
    for (region, expected) in cases {
        match anywhere_in(&topology, Some(region), Intent::Write, &everything_is_usable) {
            Some(decision) => assert_eq!(decision.address, expected, "in {region}"),
            None => panic!("{region} named no endpoint"),
        }
    }
}

#[test]
fn a_region_that_holds_no_shard_falls_back_rather_than_answering_nothing() {
    let topology = topology(ONE_PER_REGION);
    for region in [Some("sa-east"), None] {
        match anywhere_in(&topology, region, Intent::Write, &everything_is_usable) {
            Some(decision) => assert_eq!(decision.address, "na:5432", "{region:?}"),
            None => panic!("{region:?} named no endpoint"),
        }
    }
}

#[test]
fn a_single_region_topology_names_its_only_endpoint() {
    let single = topology(
        r#"
[[shards]]
number = 1
primary = { address = "only:5432" }
"#,
    );
    assert_eq!(
        chosen(&single, Intent::Write, &everything_is_usable),
        "only:5432"
    );
}

#[test]
fn the_local_shards_come_first_in_the_order() {
    let topology = topology(TWO_IN_THE_LOCAL_REGION);
    let order: Vec<u16> = anywhere_order(&topology, topology.region())
        .map(|shard| shard.number())
        .collect();
    assert_eq!(order, vec![2, 3, 1]);

    let unnamed: Vec<u16> = anywhere_order(&topology, None)
        .map(|shard| shard.number())
        .collect();
    assert_eq!(unnamed, vec![1, 2, 3]);
}

#[test]
fn an_endpoint_taken_out_of_service_is_stepped_over() {
    let topology = topology(ONE_PER_REGION);
    let draining = |address: &str| !address.starts_with("eu");
    assert_eq!(chosen(&topology, Intent::Write, &draining), "na:5432");
}

#[test]
fn an_unroutable_read_prefers_a_replica_in_the_local_region() {
    let topology = topology(WITH_REPLICAS);
    assert_eq!(
        chosen(&topology, Intent::Read, &everything_is_usable),
        "eu-replica:5432"
    );
}

#[test]
fn an_unroutable_write_is_never_sent_to_a_replica() {
    let topology = topology(WITH_REPLICAS);
    assert_eq!(
        chosen(&topology, Intent::Write, &everything_is_usable),
        "eu:5432"
    );
}

#[test]
fn a_read_whose_local_replica_is_down_falls_back_to_the_primary_beside_it() {
    let topology = topology(WITH_REPLICAS);
    let replica_is_down = |address: &str| address != "eu-replica:5432";
    assert_eq!(chosen(&topology, Intent::Read, &replica_is_down), "eu:5432");
}

#[test]
fn a_read_whose_whole_local_shard_is_down_crosses_to_another_region() {
    let topology = topology(WITH_REPLICAS);
    let region_is_down = |address: &str| !address.starts_with("eu");
    assert_eq!(
        chosen(&topology, Intent::Read, &region_is_down),
        "na-replica:5432"
    );
}

#[test]
fn when_nothing_is_usable_it_still_names_an_endpoint_rather_than_refusing() {
    let topology = topology(WITH_REPLICAS);
    let nothing = |_address: &str| false;
    assert_eq!(chosen(&topology, Intent::Write, &nothing), "eu:5432");
    assert_eq!(chosen(&topology, Intent::Read, &nothing), "eu-replica:5432");
}

fn map_of(topology: &Topology) -> &ShardMap {
    match topology.map() {
        Some(map) => map,
        None => panic!("this topology has no map for its own region"),
    }
}
