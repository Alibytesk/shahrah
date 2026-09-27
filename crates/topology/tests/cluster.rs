use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use shahrah_topology::node::{Node, Spread};

fn state_dir(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("shahrah-raft-{name}-{}", std::process::id()));
    let _ignored = std::fs::remove_dir_all(&base);
    match std::fs::create_dir_all(&base) {
        Ok(()) => base,
        Err(error) => panic!("could not make {base:?}: {error}"),
    }
}

fn port(offset: u16) -> u16 {
    let pid = u16::try_from(std::process::id() % 10_000).unwrap_or(0);
    20_000u16
        .checked_add(pid % 20_000)
        .and_then(|base| base.checked_add(offset))
        .unwrap_or(29_000)
}

async fn start(id: u64, dir: &std::path::Path, offset: u16, spread: Spread) -> Node {
    let listen = format!("127.0.0.1:{}", port(offset));
    let validate: shahrah_topology::network::Validator =
        std::sync::Arc::new(|toml: &str| match toml.trim().is_empty() {
            true => Err("a topology cannot be empty".to_owned()),
            false => Ok(()),
        });
    let report: shahrah_topology::network::Reporter =
        std::sync::Arc::new(|_subject: &str| "[]".to_owned());
    match Node::start(
        id,
        &listen,
        &dir.join(format!("node{id}.json")),
        spread,
        validate,
        report,
    )
    .await
    {
        Ok(node) => node,
        Err(error) => panic!("node {id} did not start: {error}"),
    }
}

const TOPOLOGY_A: &str = r#"
[[shards]]
number = 1
primary = { address = "a:5432" }
"#;

const TOPOLOGY_B: &str = r#"
[[shards]]
number = 1
primary = { address = "a:5432" }

[[shards]]
number = 2
primary = { address = "b:5432" }
"#;

#[tokio::test]
async fn a_topology_change_survives_a_restart_of_every_node() {
    let dir = state_dir("restart");
    let mut members = BTreeMap::new();
    for id in 1..=3u64 {
        let offset = u16::try_from(id).unwrap_or(0);
        members.insert(id, format!("127.0.0.1:{}", port(offset)));
    }

    let mut nodes = Vec::new();
    for id in 1..=3u64 {
        nodes.push(start(id, &dir, u16::try_from(id).unwrap_or(0), Spread::Local).await);
    }

    let Some(first) = nodes.first() else {
        panic!("no nodes");
    };
    if let Err(error) = first.bootstrap(&members).await {
        panic!("bootstrap failed: {error}");
    }
    assert!(
        first.wait_for_leader(Duration::from_secs(10)).await.is_some(),
        "no leader was elected"
    );

    if let Err(error) = first.set_topology(TOPOLOGY_A.to_owned()).await {
        panic!("first write failed: {error}");
    }
    if let Err(error) = first.set_topology(TOPOLOGY_B.to_owned()).await {
        panic!("second write failed: {error}");
    }

    tokio::time::sleep(Duration::from_millis(700)).await;
    for node in &nodes {
        assert_eq!(
            node.topology_toml().await.as_deref(),
            Some(TOPOLOGY_B),
            "node {} did not apply the topology",
            node.id
        );
    }

    for node in nodes.drain(..) {
        let _shutdown = node.raft.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    for id in 1..=3u64 {
        let node = start(id, &dir, u16::try_from(id).unwrap_or(0), Spread::Local).await;
        assert_eq!(
            node.topology_toml().await.as_deref(),
            Some(TOPOLOGY_B),
            "node {id} lost the topology across a restart"
        );
        let _shutdown = node.raft.shutdown().await;
    }
}

#[tokio::test]
async fn a_node_can_be_added_while_the_group_stays_available() {
    let dir = state_dir("membership");
    let base = 10u16;
    let mut members = BTreeMap::new();
    for id in 1..=3u64 {
        let offset = base.saturating_add(u16::try_from(id).unwrap_or(0));
        members.insert(id, format!("127.0.0.1:{}", port(offset)));
    }

    let mut nodes = Vec::new();
    for id in 1..=3u64 {
        let offset = base.saturating_add(u16::try_from(id).unwrap_or(0));
        nodes.push(start(id, &dir, offset, Spread::Local).await);
    }
    let Some(leader) = nodes.first() else {
        panic!("no nodes");
    };
    if let Err(error) = leader.bootstrap(&members).await {
        panic!("bootstrap failed: {error}");
    }
    assert!(leader.wait_for_leader(Duration::from_secs(10)).await.is_some());
    if let Err(error) = leader.set_topology(TOPOLOGY_A.to_owned()).await {
        panic!("write failed: {error}");
    }

    let fourth_offset = base.saturating_add(4);
    let fourth = start(4, &dir, fourth_offset, Spread::Local).await;
    let fourth_address = format!("127.0.0.1:{}", port(fourth_offset));

    if let Err(error) = leader.add_learner(4, fourth_address).await {
        panic!("adding a learner failed: {error}");
    }
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        fourth.topology_toml().await.as_deref(),
        Some(TOPOLOGY_A),
        "the learner did not catch up"
    );

    if let Err(error) = leader.set_topology(TOPOLOGY_B.to_owned()).await {
        panic!("the group stopped accepting writes while a learner joined: {error}");
    }

    let voters: BTreeSet<u64> = (1..=4u64).collect();
    if let Err(error) = leader.promote_to_voter(voters).await {
        panic!("promotion to voter failed: {error}");
    }
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(fourth.topology_toml().await.as_deref(), Some(TOPOLOGY_B));

    let _shutdown = fourth.raft.shutdown().await;
    for node in nodes.drain(..) {
        let _shutdown = node.raft.shutdown().await;
    }
}

#[test]
fn cross_region_timings_are_an_order_of_magnitude_slower() {
    let (local_min, local_max, local_beat) = Spread::Local.timings();
    let (wide_min, wide_max, wide_beat) = Spread::CrossRegion.timings();

    assert!(wide_min >= local_min.saturating_mul(5));
    assert!(wide_max >= local_max.saturating_mul(5));
    assert!(wide_beat >= local_beat.saturating_mul(5));
    assert!(
        wide_min > wide_beat.saturating_mul(2),
        "an election timeout under two heartbeats will flap"
    );
    assert!(
        local_min > local_beat.saturating_mul(2),
        "an election timeout under two heartbeats will flap"
    );
}
