use core::num::NonZeroU16;
use shahrah_hash::shard::{LogicalShard, LOGICAL_SHARDS};
use shahrah_routing::map::{ShardMapBuilder, ShardMapError};
use shahrah_routing::shard::PhysicalShard;

const SLOTS: u32 = LOGICAL_SHARDS;

fn physical(number: u16) -> PhysicalShard {
    match PhysicalShard::from_number(number) {
        Some(shard) => shard,
        None => panic!("physical shards are numbered from 1; {number} is not valid"),
    }
}

fn declared(count: u16) -> NonZeroU16 {
    match NonZeroU16::new(count) {
        Some(value) => value,
        None => panic!("a map needs at least one physical shard"),
    }
}

fn round_robin(index: u16, count: u16) -> u16 {
    index.checked_rem(count).unwrap_or(0).saturating_add(1)
}

fn full_builder(count: u16) -> ShardMapBuilder {
    let mut builder = ShardMapBuilder::new(declared(count));
    for index in 0..=u16::MAX {
        let number = round_robin(index, count);
        match builder.assign(LogicalShard::from_index(index), physical(number)) {
            Ok(()) => {}
            Err(error) => panic!("assigning shard {index} failed: {error}"),
        }
    }
    builder
}

#[test]
fn every_logical_shard_resolves() {
    let map = match full_builder(4).build() {
        Ok(map) => map,
        Err(error) => panic!("a fully assigned builder must build: {error}"),
    };
    for index in 0..=u16::MAX {
        let expected = round_robin(index, 4);
        let got = map.get(LogicalShard::from_index(index)).number();
        assert_eq!(got, expected, "logical shard {index}");
    }
}

#[test]
fn a_single_hole_is_rejected_and_named() {
    let mut builder = ShardMapBuilder::new(declared(1));
    for index in 0..=u16::MAX {
        if index == 40_000 {
            continue;
        }
        match builder.assign(LogicalShard::from_index(index), physical(1)) {
            Ok(()) => {}
            Err(error) => panic!("assigning shard {index} failed: {error}"),
        }
    }
    match builder.build() {
        Ok(_) => panic!("a map with a hole must not build"),
        Err(error) => assert_eq!(
            error,
            ShardMapError::Unassigned {
                count: 1,
                first: 40_000
            }
        ),
    }
}

#[test]
fn an_empty_builder_reports_every_slot_and_starts_at_zero() {
    match ShardMapBuilder::new(declared(1)).build() {
        Ok(_) => panic!("an empty builder must not build"),
        Err(error) => assert_eq!(
            error,
            ShardMapError::Unassigned {
                count: SLOTS,
                first: 0
            }
        ),
    }
}

#[test]
fn a_physical_shard_above_the_declared_count_is_rejected() {
    let mut builder = ShardMapBuilder::new(declared(4));
    match builder.assign(LogicalShard::from_index(7), physical(5)) {
        Ok(()) => panic!("physical shard 5 does not exist when 4 are declared"),
        Err(error) => assert_eq!(
            error,
            ShardMapError::OutOfRange {
                logical: 7,
                physical: 5,
                declared: 4
            }
        ),
    }
}

#[test]
fn the_last_assignment_wins() {
    let mut builder = full_builder(4);
    match builder.assign(LogicalShard::from_index(9), physical(3)) {
        Ok(()) => {}
        Err(error) => panic!("reassignment must be allowed: {error}"),
    }
    let map = match builder.build() {
        Ok(map) => map,
        Err(error) => panic!("build failed: {error}"),
    };
    assert_eq!(map.get(LogicalShard::from_index(9)).number(), 3);
}

#[test]
fn a_physical_shard_with_no_slots_is_allowed() {
    let mut builder = ShardMapBuilder::new(declared(8));
    for index in 0..=u16::MAX {
        match builder.assign(LogicalShard::from_index(index), physical(1)) {
            Ok(()) => {}
            Err(error) => panic!("assigning shard {index} failed: {error}"),
        }
    }
    match builder.build() {
        Ok(map) => assert_eq!(map.get(LogicalShard::from_index(0)).number(), 1),
        Err(error) => panic!("shards 2..=8 owning nothing is legal: {error}"),
    }
}

#[test]
fn debug_does_not_print_every_slot() {
    let map = match full_builder(2).build() {
        Ok(map) => map,
        Err(error) => panic!("build failed: {error}"),
    };
    let rendered = format!("{map:?}");
    assert!(rendered.len() < 120, "Debug output was {rendered:?}");
}