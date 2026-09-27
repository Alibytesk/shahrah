use core::num::NonZeroU16;
use divan::{black_box, Bencher};
use shahrah_hash::key::ShardKey;
use shahrah_hash::shard::{HashVersion, LogicalShard};
use shahrah_routing::map::{ShardMap, ShardMapBuilder};
use shahrah_routing::shard::PhysicalShard;

fn main() {
    divan::main();
}

const CHAIN: usize = 4096;
const STRIDE: u16 = 40_503;

fn map_over(physical_count: u16) -> ShardMap {
    let declared = match NonZeroU16::new(physical_count) {
        Some(value) => value,
        None => panic!("a map needs at least one physical shard"),
    };
    let mut builder = ShardMapBuilder::new(declared);
    for index in 0..=u16::MAX {
        let number = index
            .checked_rem(physical_count)
            .unwrap_or(0)
            .saturating_add(1);
        let physical = match PhysicalShard::from_number(number) {
            Some(shard) => shard,
            None => panic!("physical shard numbers start at 1"),
        };
        match builder.assign(LogicalShard::from_index(index), physical) {
            Ok(()) => {}
            Err(error) => panic!("assigning shard {index} failed: {error}"),
        }
    }
    match builder.build() {
        Ok(map) => map,
        Err(error) => panic!("a fully assigned builder must build: {error}"),
    }
}

#[divan::bench]
fn lookup_hot(bencher: Bencher) {
    let map = map_over(8);
    bencher.bench(|| {
        let mut acc: u16 = black_box(12_345);
        for _ in 0..CHAIN {
            acc = map
                .get(LogicalShard::from_index(black_box(12_345)))
                .number()
                .wrapping_add(acc);
        }
        acc
    });
}

#[divan::bench]
fn lookup_scattered(bencher: Bencher) {
    let map = map_over(8);
    bencher.bench(|| {
        let mut index: u16 = black_box(0);
        for _ in 0..CHAIN {
            let physical = map.get(LogicalShard::from_index(index)).number();
            index = index.wrapping_add(STRIDE).wrapping_add(physical);
        }
        index
    });
}

#[divan::bench]
fn key_to_physical(bencher: Bencher) {
    let map = map_over(8);
    bencher.bench(|| {
        let mut key: i64 = black_box(1);
        for _ in 0..CHAIN {
            let logical = LogicalShard::of(ShardKey::Int(key), HashVersion::V1);
            let physical = map.get(logical).number();
            key = key.wrapping_add(i64::from(physical));
        }
        key
    });
}