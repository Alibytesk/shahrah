#![allow(clippy::print_stdout)]

use shahrah_hash::key::ShardKey;
use shahrah_hash::shard::{HashVersion, LogicalShard};

const KEYS: u64 = 10_000_000;
const BUCKETS: usize = 65536;

const MAX_OVER_MEAN: f64 = 1.5;
const MIN_OVER_MEAN: f64 = 0.5;

const MAX_SIGMA: f64 = 5.0;

fn measure(label: &str, shard_of: impl Fn(u64) -> u16) {
    let mut counts = vec![0u32; BUCKETS];
    for i in 0..KEYS {
        let bucket = usize::from(shard_of(i));
        match counts.get_mut(bucket) {
            Some(count) => *count = count.saturating_add(1),
            None => panic!("{label}: shard {bucket} is outside 0..{BUCKETS}"),
        }
    }
    let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    assert_eq!(total, KEYS, "{label}: counted {total} keys, expected {KEYS}");
    let empty = counts.iter().filter(|&&c| c == 0).count();
    let min = counts.iter().copied().min().unwrap_or(0);
    let max = counts.iter().copied().max().unwrap_or(0);
    let mean = KEYS as f64 / BUCKETS as f64;
    let chi_square: f64 = counts
        .iter()
        .map(|&c| {
            let deviation = f64::from(c) - mean;
            deviation * deviation / mean
        })
        .sum();
    let df = (BUCKETS - 1) as f64;
    let sigma = (chi_square - df) / (2.0 * df).sqrt();
    println!(
        "{label}: mean {mean:.1}, min {min}, max {max}, empty {empty}, \
         chi2 {chi_square:.0} on {df:.0} df ({sigma:+.2} sigma)"
    );
    assert_eq!(empty, 0, "{label}: {empty} shards received no keys at all");
    assert!(
        f64::from(max) / mean < MAX_OVER_MEAN,
        "{label}: busiest shard holds {max}, {:.2} times the mean of {mean:.1}",
        f64::from(max) / mean
    );
    assert!(
        f64::from(min) / mean > MIN_OVER_MEAN,
        "{label}: quietest shard holds {min}, {:.2} times the mean of {mean:.1}",
        f64::from(min) / mean
    );
    assert!(
        sigma.abs() < MAX_SIGMA,
        "{label}: chi-square {chi_square:.0} on {df:.0} df is {sigma:+.2} sigma \
         from uniform, past the {MAX_SIGMA} sigma bound"
    );
}

fn shard(key: ShardKey<'_>) -> u16 {
    LogicalShard::of(key, HashVersion::V1).get()
}


#[test]
#[ignore = "10^7 keys; run explicitly"]
fn integers_from_zero() {
    measure("int sequential", |i| shard(ShardKey::Int(i as i64)));
}

#[test]
#[ignore = "10^7 keys; run explicitly"]
fn integers_from_a_large_base() {
    measure("int offset", |i| {
        shard(ShardKey::Int(1_000_000_000_000_i64.saturating_add(i as i64)))
    });
}

#[test]
#[ignore = "10^7 keys; run explicitly"]
fn uuids_with_a_counter() {
    measure("uuid low entropy", |i| {
        let mut raw = [0u8; 16];
        let (head, _) = raw.split_at_mut(8);
        head.copy_from_slice(&i.to_le_bytes());
        shard(ShardKey::Uuid(raw))
    });
}

#[test]
#[ignore = "10^7 keys; run explicitly"]
fn decimal_strings() {
    measure("text decimal", |i| shard(ShardKey::Text(&i.to_string())));
}