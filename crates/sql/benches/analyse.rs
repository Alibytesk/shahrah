use divan::{black_box, Bencher};
use shahrah_sql::analysis::{analyse, KeyType, Policy};
use shahrah_sql::cache::Cache;

fn main() {
    divan::main();
}

const SHORT: &str = "select name from users where id = $1";
const LONG: &str = "select u.id, u.name, u.region from users u where u.id = $1 and u.region = $2 order by u.name limit 50";

fn policy() -> Policy {
    Policy::new().with_key("users", "id", KeyType::Int)
}

#[divan::bench]
fn parse_uncached_short(bencher: Bencher) {
    let policy = policy();
    bencher.bench(|| analyse(black_box(SHORT), &policy).is_ok());
}

#[divan::bench]
fn parse_uncached_long(bencher: Bencher) {
    let policy = policy();
    bencher.bench(|| analyse(black_box(LONG), &policy).is_ok());
}

#[divan::bench]
fn cache_hit_short(bencher: Bencher) {
    let policy = policy();
    let cache = Cache::new(1024);
    let _warm = cache.analyse(SHORT, &policy);
    bencher.bench(|| cache.analyse(black_box(SHORT), &policy).is_ok());
}

#[divan::bench]
fn a_shape_the_cache_will_not_hold(bencher: Bencher) {
    let policy = policy();
    let cache = Cache::new(1024);
    let _warm = cache.analyse(LONG, &policy);
    bencher.bench(|| cache.analyse(black_box(LONG), &policy).is_ok());
}

#[divan::bench]
fn a_paginated_read_with_a_fresh_key_each_time(bencher: Bencher) {
    let policy = policy();
    let cache = Cache::new(1024);
    let statements: Vec<String> = (0..64)
        .map(|key| format!("select name from users where id = {key} order by name limit 20"))
        .collect();
    for one in &statements {
        let _warm = cache.analyse(one, &policy);
    }
    let mut at = 0usize;
    bencher.bench_local(|| {
        at = at.wrapping_add(1).checked_rem(statements.len()).unwrap_or(0);
        let one = statements.get(at).map_or("select 1", String::as_str);
        cache.analyse(black_box(one), &policy).is_ok()
    });
}

#[divan::bench]
fn a_key_beside_another_literal(bencher: Bencher) {
    let policy = policy();
    let cache = Cache::new(1024);
    let statements: Vec<String> = (0..64)
        .map(|key| format!("select name from users where id = {key} and name = 'ali'"))
        .collect();
    for one in &statements {
        let _warm = cache.analyse(one, &policy);
    }
    let mut at = 0usize;
    bencher.bench_local(|| {
        at = at.wrapping_add(1).checked_rem(statements.len()).unwrap_or(0);
        let one = statements.get(at).map_or("select 1", String::as_str);
        cache.analyse(black_box(one), &policy).is_ok()
    });
}
