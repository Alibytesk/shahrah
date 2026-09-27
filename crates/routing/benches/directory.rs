use divan::{black_box, Bencher};
use shahrah_routing::directory::Directory;

fn main() {
    divan::main();
}

fn seeded(entries: usize) -> (std::sync::Arc<Directory>, Vec<Vec<u8>>) {
    let directory = Directory::from_env();
    let mut keys = Vec::with_capacity(entries);
    for index in 0..entries {
        let key = (index as i64).to_le_bytes().to_vec();
        let home = match index % 3 {
            0 => "na-east",
            1 => "eu-central",
            _ => "asia-west",
        };
        directory.remember(&key, Some(home));
        keys.push(key);
    }
    (directory, keys)
}

#[divan::bench]
fn hit_in_a_small_cache(bencher: Bencher) {
    let (directory, keys) = seeded(1_000);
    let mut turn = 0usize;
    bencher.bench_local(|| {
        turn = turn.wrapping_add(1);
        let key = keys
            .get(turn.checked_rem(keys.len()).unwrap_or(0))
            .map_or(&[][..], Vec::as_slice);
        black_box(directory.cached(black_box(key))).is_some()
    });
}

#[divan::bench]
fn hit_in_a_million_entry_cache(bencher: Bencher) {
    let (directory, keys) = seeded(1_000_000);
    let mut turn = 0usize;
    bencher.bench_local(|| {
        turn = turn.wrapping_add(1);
        let key = keys
            .get(turn.checked_rem(keys.len()).unwrap_or(0))
            .map_or(&[][..], Vec::as_slice);
        black_box(directory.cached(black_box(key))).is_some()
    });
}

#[divan::bench]
fn a_key_the_cache_has_never_seen(bencher: Bencher) {
    let (directory, _keys) = seeded(1_000_000);
    let absent = (-1i64).to_le_bytes().to_vec();
    bencher.bench_local(|| black_box(directory.cached(black_box(&absent))).is_none());
}

#[divan::bench]
fn a_key_known_to_have_no_home(bencher: Bencher) {
    let (directory, _keys) = seeded(1_000);
    let unplaced = (-42i64).to_le_bytes().to_vec();
    directory.remember(&unplaced, None);
    bencher.bench_local(|| black_box(directory.cached(black_box(&unplaced))).is_some());
}
