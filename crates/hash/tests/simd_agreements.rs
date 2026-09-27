use xxhash_rust::{const_xxh3, xxh3};

const MAX_LEN: usize = 2560;
const _: () = assert!(const_xxh3::xxh3_64(b"ali".as_slice()) == 0x23d1_6eaf_26be_9045);

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
        .collect()
}

#[test]
fn simd_matches_scalar_at_every_length() {
    let buffer = pattern(MAX_LEN);
    let mut disagreements = Vec::new();
    for len in 0..=MAX_LEN {
        let input = match buffer.get(..len) {
            Some(slice) => slice,
            None => panic!("buffer is shorter than {len}"),
        };
        let simd = xxh3::xxh3_64(input);
        let scalar = const_xxh3::xxh3_64(input);
        if simd != scalar {
            disagreements.push(format!("len {len}: xxh3 {simd:016x}, const_xxh3 {scalar:016x}"));
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} of {} lengths disagree between the SIMD and scalar XXH3 in this \
         build -- shards computed by this binary do not match shards computed \
         by one built for a different target:\n{}",
        disagreements.len(),
        MAX_LEN.saturating_add(1),
        disagreements.join("\n")
    );
}