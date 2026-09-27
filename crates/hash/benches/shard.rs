use divan::{black_box, Bencher};
use shahrah_hash::key::ShardKey;
use shahrah_hash::shard::{HashVersion, LogicalShard};

fn main() {
    divan::main();
}

const TEXT_LENS: &[usize] = &[3, 8, 16, 17, 32, 64, 128, 129, 240, 241, 1024];

#[divan::bench]
fn integer() -> u16 {
    LogicalShard::of(
        ShardKey::Int(black_box(9_007_199_254_740_993)),
        black_box(HashVersion::V1),
    )
        .get()
}

#[divan::bench]
fn uuid() -> u16 {
    let raw: [u8; 16] = [
        0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00,
        0x00,
    ];
    LogicalShard::of(ShardKey::Uuid(black_box(raw)), black_box(HashVersion::V1)).get()
}

#[divan::bench(args = TEXT_LENS)]
fn text(bencher: Bencher, len: usize) {
    let buffer = "a".repeat(len);
    bencher.bench(|| {
        LogicalShard::of(
            ShardKey::Text(black_box(buffer.as_str())),
            black_box(HashVersion::V1),
        )
            .get()
    });
}