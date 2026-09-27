use shahrah_hash::key::ShardKey;
use shahrah_hash::shard::{HashVersion, LogicalShard};

const VECTORS: &str = include_str!("../../../docs/vectors.tsv");
const EXPECTED_ROWS: usize = 60;

fn decode_hex(hex: &str, line_no: usize) -> Vec<u8> {
    let chunks = hex.as_bytes().chunks_exact(2);
    if !chunks.remainder().is_empty() {
        panic!("line {line_no}: odd-length hex field {hex:?}");
    }
    chunks
        .map(|pair| match core::str::from_utf8(pair) {
            Ok(digits) => match u8::from_str_radix(digits, 16) {
                Ok(byte) => byte,
                Err(_) => panic!("line {line_no}: {digits:?} is not a hex byte"),
            },
            Err(_) => panic!("line {line_no}: hex field {hex:?} is not utf-8"),
        })
        .collect()
}

#[test]
fn frozen_vectors() {
    let mut checked = 0usize;
    let mut failures = Vec::new();
    for (index, line) in VECTORS.lines().enumerate() {
        let line_no = index.saturating_add(1);
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t');
        let columns = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        );
        let (version, ty, value, canonical, hash, shard) = match columns {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), None) => (a, b, c, d, e, f),
            _ => panic!("line {line_no}: expected exactly six tab-separated columns"),
        };
        let version = match version {
            "1" => HashVersion::V1,
            other => panic!("line {line_no}: unknown hash version {other:?}"),
        };
        let decoded = match ty {
            "text" | "bytea" => decode_hex(value, line_no),
            "uuid" => decode_hex(&value.replace('-', ""), line_no),
            _ => Vec::new(),
        };
        let key = match ty {
            "int2" | "int4" | "int8" | "oid" => match value.parse::<i64>() {
                Ok(n) => ShardKey::Int(n),
                Err(_) => panic!("line {line_no}: {value:?} does not parse as i64"),
            },
            "uuid" => match <[u8; 16]>::try_from(decoded.as_slice()) {
                Ok(raw) => ShardKey::Uuid(raw),
                Err(_) => panic!("line {line_no}: uuid {value:?} is not 16 bytes"),
            },
            "text" => match core::str::from_utf8(&decoded) {
                Ok(text) => ShardKey::Text(text),
                Err(_) => panic!("line {line_no}: text vector {value:?} is not utf-8"),
            },
            "bytea" => ShardKey::Bytes(&decoded),
            other => panic!("line {line_no}: unknown key type {other:?}"),
        };
        let want = match shard.parse::<u16>() {
            Ok(n) => n,
            Err(_) => panic!("line {line_no}: shard {shard:?} does not parse as u16"),
        };
        let got = LogicalShard::of(key, version).get();
        if got != want {
            failures.push(format!(
                "line {line_no}  {ty} {value}: expected {want}, got {got} \
                 (canonical {canonical}, hash {hash})"
            ));
        }
        checked = checked.saturating_add(1);
    }
    assert_eq!(
        checked, EXPECTED_ROWS,
        "read {checked} vectors, expected {EXPECTED_ROWS} -- the file is frozen, \
         so a different count means it was truncated or the parser is skipping rows"
    );
    assert!(
        failures.is_empty(),
        "{} of {checked} vectors moved:\n{}",
        failures.len(),
        failures.join("\n")
    );
}