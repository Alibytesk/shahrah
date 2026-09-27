use crate::shard::HashVersion;
use xxhash_rust::xxh3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardKey<'a> {
    Int(i64),
    Uuid([u8; 16]),
    Bytes(&'a [u8]),
    Text(&'a str),
}

impl ShardKey<'_> {
    pub(crate) fn hash(&self, version: HashVersion) -> u64 {
        match version {
            HashVersion::V1 => match *self {
                ShardKey::Int(n) => xxh3::xxh3_64(&n.to_le_bytes()),
                ShardKey::Uuid(u) => xxh3::xxh3_64(&u),
                ShardKey::Bytes(b) => xxh3::xxh3_64(b),
                ShardKey::Text(t) => xxh3::xxh3_64(t.as_bytes())
            }
        }
    }
}