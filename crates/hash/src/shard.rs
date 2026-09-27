use crate::key::ShardKey;

pub const LOGICAL_SHARDS: u32 = 65536;
const _: () = assert!(LOGICAL_SHARDS == u16::MAX as u32 + 1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashVersion { V1 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogicalShard(u16);

impl LogicalShard {
    pub const fn get(&self) -> u16 {
        self.0
    }

    pub fn of(key: ShardKey<'_>, version: HashVersion) -> Self {
        Self((key.hash(version) & 0xFFFF) as u16)
    }

    pub const fn from_index(index: u16) -> Self {
        Self(index)
    }
}