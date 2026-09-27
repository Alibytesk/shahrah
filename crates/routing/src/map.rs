use crate::shard::PhysicalShard;
use core::fmt;
use core::num::NonZeroU16;
use shahrah_hash::shard::{LOGICAL_SHARDS, LogicalShard};
use thiserror::Error;

const SLOTS: usize = LOGICAL_SHARDS as usize;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShardMapError {
    #[error(
        "logical shard {logical} was assigned physical shard {physical}, \
         but only {declared} physical shards are declared"
    )]
    OutOfRange {
        logical: u16,
        physical: u16,
        declared: u16,
    },
    #[error("{count} logical shards have no physical shard; the first is {first}")]
    Unassigned { count: u32, first: u16 },
    #[error("internal invariant: the map has {got} slots, expected {expected}")]
    Internal { got: usize, expected: usize },
}

pub struct ShardMap(Box<[PhysicalShard; SLOTS]>);

impl ShardMap {
    #[must_use]
    #[inline]
    #[allow(clippy::indexing_slicing)]
    pub fn get(&self, logical: LogicalShard) -> PhysicalShard {
        self.0[usize::from(logical.get())]
    }
}

impl fmt::Debug for ShardMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShardMap")
            .field("slots", &SLOTS)
            .finish_non_exhaustive()
    }
}

pub struct ShardMapBuilder {
    slots: Box<[Option<PhysicalShard>]>,
    declared: NonZeroU16,
}

impl ShardMapBuilder {
    #[must_use]
    pub fn new(declared: NonZeroU16) -> Self {
        Self {
            slots: vec![None; SLOTS].into_boxed_slice(),
            declared,
        }
    }

    pub fn assign(
        &mut self,
        logical: LogicalShard,
        physical: PhysicalShard,
    ) -> Result<(), ShardMapError> {
        if physical.number() > self.declared.get() {
            return Err(ShardMapError::OutOfRange {
                logical: logical.get(),
                physical: physical.number(),
                declared: self.declared.get(),
            });
        }
        match self.slots.get_mut(usize::from(logical.get())) {
            Some(slot) => {
                *slot = Some(physical);
                Ok(())
            }
            None => Err(ShardMapError::Internal {
                got: self.slots.len(),
                expected: SLOTS,
            }),
        }
    }

    pub fn build(self) -> Result<ShardMap, ShardMapError> {
        let mut filled: Vec<PhysicalShard> = Vec::with_capacity(SLOTS);
        let mut missing: u32 = 0;
        let mut first_missing: Option<u16> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                Some(physical) => filled.push(*physical),
                None => {
                    missing = missing.saturating_add(1);
                    if first_missing.is_none() {
                        first_missing = u16::try_from(index).ok();
                    }
                }
            }
        }
        if let Some(first) = first_missing {
            return Err(ShardMapError::Unassigned {
                count: missing,
                first,
            });
        }
        let boxed = filled.into_boxed_slice();
        let got = boxed.len();
        match <Box<[PhysicalShard; SLOTS]>>::try_from(boxed) {
            Ok(array) => Ok(ShardMap(array)),
            Err(_) => Err(ShardMapError::Internal {
                got,
                expected: SLOTS,
            }),
        }
    }
}

impl fmt::Debug for ShardMapBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let assigned = self.slots.iter().filter(|slot| slot.is_some()).count();
        formatter
            .debug_struct("ShardMapBuilder")
            .field("declared", &self.declared)
            .field("assigned", &assigned)
            .field("slots", &SLOTS)
            .finish_non_exhaustive()
    }
}
