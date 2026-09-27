use core::num::NonZeroU16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysicalShard(NonZeroU16);

impl PhysicalShard {
    #[must_use]
    pub const fn new(id: NonZeroU16) -> Self {
        Self(id)
    }

    #[must_use]
    pub const fn from_number(number: u16) -> Option<Self> {
        match NonZeroU16::new(number) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    #[must_use]
    pub const fn number(self) -> u16 {
        self.0.get()
    }
}