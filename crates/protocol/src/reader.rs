use crate::error::{ProtocolError, Result};

#[derive(Debug, Clone)]
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        self.0
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        match self.0.split_at_checked(count) {
            Some((head, tail)) => {
                self.0 = tail;
                Ok(head)
            }
            None => Err(ProtocolError::UnexpectedEnd {
                needed: count,
                remaining: self.0.len(),
            }),
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        let taken = self.bytes(1)?;
        match taken {
            [value] => Ok(*value),
            _ => Err(ProtocolError::UnexpectedEnd {
                needed: 1,
                remaining: taken.len(),
            }),
        }
    }

    pub fn i16(&mut self) -> Result<i16> {
        let taken = self.bytes(2)?;
        match <[u8; 2]>::try_from(taken) {
            Ok(array) => Ok(i16::from_be_bytes(array)),
            Err(_) => Err(ProtocolError::UnexpectedEnd {
                needed: 2,
                remaining: taken.len(),
            }),
        }
    }

    pub fn i32(&mut self) -> Result<i32> {
        let taken = self.bytes(4)?;
        match <[u8; 4]>::try_from(taken) {
            Ok(array) => Ok(i32::from_be_bytes(array)),
            Err(_) => Err(ProtocolError::UnexpectedEnd {
                needed: 4,
                remaining: taken.len(),
            }),
        }
    }

    pub fn cstring(&mut self) -> Result<&'a [u8]> {
        match self.0.iter().position(|byte| *byte == 0) {
            Some(index) => {
                let text = self.bytes(index)?;
                self.u8()?;
                Ok(text)
            }
            None => Err(ProtocolError::UnterminatedString),
        }
    }

    pub fn expect_end(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes {
                trailing: self.0.len(),
            })
        }
    }
}
