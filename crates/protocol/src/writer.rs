use crate::error::{ProtocolError, Result, MAX_MESSAGE_BODY};

const LENGTH_BYTES: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct Writer {
    buffer: Vec<u8>,
    message_start: Option<usize>,
}

impl Writer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            message_start: None,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    #[must_use]
    pub fn is_message_open(&self) -> bool {
        self.message_start.is_some()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.message_start = None;
    }

    pub fn release(&mut self) {
        self.buffer = Vec::new();
        self.message_start = None;
    }

    pub fn take(&mut self) -> Result<Vec<u8>> {
        if self.message_start.is_some() {
            return Err(ProtocolError::MessageAlreadyOpen);
        }
        Ok(core::mem::take(&mut self.buffer))
    }

    pub fn begin(&mut self, tag: u8) -> Result<()> {
        if self.message_start.is_some() {
            return Err(ProtocolError::MessageAlreadyOpen);
        }
        self.buffer.push(tag);
        self.open_length_slot();
        Ok(())
    }

    pub fn begin_untagged(&mut self) -> Result<()> {
        if self.message_start.is_some() {
            return Err(ProtocolError::MessageAlreadyOpen);
        }
        self.open_length_slot();
        Ok(())
    }

    fn open_length_slot(&mut self) {
        self.message_start = Some(self.buffer.len());
        self.buffer.extend_from_slice(&[0; LENGTH_BYTES]);
    }

    pub fn end(&mut self) -> Result<()> {
        let start = match self.message_start.take() {
            Some(start) => start,
            None => return Err(ProtocolError::NoMessageOpen),
        };

        let body = match self.buffer.len().checked_sub(start) {
            Some(body) => body,
            None => return Err(ProtocolError::NoMessageOpen),
        };

        if body > MAX_MESSAGE_BODY {
            return Err(ProtocolError::OversizedMessage {
                body,
                limit: MAX_MESSAGE_BODY,
            });
        }

        let length = match i32::try_from(body) {
            Ok(length) => length,
            Err(_) => {
                return Err(ProtocolError::OversizedMessage {
                    body,
                    limit: MAX_MESSAGE_BODY,
                })
            }
        };

        let slot_end = match start.checked_add(LENGTH_BYTES) {
            Some(slot_end) => slot_end,
            None => return Err(ProtocolError::NoMessageOpen),
        };

        match self.buffer.get_mut(start..slot_end) {
            Some(slot) => {
                slot.copy_from_slice(&length.to_be_bytes());
                Ok(())
            }
            None => Err(ProtocolError::NoMessageOpen),
        }
    }

    pub fn u8(&mut self, value: u8) {
        self.buffer.push(value);
    }

    pub fn i16(&mut self, value: i16) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    pub fn i32(&mut self, value: i32) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.buffer.extend_from_slice(value);
    }

    pub fn cstring(&mut self, value: &[u8]) {
        self.buffer.extend_from_slice(value);
        self.buffer.push(0);
    }
}
