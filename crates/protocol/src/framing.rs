use crate::error::{ProtocolError, Result, MAX_MESSAGE_BODY};
use crate::reader::Reader;

const LENGTH_BYTES: usize = 4;
const TAG_BYTES: usize = 1;
const MIN_DECLARED_LENGTH: i32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub tag: Option<u8>,
    pub body: &'a [u8],
    pub consumed: usize,
}

impl<'a> Frame<'a> {
    #[must_use]
    pub const fn reader(&self) -> Reader<'a> {
        Reader::new(self.body)
    }
}

pub fn tagged(buffer: &[u8]) -> Result<Option<Frame<'_>>> {
    let (tag, rest) = match buffer.split_at_checked(TAG_BYTES) {
        Some(([tag], rest)) => (*tag, rest),
        _ => return Ok(None),
    };

    let body_length = match declared_body_length(rest)? {
        Some(body_length) => body_length,
        None => return Ok(None),
    };

    let after_length = match rest.split_at_checked(LENGTH_BYTES) {
        Some((_, after_length)) => after_length,
        None => return Ok(None),
    };

    let body = match after_length.split_at_checked(body_length) {
        Some((body, _)) => body,
        None => return Ok(None),
    };

    let consumed = match TAG_BYTES
        .checked_add(LENGTH_BYTES)
        .and_then(|prefix| prefix.checked_add(body_length))
    {
        Some(consumed) => consumed,
        None => {
            return Err(ProtocolError::OversizedMessage {
                body: body_length,
                limit: MAX_MESSAGE_BODY,
            })
        }
    };

    Ok(Some(Frame {
        tag: Some(tag),
        body,
        consumed,
    }))
}

pub fn untagged(buffer: &[u8]) -> Result<Option<Frame<'_>>> {
    let body_length = match declared_body_length(buffer)? {
        Some(body_length) => body_length,
        None => return Ok(None),
    };

    let after_length = match buffer.split_at_checked(LENGTH_BYTES) {
        Some((_, after_length)) => after_length,
        None => return Ok(None),
    };

    let body = match after_length.split_at_checked(body_length) {
        Some((body, _)) => body,
        None => return Ok(None),
    };

    let consumed = match LENGTH_BYTES.checked_add(body_length) {
        Some(consumed) => consumed,
        None => {
            return Err(ProtocolError::OversizedMessage {
                body: body_length,
                limit: MAX_MESSAGE_BODY,
            })
        }
    };

    Ok(Some(Frame {
        tag: None,
        body,
        consumed,
    }))
}

fn declared_body_length(buffer: &[u8]) -> Result<Option<usize>> {
    let raw = match buffer.split_at_checked(LENGTH_BYTES) {
        Some((head, _)) => match <[u8; LENGTH_BYTES]>::try_from(head) {
            Ok(array) => i32::from_be_bytes(array),
            Err(_) => return Ok(None),
        },
        None => return Ok(None),
    };

    if raw < 0 {
        return Err(ProtocolError::NegativeLength { length: raw });
    }
    if raw < MIN_DECLARED_LENGTH {
        return Err(ProtocolError::LengthTooSmall { length: raw });
    }

    let declared = match usize::try_from(raw) {
        Ok(declared) => declared,
        Err(_) => return Err(ProtocolError::NegativeLength { length: raw }),
    };

    let body = match declared.checked_sub(LENGTH_BYTES) {
        Some(body) => body,
        None => return Err(ProtocolError::LengthTooSmall { length: raw }),
    };

    if body > MAX_MESSAGE_BODY {
        return Err(ProtocolError::OversizedMessage {
            body,
            limit: MAX_MESSAGE_BODY,
        });
    }

    Ok(Some(body))
}
