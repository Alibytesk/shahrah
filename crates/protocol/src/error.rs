use thiserror::Error;

pub const MAX_MESSAGE_BODY: usize = 1 << 30;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("needed {needed} bytes, {remaining} remain in the message")]
    UnexpectedEnd { needed: usize, remaining: usize },

    #[error("string is not terminated")]
    UnterminatedString,

    #[error("{trailing} bytes remain unparsed at the end of the message")]
    TrailingBytes { trailing: usize },

    #[error("declared message length {length} is below the minimum of 4")]
    LengthTooSmall { length: i32 },

    #[error("declared message length {length} is negative")]
    NegativeLength { length: i32 },

    #[error("message body of {body} bytes exceeds the limit of {limit}")]
    OversizedMessage { body: usize, limit: usize },

    #[error("a message is already open")]
    MessageAlreadyOpen,

    #[error("no message is open")]
    NoMessageOpen,
}

pub type Result<T> = core::result::Result<T, ProtocolError>;
