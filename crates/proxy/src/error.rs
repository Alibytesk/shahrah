use shahrah_protocol::error::ProtocolError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("client closed the connection during the handshake")]
    ClientClosed,

    #[error("startup packet exceeded {limit} bytes")]
    StartupTooLarge { limit: usize },

    #[error("client sent a second SSL request")]
    RepeatedSslRequest,

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("client sent {bytes} plaintext bytes after its SSL request")]
    PlaintextAfterSslRequest { bytes: usize },

    #[error("backend refused: {code} {message}")]
    BackendRefused { code: String, message: String },

    #[error("backend asked for authentication method {code}, which shahrah does not implement")]
    UnsupportedAuthentication { code: i32 },

    #[error(transparent)]
    Scram(#[from] shahrah_protocol::scram::ScramError),

    #[error("client sent message {tag:?} during authentication")]
    UnexpectedClientMessage { tag: u8 },

    #[error("client asked for SASL mechanism {name}, which shahrah does not offer")]
    UnsupportedMechanism { name: String },

    #[error("shahrah cannot merge this broadcast result: {why}")]
    Unmergeable { why: &'static str },

    #[error("the pool is closed")]
    PoolClosed,

    #[error(
        "waited {seconds:.1}s for a connection to {address} and every one of the {limit} in that \
         pool is still in use"
    )]
    PoolBusy {
        address: String,
        seconds: f64,
        limit: usize,
    },

    #[error("tls: {0}")]
    Tls(String),

    #[error("the raft node could not start: {0}")]
    Cluster(String),

    #[error("{0}")]
    Setting(String),

    #[error("{0}")]
    Relocate(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
