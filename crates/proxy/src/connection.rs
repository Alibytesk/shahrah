use base64::Engine;
use rand::RngCore;
use shahrah_protocol::error::ProtocolError;
use shahrah_protocol::framing::tagged;
use shahrah_protocol::messages::{
    authentication_code, data_row_fields, parse_error_fields, query, sasl_initial_response,
    sasl_payload, sasl_response, AUTH_OK, AUTH_SASL, AUTH_SASL_CONTINUE, AUTH_SASL_FINAL,
    TAG_AUTHENTICATION, TAG_BACKEND_KEY_DATA, TAG_DATA_ROW, TAG_ERROR_RESPONSE,
    TAG_COMMAND_COMPLETE, TAG_PARAMETER_STATUS, TAG_READY_FOR_QUERY, TAG_ROW_DESCRIPTION,
};
use shahrah_protocol::reader::Reader;
use shahrah_protocol::scram::{self, ClientExchange};
use shahrah_protocol::startup::{PROTOCOL_VERSION_3, SSL_REQUEST_CODE};
use shahrah_protocol::writer::Writer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::error::SessionError;
use crate::tls::{server_name, BackendTls};
use crate::transport::Transport;

const READ_CHUNK: usize = 8192;
const FIRST_CHUNK: usize = 1024;
const IDLE_BUFFER_CEILING: usize = 512;
const OUTGOING_CEILING: usize = 64 * 1024;
const SSL_ACCEPTED: u8 = b'S';

pub struct Connection {
    transport: Transport,
    buffer: Vec<u8>,
    outgoing: Vec<u8>,
    start: usize,
    key: Option<(i32, i32)>,
    parameters: Vec<(String, String)>,
    prepared: std::collections::HashSet<String>,
    role: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSpan {
    pub tag: u8,
    pub body_start: usize,
    pub total: usize,
}

pub const BACKEND_TIMEZONE_ENV: &str = "SHAHRAH_BACKEND_TIMEZONE";
pub const STATEMENT_TIMEOUT_ENV: &str = "SHAHRAH_STATEMENT_TIMEOUT";
pub const IDLE_TRANSACTION_TIMEOUT_ENV: &str = "SHAHRAH_IDLE_TRANSACTION_TIMEOUT";
pub const DEFAULT_IDLE_TRANSACTION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(60);

static BACKEND_SETTINGS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn backend_settings() -> Result<&'static str, String> {
    if let Some(built) = BACKEND_SETTINGS.get() {
        return Ok(built.as_str());
    }
    let timezone = std::env::var(BACKEND_TIMEZONE_ENV).unwrap_or_else(|_| "UTC".to_owned());
    if timezone.contains('\'') {
        return Err(format!("{BACKEND_TIMEZONE_ENV} may not contain a quote"));
    }
    let statement = crate::settings::millis(STATEMENT_TIMEOUT_ENV, None)?;
    let idle = crate::settings::millis(
        IDLE_TRANSACTION_TIMEOUT_ENV,
        Some(DEFAULT_IDLE_TRANSACTION_TIMEOUT),
    )?;
    let built = format!(
        "SET DateStyle = 'ISO, MDY'; SET IntervalStyle = 'postgres'; \
         SET bytea_output = 'hex'; SET extra_float_digits = 1; SET TimeZone = '{timezone}'; \
         SET statement_timeout = {}; SET idle_in_transaction_session_timeout = {}",
        as_millis(statement),
        as_millis(idle)
    );
    let _placed = BACKEND_SETTINGS.set(built);
    BACKEND_SETTINGS
        .get()
        .map(String::as_str)
        .ok_or_else(|| "the backend settings could not be held".to_owned())
}

fn as_millis(bound: Option<std::time::Duration>) -> u64 {
    bound.map_or(0, |held| u64::try_from(held.as_millis()).unwrap_or(u64::MAX))
}

impl Connection {
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            buffer: Vec::new(),
            outgoing: Vec::new(),
            start: 0,
            key: None,
            parameters: Vec::new(),
            prepared: std::collections::HashSet::new(),
            role: None,
        }
    }

    pub async fn connect(
        address: &str,
        tls: BackendTls,
        connector: &TlsConnector,
    ) -> Result<Self, SessionError> {
        let mut stream = TcpStream::connect(address).await?;
        stream.set_nodelay(true)?;

        if tls == BackendTls::Disable {
            return Ok(Self::new(Transport::Plain(stream)));
        }

        let mut request = Writer::with_capacity(8);
        request.begin_untagged()?;
        request.i32(SSL_REQUEST_CODE);
        request.end()?;
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut answer = [0u8; 1];
        stream.read_exact(&mut answer).await?;
        match answer {
            [SSL_ACCEPTED] => {
                let name = server_name(address)?;
                let upgraded = connector.connect(name, stream).await?;
                debug!(address, "backend connection upgraded to TLS");
                Ok(Self::new(Transport::ClientTls(Box::new(upgraded))))
            }
            _ => {
                warn!(address, "backend refused TLS while it was required");
                Err(SessionError::Tls(
                    "backend refused an SSL request".to_owned(),
                ))
            }
        }
    }

    fn pending(&self) -> &[u8] {
        self.buffer.get(self.start..).unwrap_or(&[])
    }

    pub fn try_frame(&self) -> Result<Option<FrameSpan>, SessionError> {
        let Some(frame) = tagged(self.pending())? else {
            return Ok(None);
        };
        let body_start = frame.consumed.saturating_sub(frame.body.len());
        let Some(tag) = frame.tag else {
            return Ok(None);
        };
        Ok(Some(FrameSpan {
            tag,
            body_start,
            total: frame.consumed,
        }))
    }

    pub async fn next_frame(&mut self) -> Result<FrameSpan, SessionError> {
        loop {
            if let Some(frame) = tagged(self.pending())? {
                let body_start = match frame.consumed.checked_sub(frame.body.len()) {
                    Some(body_start) => body_start,
                    None => {
                        return Err(SessionError::Protocol(ProtocolError::UnexpectedEnd {
                            needed: frame.body.len(),
                            remaining: frame.consumed,
                        }))
                    }
                };
                let tag = match frame.tag {
                    Some(tag) => tag,
                    None => {
                        return Err(SessionError::Protocol(ProtocolError::UnexpectedEnd {
                            needed: 1,
                            remaining: 0,
                        }))
                    }
                };
                return Ok(FrameSpan {
                    tag,
                    body_start,
                    total: frame.consumed,
                });
            }
            self.push().await?;
            self.transport.flush().await?;
            self.fill().await?;
        }
    }

    pub fn raw(&self, frame: FrameSpan) -> Result<&[u8], SessionError> {
        match self.pending().get(..frame.total) {
            Some(bytes) => Ok(bytes),
            None => Err(SessionError::Protocol(ProtocolError::UnexpectedEnd {
                needed: frame.total,
                remaining: self.buffer.len(),
            })),
        }
    }

    pub fn body(&self, frame: FrameSpan) -> Result<&[u8], SessionError> {
        match self.pending().get(frame.body_start..frame.total) {
            Some(bytes) => Ok(bytes),
            None => Err(SessionError::Protocol(ProtocolError::UnexpectedEnd {
                needed: frame.total,
                remaining: self.buffer.len(),
            })),
        }
    }

    pub fn consume(&mut self, frame: FrameSpan) {
        self.advance(frame.total);
    }

    pub fn advance(&mut self, bytes: usize) {
        self.start = self.start.saturating_add(bytes).min(self.buffer.len());
        if self.start == self.buffer.len() {
            self.buffer.clear();
            self.start = 0;
        }
    }



    pub async fn wait_readable(&mut self) -> Result<(), SessionError> {
        self.push().await?;
        self.transport.flush().await?;
        self.fill().await
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        self.outgoing.extend_from_slice(bytes);
        if self.outgoing.len() >= OUTGOING_CEILING {
            self.push().await?;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), SessionError> {
        self.push().await?;
        self.transport.flush().await?;
        Ok(())
    }

    async fn push(&mut self) -> Result<(), SessionError> {
        if self.outgoing.is_empty() {
            return Ok(());
        }
        let sent = self.transport.write_all(&self.outgoing).await;
        self.outgoing.clear();
        if self.outgoing.capacity() > OUTGOING_CEILING {
            self.outgoing = Vec::new();
        }
        sent?;
        Ok(())
    }

    pub fn adopt(&mut self, leftover: Vec<u8>) {
        if self.buffer.is_empty() {
            self.buffer = leftover;
            self.start = 0;
        } else {
            self.buffer.extend_from_slice(&leftover);
        }
    }

    pub fn release_buffer(&mut self) {
        if self.start >= self.buffer.len() {
            self.buffer.clear();
            self.start = 0;
        }
        if self.buffer.is_empty() && self.buffer.capacity() > IDLE_BUFFER_CEILING {
            self.buffer = Vec::new();
        }
    }

    async fn fill(&mut self) -> Result<(), SessionError> {
        if self.start > 0 && self.start >= self.buffer.len() / 2 {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        let want = if self.buffer.capacity() < FIRST_CHUNK {
            FIRST_CHUNK
        } else {
            READ_CHUNK
        };
        let spare = self.buffer.capacity().saturating_sub(self.buffer.len());
        if spare < want {
            self.buffer.reserve(want.saturating_sub(spare));
        }
        let read = self.transport.read_buf(&mut self.buffer).await?;
        if read == 0 {
            return Err(SessionError::ClientClosed);
        }
        Ok(())
    }
}

impl Connection {
    pub async fn open_backend(
        address: &str,
        tls: BackendTls,
        connector: &TlsConnector,
        user: &str,
        password: &str,
        database: &str,
        role: Option<&str>,
    ) -> Result<Self, SessionError> {
        let mut backend = Self::connect(address, tls, connector).await?;

        let mut writer = Writer::with_capacity(256);
        writer.begin_untagged()?;
        writer.i32(PROTOCOL_VERSION_3);
        writer.cstring(b"user");
        writer.cstring(user.as_bytes());
        writer.cstring(b"database");
        writer.cstring(database.as_bytes());
        writer.cstring(b"application_name");
        writer.cstring(b"shahrah");
        writer.cstring(b"client_encoding");
        writer.cstring(b"UTF8");
        writer.u8(0);
        writer.end()?;
        backend.write_all(writer.as_bytes()).await?;
        backend.flush().await?;

        backend.run_client_authentication(user, password).await?;
        backend.await_ready().await?;
        backend.role = role.map(str::to_owned);
        backend.pin_rendering().await?;
        backend.assume_role().await?;
        Ok(backend)
    }

    async fn run_client_authentication(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<(), SessionError> {
        let mut exchange: Option<ClientExchange> = None;
        let mut writer = Writer::with_capacity(256);

        loop {
            let frame = self.next_frame().await?;
            let tag = frame.tag;
            let body = self.body(frame)?.to_vec();
            self.consume(frame);

            match tag {
                TAG_ERROR_RESPONSE => {
                    let fields = parse_error_fields(&body)?;
                    return Err(SessionError::BackendRefused {
                        code: String::from_utf8_lossy(fields.code.unwrap_or(b"")).into_owned(),
                        message: String::from_utf8_lossy(fields.message.unwrap_or(b"")).into_owned(),
                    });
                }
                TAG_AUTHENTICATION => match authentication_code(&body)? {
                    AUTH_OK => return Ok(()),
                    AUTH_SASL => {
                        let nonce = random_nonce();
                        let (started, first) = ClientExchange::start(user, password, &nonce);
                        exchange = Some(started);
                        writer.clear();
                        sasl_initial_response(&mut writer, scram::MECHANISM, &first)?;
                        self.write_all(writer.as_bytes()).await?;
                        self.flush().await?;
                    }
                    AUTH_SASL_CONTINUE => {
                        let Some(active) = exchange.as_mut() else {
                            return Err(SessionError::Tls("SASL continue before start".to_owned()));
                        };
                        let reply = active.respond(sasl_payload(&body)?)?;
                        writer.clear();
                        sasl_response(&mut writer, &reply)?;
                        self.write_all(writer.as_bytes()).await?;
                        self.flush().await?;
                    }
                    AUTH_SASL_FINAL => {
                        let Some(active) = exchange.as_mut() else {
                            return Err(SessionError::Tls("SASL final before start".to_owned()));
                        };
                        active.verify(sasl_payload(&body)?)?;
                    }
                    other => {
                        return Err(SessionError::UnsupportedAuthentication { code: other });
                    }
                },
                _ => {}
            }
        }
    }

    async fn await_ready(&mut self) -> Result<(), SessionError> {
        loop {
            let frame = self.next_frame().await?;
            let tag = frame.tag;
            if tag == TAG_ERROR_RESPONSE {
                let fields = parse_error_fields(self.body(frame)?)?;
                let error = SessionError::BackendRefused {
                    code: String::from_utf8_lossy(fields.code.unwrap_or(b"")).into_owned(),
                    message: String::from_utf8_lossy(fields.message.unwrap_or(b"")).into_owned(),
                };
                self.consume(frame);
                return Err(error);
            }
            if tag == TAG_BACKEND_KEY_DATA {
                let mut reader = Reader::new(self.body(frame)?);
                self.key = Some((reader.i32()?, reader.i32()?));
            }
            if tag == TAG_PARAMETER_STATUS {
                let mut reader = Reader::new(self.body(frame)?);
                let name = String::from_utf8_lossy(reader.cstring()?).into_owned();
                let value = String::from_utf8_lossy(reader.cstring()?).into_owned();
                self.parameters.push((name, value));
            }
            self.consume(frame);
            if tag == TAG_READY_FOR_QUERY {
                return Ok(());
            }
        }
    }


    #[must_use]
    pub fn parameters(&self) -> &[(String, String)] {
        &self.parameters
    }

    #[must_use]
    pub fn has_prepared(&self, name: &str) -> bool {
        self.prepared.contains(name)
    }

    pub fn forget_one_prepared(&mut self, name: &str) {
        self.prepared.remove(name);
    }

    pub fn remember_prepared(&mut self, name: String) {
        self.prepared.insert(name);
    }

    #[must_use]
    pub fn backend_key(&self) -> Option<(i32, i32)> {
        self.key
    }

    pub async fn pin_rendering(&mut self) -> Result<(), SessionError> {
        let sql = backend_settings().map_err(SessionError::Setting)?;
        self.simple_query(sql).await?;
        Ok(())
    }

    pub async fn assume_role(&mut self) -> Result<(), SessionError> {
        let Some(role) = self.role.clone() else {
            return Ok(());
        };
        let sql = format!("SET ROLE \"{}\"", role.replace('"', "\"\""));
        self.simple_query(&sql).await?;
        Ok(())
    }

    #[must_use]
    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    pub fn forget_prepared(&mut self) {
        self.prepared.clear();
    }


    pub async fn simple_query(&mut self, sql: &str) -> Result<Vec<Vec<Option<Vec<u8>>>>, SessionError> {
        let mut writer = Writer::with_capacity(sql.len().saturating_add(8));
        query(&mut writer, sql)?;
        self.write_all(writer.as_bytes()).await?;
        self.flush().await?;

        let mut rows = Vec::new();
        let mut failure = None;
        loop {
            let frame = self.next_frame().await?;
            let tag = frame.tag;
            match tag {
                TAG_DATA_ROW => rows.push(data_row_fields(self.body(frame)?)?),
                TAG_ERROR_RESPONSE => {
                    let fields = parse_error_fields(self.body(frame)?)?;
                    failure = Some(SessionError::BackendRefused {
                        code: String::from_utf8_lossy(fields.code.unwrap_or(b"")).into_owned(),
                        message: String::from_utf8_lossy(fields.message.unwrap_or(b"")).into_owned(),
                    });
                }
                _ => {}
            }
            self.consume(frame);
            if tag == TAG_READY_FOR_QUERY {
                return match failure {
                    Some(error) => Err(error),
                    None => Ok(rows),
                };
            }
        }
    }
}

fn random_nonce() -> String {
    let mut raw = [0u8; 18];
    rand::rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::STANDARD.encode(raw)
}

#[derive(Debug, Default)]
pub struct Collected {
    pub description: Option<Vec<u8>>,
    pub rows: Vec<Vec<u8>>,
    pub affected: u64,
    pub tag: String,
    pub failure: Option<SessionError>,
}

impl Connection {
    pub async fn collect_query(&mut self, sql: &str) -> Result<Collected, SessionError> {
        let mut writer = Writer::with_capacity(sql.len().saturating_add(8));
        query(&mut writer, sql)?;
        self.collect_raw(writer.as_bytes()).await
    }

    pub async fn collect_raw(&mut self, request: &[u8]) -> Result<Collected, SessionError> {
        self.write_all(request).await?;
        self.flush().await?;

        let mut out = Collected::default();
        loop {
            let frame = self.next_frame().await?;
            let tag = frame.tag;
            match tag {
                TAG_ROW_DESCRIPTION if out.description.is_none() => {
                    out.description = Some(self.raw(frame)?.to_vec());
                }
                TAG_DATA_ROW => out.rows.push(self.raw(frame)?.to_vec()),
                TAG_COMMAND_COMPLETE => {
                    let mut reader = Reader::new(self.body(frame)?);
                    let text = String::from_utf8_lossy(reader.cstring()?).into_owned();
                    out.affected = out
                        .affected
                        .saturating_add(text.rsplit(' ').next().and_then(|n| n.parse().ok()).unwrap_or(0));
                    out.tag = text;
                }
                TAG_ERROR_RESPONSE => {
                    let fields = parse_error_fields(self.body(frame)?)?;
                    out.failure = Some(SessionError::BackendRefused {
                        code: String::from_utf8_lossy(fields.code.unwrap_or(b"")).into_owned(),
                        message: String::from_utf8_lossy(fields.message.unwrap_or(b"")).into_owned(),
                    });
                }
                _ => {}
            }
            self.consume(frame);
            if tag == TAG_READY_FOR_QUERY {
                return Ok(out);
            }
        }
    }
}
