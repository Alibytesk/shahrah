use std::sync::Arc;

use shahrah_protocol::error::ProtocolError;
use shahrah_protocol::framing::untagged;
use shahrah_protocol::messages::{
    authentication, authentication_sasl, backend_key_data, error_response, parameter_status,
    command_complete, ready_for_query, sasl_initial_payload, AUTH_OK, AUTH_SASL_CONTINUE,
    AUTH_SASL_FINAL, SEVERITY_ERROR, SEVERITY_FATAL, SQLSTATE_ADMIN_SHUTDOWN, SQLSTATE_FEATURE_NOT_SUPPORTED,
    SQLSTATE_CONNECTION_FAILURE, SQLSTATE_IN_FAILED_TRANSACTION, SQLSTATE_INVALID_PASSWORD,
    SQLSTATE_UNSUPPORTED_PROTOCOL_VERSION, TAG_PASSWORD_MESSAGE,
    TAG_ERROR_RESPONSE, TAG_FLUSH, TAG_QUERY, TAG_READY_FOR_QUERY, TAG_SYNC, TAG_TERMINATE,
    TRANSACTION_ACTIVE, TRANSACTION_FAILED, TRANSACTION_IDLE,
};
use shahrah_protocol::reader::Reader;
use shahrah_protocol::scram::{self, ServerExchange};
use shahrah_protocol::startup::{Startup, CANCEL_REQUEST_CODE, MAX_STARTUP_BODY, PROTOCOL_MAJOR};
use shahrah_protocol::writer::Writer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use crate::admin::{self, ADMIN_DATABASE};
use crate::auth::{nonce, Verifiers};
use crate::cancel::{BackendRoute, CancelKey, CancelRegistry};
use crate::connection::Connection;
use crate::error::SessionError;
use crate::pool::{Lease, Pool};
use crate::statements::Statements;
use crate::tls::BackendTls;
use crate::transport::Transport;
use shahrah_hash::key::ShardKey;
use shahrah_hash::shard::{HashVersion, LogicalShard};
use shahrah_routing::router::{logical_for, Intent};

const READ_CHUNK: usize = 4096;
const FIRST_CHUNK: usize = 1024;
const SSL_DECLINED: u8 = b'N';
const SSL_ACCEPTED: u8 = b'S';
const TAGGED_HEADER: usize = 5;

#[derive(Clone)]
pub struct Shared {
    pub backend_address: String,
    pub registry: Arc<CancelRegistry>,
    pub acceptor: Option<TlsAcceptor>,
    pub connector: TlsConnector,
    pub backend_tls: BackendTls,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
    pub pool: Arc<Pool>,
    pub verifiers: Arc<Verifiers>,
    pub routing: Arc<arc_swap::ArcSwapOption<crate::config::Loaded>>,
    pub health: Arc<crate::health::Health>,
    pub cache: Arc<shahrah_sql::cache::Cache>,
    pub text_sorts_by_bytes: Arc<std::sync::OnceLock<bool>>,
    pub directory: Arc<shahrah_routing::directory::Directory>,
    pub warmed: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    pub warm_per_shard: usize,
    pub relocations: Arc<crate::relocate::Relocations>,
    pub cluster: Arc<std::sync::OnceLock<Arc<shahrah_topology::node::Node>>>,
    pub counters: Arc<crate::metrics::Counters>,
    pub traffic: Arc<crate::metrics::Traffic>,
    pub tracing: Arc<crate::metrics::Tracing>,
}

pub struct Session {
    transport: Transport,
    buffer: Vec<u8>,
    scratch: Writer,
    ssl_offered: bool,
    shared: Shared,
}

pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl Session {
    #[must_use]
    pub fn new(transport: Transport, shared: Shared) -> Self {
        Self {
            transport,
            buffer: Vec::new(),
            scratch: Writer::with_capacity(512),
            ssl_offered: false,
            shared,
        }
    }

    pub async fn run(mut self) -> Result<(), SessionError> {
        loop {
            let raw = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.next_startup_frame())
                .await
                .map_err(|_elapsed| {
                    SessionError::Tls(format!(
                        "the client did not finish its handshake within {HANDSHAKE_TIMEOUT:?}"
                    ))
                })??;
            let body = match untagged(&raw)? {
                Some(frame) => frame.body.to_vec(),
                None => {
                    return Err(SessionError::Protocol(ProtocolError::UnexpectedEnd {
                        needed: raw.len(),
                        remaining: raw.len(),
                    }))
                }
            };

            match Startup::parse(&body)? {
                Startup::SslRequest => {
                    if self.ssl_offered {
                        return Err(SessionError::RepeatedSslRequest);
                    }
                    self.ssl_offered = true;
                    self.negotiate_tls().await?;
                }
                Startup::GssEncRequest => {
                    debug!("declining GSSAPI encryption");
                    self.transport.write_all(&[SSL_DECLINED]).await?;
                }
                Startup::Cancel {
                    process_id,
                    secret_key,
                } => {
                    let key = CancelKey {
                        process_id,
                        secret_key,
                    };
                    return match self.shared.registry.lookup(key).filter(BackendRoute::is_real) {
                        Some(route) => {
                            info!(process_id, address = %route.address, "routing a cancel request");
                            forward_cancel(&route, &self.shared).await
                        }
                        None => {
                            warn!(process_id, "cancel request for an unknown key, ignored");
                            Ok(())
                        }
                    };
                }
                Startup::Connect {
                    major,
                    minor,
                    parameters,
                } => {
                    if major != PROTOCOL_MAJOR {
                        warn!(major, minor, "unsupported protocol version");
                        return self
                            .refuse(
                                SQLSTATE_UNSUPPORTED_PROTOCOL_VERSION,
                                b"shahrah speaks PostgreSQL protocol 3.0 only",
                            )
                            .await;
                    }

                    let user = String::from_utf8_lossy(parameters.get(b"user").unwrap_or(b""))
                        .into_owned();
                    let database = parameters
                        .get(b"database")
                        .map_or_else(|| user.clone(), |value| {
                            String::from_utf8_lossy(value).into_owned()
                        });
                    return self.serve(user, database).await;
                }
            }
        }
    }

    async fn negotiate_tls(&mut self) -> Result<(), SessionError> {
        let Some(acceptor) = self.shared.acceptor.clone() else {
            debug!("declining SSL, no certificate is configured");
            self.transport.write_all(&[SSL_DECLINED]).await?;
            return Ok(());
        };

        if !self.buffer.is_empty() {
            return Err(SessionError::PlaintextAfterSslRequest {
                bytes: self.buffer.len(),
            });
        }

        self.transport.write_all(&[SSL_ACCEPTED]).await?;
        self.transport.flush().await?;

        let plain = core::mem::replace(&mut self.transport, Transport::Placeholder);
        let Transport::Plain(stream) = plain else {
            return Err(SessionError::RepeatedSslRequest);
        };
        let upgraded = acceptor.accept(stream).await?;
        self.transport = Transport::ServerTls(Box::new(upgraded));
        debug!("client connection upgraded to TLS");
        Ok(())
    }

    async fn serve(self, user: String, database: String) -> Result<(), SessionError> {
        let shared = self.shared.clone();
        let Self {
            transport,
            buffer,
            mut scratch,
            ..
        } = self;

        let mut client = Connection::new(transport);
        client.adopt(buffer);

        let verifier = match shared.verifiers.lookup(&user).await {
            Ok(Some(verifier)) => verifier,
            Ok(None) => {
                warn!(user, "no such role");
                return refuse_on(
                    &mut client,
                    &mut scratch,
                    SQLSTATE_INVALID_PASSWORD,
                    format!("password authentication failed for user \"{user}\"").as_bytes(),
                )
                .await;
            }
            Err(SessionError::Scram(
                shahrah_protocol::scram::ScramError::NotScram
                | shahrah_protocol::scram::ScramError::MalformedVerifier,
            )) => {
                warn!(
                    user,
                    "this role's stored password is not a SCRAM-SHA-256 verifier"
                );
                return refuse_on(
                    &mut client,
                    &mut scratch,
                    SQLSTATE_FEATURE_NOT_SUPPORTED,
                    format!(
                        "the password stored for \"{user}\" is not a SCRAM-SHA-256 verifier, \
                         and shahrah speaks no weaker method. Set password_encryption to \
                         scram-sha-256 and give the role its password again"
                    )
                    .as_bytes(),
                )
                .await;
            }
            Err(cause) => {
                warn!(user, %cause, "could not read the verifier");
                return refuse_on(
                    &mut client,
                    &mut scratch,
                    SQLSTATE_FEATURE_NOT_SUPPORTED,
                    b"shahrah could not reach the backend to verify credentials",
                )
                .await;
            }
        };

        if let Err(cause) =
            authenticate_client(&mut client, &mut scratch, verifier, &user).await
        {
            warn!(user, %cause, "client authentication failed");
            return refuse_on(
                &mut client,
                &mut scratch,
                SQLSTATE_INVALID_PASSWORD,
                format!("password authentication failed for user \"{user}\"").as_bytes(),
            )
            .await;
        }
        info!(user, database, "client authenticated by shahrah");
        warm_for_role(&shared, &database, &user);

        let cancel_key = CancelKey {
            process_id: rand_i32(),
            secret_key: rand_i32(),
        };
        let _unused_key = cancel_key;
        let guard = shared.registry.register(BackendRoute::nowhere());
        let issued = guard.issued();

        let backend_parameters = shared.pool.parameters();
        scratch.clear();
        authentication(&mut scratch, AUTH_OK, &[])?;
        if backend_parameters.is_empty() {
            for (name, value) in default_parameters() {
                parameter_status(&mut scratch, name, value)?;
            }
        } else {
            for (name, value) in &backend_parameters {
                parameter_status(&mut scratch, name, value)?;
            }
        }
        backend_key_data(&mut scratch, issued.process_id, issued.secret_key)?;
        ready_for_query(&mut scratch, TRANSACTION_IDLE)?;
        client.write_all(scratch.as_bytes()).await?;
        client.flush().await?;

        client.release_buffer();
        scratch.release();

        let outcome = if database == ADMIN_DATABASE {
            serve_admin(&mut client, &mut scratch, &shared).await
        } else {
            pump(&mut client, &mut scratch, &shared, &user, &database, issued).await
        };
        drop(guard);
        outcome
    }

    async fn next_startup_frame(&mut self) -> Result<Vec<u8>, SessionError> {
        loop {
            match untagged(&self.buffer)? {
                Some(frame) => {
                    let total = frame.consumed;
                    let raw = self.buffer.drain(..total).collect();
                    return Ok(raw);
                }
                None => {
                    if self.buffer.len() > MAX_STARTUP_BODY {
                        return Err(SessionError::StartupTooLarge {
                            limit: MAX_STARTUP_BODY,
                        });
                    }
                    self.fill().await?;
                }
            }
        }
    }

    async fn fill(&mut self) -> Result<(), SessionError> {
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

    async fn refuse(&mut self, code: &[u8], message: &[u8]) -> Result<(), SessionError> {
        self.scratch.clear();
        error_response(&mut self.scratch, SEVERITY_FATAL, code, message)?;
        self.transport.write_all(self.scratch.as_bytes()).await?;
        self.transport.flush().await?;
        Ok(())
    }
}

fn rand_i32() -> i32 {
    use rand::RngCore;
    rand::rng().next_u32() as i32
}

fn default_parameters() -> [(&'static str, &'static str); 6] {
    [
        ("server_version", "18.4"),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
    ]
}

async fn refuse_on(
    client: &mut Connection,
    scratch: &mut Writer,
    code: &[u8],
    message: &[u8],
) -> Result<(), SessionError> {
    scratch.clear();
    error_response(scratch, SEVERITY_FATAL, code, message)?;
    client.write_all(scratch.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

async fn authenticate_client(
    client: &mut Connection,
    scratch: &mut Writer,
    verifier: shahrah_protocol::scram::Verifier,
    user: &str,
) -> Result<(), SessionError> {
    let _named = user;
    scratch.clear();
    authentication_sasl(scratch, scram::MECHANISM)?;
    client.write_all(scratch.as_bytes()).await?;
    client.flush().await?;

    let mut exchange = ServerExchange::new(verifier, nonce());

    let frame = client.next_frame().await?;
    if frame.tag != TAG_PASSWORD_MESSAGE {
        return Err(SessionError::UnexpectedClientMessage { tag: frame.tag });
    }
    let (mechanism, payload) = sasl_initial_payload(client.body(frame)?)?;
    if mechanism != scram::MECHANISM.as_bytes() {
        return Err(SessionError::UnsupportedMechanism {
            name: String::from_utf8_lossy(mechanism).into_owned(),
        });
    }
    let server_first = exchange.first(payload)?;
    client.consume(frame);

    scratch.clear();
    authentication(scratch, AUTH_SASL_CONTINUE, server_first.as_bytes())?;
    client.write_all(scratch.as_bytes()).await?;
    client.flush().await?;

    let frame = client.next_frame().await?;
    if frame.tag != TAG_PASSWORD_MESSAGE {
        return Err(SessionError::UnexpectedClientMessage { tag: frame.tag });
    }
    let final_message = client.body(frame)?.to_vec();
    client.consume(frame);
    let server_final = exchange.finish(&final_message)?;

    scratch.clear();
    authentication(scratch, AUTH_SASL_FINAL, server_final.as_bytes())?;
    client.write_all(scratch.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

async fn serve_admin(
    client: &mut Connection,
    scratch: &mut Writer,
    shared: &Shared,
) -> Result<(), SessionError> {
    let mut prepared = false;
    let mut reported = false;
    loop {
        let frame = match client.next_frame().await {
            Ok(frame) => frame,
            Err(SessionError::ClientClosed) => return Ok(()),
            Err(cause) => return Err(cause),
        };
        match frame.tag {
            TAG_TERMINATE => return Ok(()),
            TAG_QUERY => {
                let mut reader = Reader::new(client.body(frame)?);
                let sql = String::from_utf8_lossy(reader.cstring()?).into_owned();
                client.consume(frame);

                admin::respond(scratch, shared, &sql).await?;
                client.write_all(scratch.as_bytes()).await?;
                client.flush().await?;
                prepared = false;
                reported = false;
            }
            TAG_SYNC => {
                client.consume(frame);
                scratch.clear();
                if prepared && !reported {
                    error_response(
                        scratch,
                        SEVERITY_ERROR,
                        SQLSTATE_FEATURE_NOT_SUPPORTED,
                        CONSOLE_SIMPLE_ONLY,
                    )?;
                }
                ready_for_query(scratch, TRANSACTION_IDLE)?;
                client.write_all(scratch.as_bytes()).await?;
                client.flush().await?;
                prepared = false;
                reported = false;
            }
            TAG_FLUSH => {
                client.consume(frame);
                if prepared && !reported {
                    scratch.clear();
                    error_response(
                        scratch,
                        SEVERITY_ERROR,
                        SQLSTATE_FEATURE_NOT_SUPPORTED,
                        CONSOLE_SIMPLE_ONLY,
                    )?;
                    client.write_all(scratch.as_bytes()).await?;
                    client.flush().await?;
                    reported = true;
                }
            }
            _ => {
                client.consume(frame);
                prepared = true;
            }
        }
    }
}

const CONSOLE_SIMPLE_ONLY: &[u8] =
    b"the shahrah console answers the simple query protocol; send console statements unprepared";

fn remember_setting(settings: &mut Vec<(String, String)>, sql: &str) {
    let trimmed = sql.trim_start();
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("reset all") || lowered.starts_with("discard all") {
        settings.clear();
        return;
    }
    if !lowered.starts_with("set ") || lowered.starts_with("set local ") {
        return;
    }
    let Some(rest) = trimmed.get(4..) else {
        return;
    };
    let name = rest
        .split(|c: char| c.is_whitespace() || c == '=')
        .find(|piece| !piece.is_empty())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.is_empty() || matches!(name.as_str(), "role" | "session_authorization") {
        return;
    }
    settings.retain(|(known, _sql)| known != &name);
    settings.push((name, trimmed.to_owned()));
}

async fn replay_settings(lease: &mut Lease, settings: &[(String, String)]) {
    if settings.is_empty() {
        return;
    }
    let Ok(backend) = lease.connection() else {
        return;
    };
    for (name, sql) in settings {
        if let Err(cause) = backend.simple_query(sql).await {
            debug!(%name, %cause, "a session setting did not replay onto this shard");
            return;
        }
    }
}

fn retarget_cancel(
    shared: &Shared,
    issued: CancelKey,
    lease: &mut Lease,
    address: &str,
    routed: &mut Option<(CancelKey, String)>,
) {
    let Ok(backend) = lease.connection() else {
        return;
    };
    let Some((process_id, secret_key)) = backend.backend_key() else {
        return;
    };
    let key = CancelKey {
        process_id,
        secret_key,
    };
    if let Some((known, known_address)) = routed.as_ref()
        && *known == key
        && known_address == address
    {
        return;
    }
    shared.registry.retarget(
        issued,
        BackendRoute {
            key,
            address: address.to_owned(),
        },
    );
    *routed = Some((key, address.to_owned()));
}

async fn pump(
    client: &mut Connection,
    scratch: &mut Writer,
    shared: &Shared,
    user: &str,
    database: &str,
    issued: CancelKey,
) -> Result<(), SessionError> {
    let mut held: Option<Lease> = None;
    let mut statements = Statements::new();
    let mut pinned = false;
    let mut settings: Vec<(String, String)> = Vec::new();
    let mut wrote: std::collections::HashMap<String, Wrote> = std::collections::HashMap::new();
    let mut pending_prepared: Vec<String> = Vec::new();
    let mut deferred: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut in_transaction = false;
    let mut held_address = String::new();
    let mut poisoned = false;
    let mut skip_until_sync = false;
    let mut pending_begin: Option<String> = None;
    let mut held_generation: u64 = 0;
    let mut broadcast_pending: Option<(String, Vec<u8>, Vec<u8>)> = None;
    let mut broadcast_describe = false;
    let mut broadcast_parsed = false;
    let mut shapes: Shapes = std::collections::HashMap::new();
    let mut cancel_route: Option<(CancelKey, String)> = None;
    let mut slot: Option<crate::pool::Held> = None;

    loop {
        let mut progressed = false;
        let mut wrote_to_backend = false;

        while let Some(frame) = client.try_frame()? {
            if frame.tag == shahrah_protocol::messages::TAG_TERMINATE {
                if let Some(lease) = held.take() {
                    if in_transaction {
                        if let Err(cause) = rollback_and_release(lease, pinned).await {
                            debug!(
                                %cause,
                                "a client left a transaction open and the backend could not be \
                                 rolled back, so it does not go back in the pool"
                            );
                        }
                    } else if pinned {
                        lease.release_deep().await;
                    } else {
                        lease.release().await;
                    }
                }
                return Ok(());
            }

            if frame.tag == shahrah_protocol::messages::TAG_PARSE
                && let Ok(name) = shahrah_protocol::messages::parse_statement_name(client.body(frame)?)
                && let Ok(sql) = shahrah_protocol::messages::parse_sql(client.body(frame)?)
            {
                shapes.insert(
                    name.to_vec(),
                    (
                        String::from_utf8_lossy(sql).into_owned(),
                        shahrah_protocol::messages::parse_param_types(client.body(frame)?)
                            .map(<[u8]>::to_vec)
                            .unwrap_or_default(),
                    ),
                );
            }

            if broadcast_pending.is_some() {
                match frame.tag {
                    shahrah_protocol::messages::TAG_DESCRIBE => {
                        broadcast_describe = true;
                        client.consume(frame);
                        progressed = true;
                        continue;
                    }
                    shahrah_protocol::messages::TAG_EXECUTE
                    | shahrah_protocol::messages::TAG_FLUSH => {
                        client.consume(frame);
                        progressed = true;
                        continue;
                    }
                    shahrah_protocol::messages::TAG_CLOSE => {
                        client.consume(frame);
                        progressed = true;
                        scratch.clear();
                        shahrah_protocol::messages::close_complete(scratch)?;
                        client.write_all(scratch.as_bytes()).await?;
                        client.flush().await?;
                        continue;
                    }
                    shahrah_protocol::messages::TAG_SYNC => {
                        let Some((sql, body, types)) = broadcast_pending.take() else {
                            continue;
                        };
                        client.consume(frame);
                        progressed = true;
                        run_broadcast(
                            client,
                            scratch,
                            shared,
                            database,
                            user,
                            &sql,
                            Some((&body, &types)),
                            crate::broadcast::Framing::Extended {
                                describe: broadcast_describe,
                                parsed: broadcast_parsed,
                            },
                            &settings,
                        )
                        .await?;
                        broadcast_describe = false;
                        broadcast_parsed = false;
                        scratch.clear();
                        ready_for_query(scratch, TRANSACTION_IDLE)?;
                        client.write_all(scratch.as_bytes()).await?;
                        client.flush().await?;
                        continue;
                    }
                    _ => {
                        broadcast_pending = None;
                        broadcast_describe = false;
                        broadcast_parsed = false;
                    }
                }
            }

            if skip_until_sync {
                let is_sync = frame.tag == shahrah_protocol::messages::TAG_SYNC;
                client.consume(frame);
                progressed = true;
                if is_sync {
                    skip_until_sync = false;
                    scratch.clear();
                    ready_for_query(
                        scratch,
                        if poisoned {
                            TRANSACTION_FAILED
                        } else {
                            TRANSACTION_IDLE
                        },
                    )?;
                    client.write_all(scratch.as_bytes()).await?;
                    client.flush().await?;
                }
                continue;
            }

            if poisoned {
                let text = statement_text(frame.tag, client.body(frame)?, &shapes);
                let ends = text.as_deref().is_some_and(ends_transaction);
                if ends {
                    poisoned = false;
                    in_transaction = false;
                    if let Some(lease) = held.take() {
                        rollback_and_release(lease, pinned).await?;
                    }
                    held_address.clear();
                    deferred.clear();
                    statements.clear_in_flight();
                    scratch.clear();
                    command_complete(scratch, "ROLLBACK")?;
                    ready_for_query(scratch, TRANSACTION_IDLE)?;
                    client.write_all(scratch.as_bytes()).await?;
                    client.flush().await?;
                    client.consume(frame);
                    progressed = true;
                    continue;
                }
                let simple = frame.tag == shahrah_protocol::messages::TAG_QUERY;
                client.consume(frame);
                progressed = true;
                refuse_statement(
                    client,
                    scratch,
                    SQLSTATE_IN_FAILED_TRANSACTION,
                    b"current transaction is aborted, commands ignored until end of transaction block",
                    simple,
                    TRANSACTION_FAILED,
                )
                .await?;
                if !simple {
                    skip_until_sync = true;
                }
                continue;
            }

            if shared.routing.load().is_some()
                && frame.tag == shahrah_protocol::messages::TAG_QUERY
                && held.is_none()
                && let Some(text) = statement_text(frame.tag, client.body(frame)?, &shapes)
                && carries_only_a_begin(&text)
            {
                pending_begin = Some(text);
                in_transaction = true;
                held_generation = 0;
                client.consume(frame);
                progressed = true;
                scratch.clear();
                command_complete(scratch, "BEGIN")?;
                ready_for_query(scratch, TRANSACTION_ACTIVE)?;
                client.write_all(scratch.as_bytes()).await?;
                client.flush().await?;
                continue;
            }

            if shared.routing.load().is_some()
                && pending_begin.is_some()
                && held.is_none()
                && frame.tag == shahrah_protocol::messages::TAG_QUERY
                && let Some(text) = statement_text(frame.tag, client.body(frame)?, &shapes)
                && carries_only_an_end(&text)
            {
                pending_begin = None;
                in_transaction = false;
                client.consume(frame);
                progressed = true;
                scratch.clear();
                command_complete(scratch, end_tag(&text))?;
                ready_for_query(scratch, TRANSACTION_IDLE)?;
                client.write_all(scratch.as_bytes()).await?;
                client.flush().await?;
                continue;
            }

            let decide = held.is_none()
                || matches!(
                    frame.tag,
                    shahrah_protocol::messages::TAG_BIND | shahrah_protocol::messages::TAG_QUERY
                );
            let wanted = if decide {
                target_for(
                    shared,
                    client.body(frame)?,
                    frame.tag,
                    &shapes,
                    in_transaction || pending_begin.is_some(),
                    &mut wrote,
                )
            } else {
                Target::Undecided
            };

            if matches!(wanted, Target::Broadcast) {
                if in_transaction && pending_begin.is_none() {
                    let message = b"a broadcast read cannot join a transaction that already holds \
                                    one shard".to_vec();
                    client.consume(frame);
                    progressed = true;
                    poisoned = true;
                    refuse_statement(
                        client,
                        scratch,
                        SQLSTATE_FEATURE_NOT_SUPPORTED,
                        &message,
                        frame.tag == shahrah_protocol::messages::TAG_QUERY,
                        TRANSACTION_FAILED,
                    )
                    .await?;
                    if frame.tag != shahrah_protocol::messages::TAG_QUERY {
                        skip_until_sync = true;
                    }
                    continue;
                }
                let sql = statement_text(frame.tag, client.body(frame)?, &shapes)
                    .unwrap_or_default();
                if frame.tag == shahrah_protocol::messages::TAG_QUERY {
                    client.consume(frame);
                    progressed = true;
                    run_broadcast(
                        client,
                        scratch,
                        shared,
                        database,
                        user,
                        &sql,
                        None,
                        crate::broadcast::Framing::Simple,
                        &settings,
                    )
                    .await?;
                    continue;
                }
                let body = client.body(frame)?.to_vec();
                let types = statement_types(client.body(frame)?, &shapes);
                client.consume(frame);
                progressed = true;
                broadcast_parsed = deferred
                    .iter()
                    .any(|(tag, _raw)| *tag == shahrah_protocol::messages::TAG_PARSE);
                deferred.clear();
                if let Some(mut lease) = held.take() {
                    let backend = lease.connection()?;
                    for name in pending_prepared.drain(..) {
                        backend.remember_prepared(name);
                    }
                    if settings.is_empty() {
                        lease.release().await;
                    } else {
                        lease.release_deep().await;
                    }
                    held_address = String::new();
                }
                statements.commit_in_flight();
                broadcast_describe = false;
                broadcast_pending = Some((sql, body, types));
                continue;
            }

            if let Target::Refuse { code, message } = &wanted {
                let simple = frame.tag == shahrah_protocol::messages::TAG_QUERY;
                warn!(%message, "refusing a statement shahrah cannot route safely");
                client.consume(frame);
                progressed = true;
                if in_transaction {
                    poisoned = true;
                }
                refuse_statement(
                    client,
                    scratch,
                    code,
                    message.as_bytes(),
                    simple,
                    if in_transaction {
                        TRANSACTION_FAILED
                    } else {
                        TRANSACTION_IDLE
                    },
                )
                .await?;
                if !simple {
                    skip_until_sync = true;
                }
                continue;
            }

            if let Target::NeedsDirectory(key) = &wanted {
                let key = key.clone();
                if shared.relocations.is_moving_key(&key) {
                    crate::metrics::Counters::bump(&shared.counters.directory_waits);
                }
                shared.relocations.wait_if_moving(&key).await;
                match look_up_home(shared, &key, database).await {
                    Ok(()) => {
                        progressed = true;
                        continue;
                    }
                    Err(cause) => {
                        warn!(
                            %cause,
                            "the directory that says where this key lives could not be read"
                        );
                        client.consume(frame);
                        progressed = true;
                        if in_transaction {
                            poisoned = true;
                        }
                        refuse_statement(
                            client,
                            scratch,
                            SQLSTATE_CONNECTION_FAILURE,
                            b"shahrah could not reach the directory that says which region this \
                              key lives in, and it will not guess one",
                            frame.tag == shahrah_protocol::messages::TAG_QUERY,
                            if in_transaction {
                                TRANSACTION_FAILED
                            } else {
                                TRANSACTION_IDLE
                            },
                        )
                        .await?;
                        if frame.tag != shahrah_protocol::messages::TAG_QUERY {
                            skip_until_sync = true;
                        }
                        continue;
                    }
                }
            }

            if let Target::Backend(_) = &wanted
                && let Some(logical) = logical_of_frame(shared, client.body(frame)?, frame.tag, &shapes)
            {
                shared.relocations.wait_if_logical_moving(logical).await;
            }

            if held.is_none() {
                match wanted {
                    Target::Backend(address) => {
                        statements.clear_in_flight();
                        match open_lease(
                            shared,
                            &address,
                            database,
                            user,
                            &mut pending_begin,
                            &decides_the_shard(frame.tag),
                            &mut slot,
                        )
                        .await
                        {
                            Ok(mut lease) => {
                                retarget_cancel(shared, issued, &mut lease, &address, &mut cancel_route);
                                replay_settings(&mut lease, &settings).await;
                                held = Some(lease);
                                held_address = address;
                                if in_transaction && pending_begin.is_none() && held_generation == 0 {
                                    held_generation = shared
                                        .routing
                                        .load()
                                        .as_deref()
                                        .map_or(0, |loaded| loaded.generation);
                                }
                            }
                            Err(cause) => {
                                let simple =
                                    frame.tag == shahrah_protocol::messages::TAG_QUERY;
                                client.consume(frame);
                                progressed = true;
                                held_address = address;
                                if !matches!(cause, SessionError::PoolBusy { .. }) {
                                    shared.traffic.error(&held_address);
                                }
                                report_backend_loss(
                                    client, scratch, &shared.health, &cause, simple,
                                    &mut held, &mut held_address, &mut statements,
                                    &mut in_transaction, &mut poisoned, &mut skip_until_sync,
                                )
                                .await?;
                                continue;
                            }
                        }
                    }
                    Target::Anywhere(chosen) => {
                        let address = if chosen.is_empty() {
                            shared.backend_address.clone()
                        } else {
                            chosen
                        };
                        statements.clear_in_flight();
                        match open_lease(
                            shared,
                            &address,
                            database,
                            user,
                            &mut pending_begin,
                            &decides_the_shard(frame.tag),
                            &mut slot,
                        )
                        .await
                        {
                            Ok(mut lease) => {
                                retarget_cancel(shared, issued, &mut lease, &address, &mut cancel_route);
                                replay_settings(&mut lease, &settings).await;
                                held = Some(lease);
                                held_address = address;
                                if in_transaction && pending_begin.is_none() && held_generation == 0 {
                                    held_generation = shared
                                        .routing
                                        .load()
                                        .as_deref()
                                        .map_or(0, |loaded| loaded.generation);
                                }
                            }
                            Err(cause) => {
                                let simple =
                                    frame.tag == shahrah_protocol::messages::TAG_QUERY;
                                client.consume(frame);
                                progressed = true;
                                held_address = address;
                                if !matches!(cause, SessionError::PoolBusy { .. }) {
                                    shared.traffic.error(&held_address);
                                }
                                report_backend_loss(
                                    client, scratch, &shared.health, &cause, simple,
                                    &mut held, &mut held_address, &mut statements,
                                    &mut in_transaction, &mut poisoned, &mut skip_until_sync,
                                )
                                .await?;
                                continue;
                            }
                        }
                    }
                    Target::Undecided
                    | Target::Refuse { .. }
                    | Target::Broadcast
                    | Target::NeedsDirectory(_) => {
                        deferred.push((frame.tag, client.raw(frame)?.to_vec()));
                        client.consume(frame);
                        progressed = true;
                        continue;
                    }
                }
            } else if let Target::Backend(address) = &wanted
                && *address != held_address
                && matches!(
                    frame.tag,
                    shahrah_protocol::messages::TAG_BIND | shahrah_protocol::messages::TAG_QUERY
                )
                && in_transaction
                && pending_begin.is_none()
            {
                let simple = frame.tag == shahrah_protocol::messages::TAG_QUERY;
                let moved = held_generation != 0
                    && shared
                        .routing
                        .load()
                        .as_deref()
                        .is_some_and(|loaded| loaded.generation != held_generation);
                warn!(
                    from = %held_address,
                    to = %address,
                    moved,
                    "refusing a transaction that would span two shards"
                );
                client.consume(frame);
                progressed = true;
                poisoned = true;
                let message: &[u8] = if moved {
                    b"the topology changed while this transaction was open and this key now \
                      belongs to another shard; shahrah aborts the transaction rather than \
                      reading half of it from each. retry it"
                } else {
                    b"this transaction already holds one shard and this statement names another; \
                      shahrah refuses a cross-shard transaction rather than committing part of it"
                };
                refuse_statement(
                    client,
                    scratch,
                    SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message,
                    simple,
                    TRANSACTION_FAILED,
                )
                .await?;
                if !simple {
                    skip_until_sync = true;
                }
                continue;
            } else if let Target::Backend(address) = &wanted
                && *address != held_address
                && (!in_transaction || pending_begin.is_some())
                && matches!(
                    frame.tag,
                    shahrah_protocol::messages::TAG_BIND | shahrah_protocol::messages::TAG_QUERY
                )
            {
                debug!(
                    from = %held_address,
                    to = %address,
                    "moving to the shard the bound key names"
                );
                if let Some(mut lease) = held.take() {
                    let backend = lease.connection()?;
                    for name in pending_prepared.drain(..) {
                        backend.remember_prepared(name);
                    }
                    if settings.is_empty() {
                        lease.release().await;
                    } else {
                        lease.release_deep().await;
                    }
                }
                statements.clear_in_flight();
                match open_lease(
                    shared,
                    address,
                    database,
                    user,
                    &mut pending_begin,
                    &decides_the_shard(frame.tag),
                    &mut slot,
                )
                .await
                {
                    Ok(mut lease) => {
                        retarget_cancel(shared, issued, &mut lease, address, &mut cancel_route);
                        replay_settings(&mut lease, &settings).await;
                        held = Some(lease);
                        held_address = address.clone();
                        if in_transaction && pending_begin.is_none() && held_generation == 0 {
                            held_generation = shared
                                .routing
                                .load()
                                .as_deref()
                                .map_or(0, |loaded| loaded.generation);
                        }
                    }
                    Err(cause) => {
                        client.consume(frame);
                        progressed = true;
                        held_address = address.clone();
                        report_backend_loss(
                            client, scratch, &shared.health, &cause, false,
                            &mut held, &mut held_address, &mut statements,
                            &mut in_transaction, &mut poisoned, &mut skip_until_sync,
                        )
                        .await?;
                        continue;
                    }
                }
            }

            if let Some(opening) = pending_begin.as_deref()
                && decides_the_shard(frame.tag)
                && let Some(lease) = held.as_mut()
            {
                match lease.connection() {
                    Ok(backend) => {
                        if let Err(cause) = backend.simple_query(opening).await {
                            client.consume(frame);
                            progressed = true;
                            report_backend_loss(
                                client, scratch, &shared.health, &cause, false,
                                &mut held, &mut held_address, &mut statements,
                                &mut in_transaction, &mut poisoned, &mut skip_until_sync,
                            )
                            .await?;
                            continue;
                        }
                        pending_begin = None;
                    }
                    Err(cause) => {
                        client.consume(frame);
                        progressed = true;
                        report_backend_loss(
                            client, scratch, &shared.health, &cause, false,
                            &mut held, &mut held_address, &mut statements,
                            &mut in_transaction, &mut poisoned, &mut skip_until_sync,
                        )
                        .await?;
                        continue;
                    }
                }
            }

            let Some(lease) = held.as_mut() else {
                return Err(SessionError::PoolClosed);
            };

            let mut backend_failed: Option<SessionError> = None;

            for (tag, raw) in deferred.drain(..) {
                let body = raw.get(TAGGED_HEADER..).unwrap_or(&[]);
                let action = {
                    let backend = lease.connection()?;
                    let seen = |name: &str| backend.has_prepared(name);
                    statements.inspect(tag, &raw, body, &seen)?
                };
                if action.pins {
                    pinned = true;
                    if let Some(text) = statement_text(tag, body, &shapes) {
                        remember_setting(&mut settings, &text);
                    }
                }
                if action.synthesise_parse_complete {
                    scratch.clear();
                    shahrah_protocol::messages::parse_complete(scratch)?;
                    client.write_all(scratch.as_bytes()).await?;
                    client.flush().await?;
                }
                if !action.skip {
                    let backend = lease.connection()?;
                    let sent = match action.replacement {
                        Some(bytes) => backend.write_all(&bytes).await,
                        None => backend.write_all(&raw).await,
                    };
                    if let Err(cause) = sent {
                        backend_failed = Some(cause);
                        break;
                    }
                    wrote_to_backend = true;
                }
                if let Some(name) = action.closed {
                    lease.connection()?.forget_one_prepared(&name);
                }
                if let Some(name) = action.prepared {
                    pending_prepared.push(name);
                }
            }

            let action = {
                let backend = lease.connection()?;
                let seen = |name: &str| backend.has_prepared(name);
                statements.inspect(frame.tag, client.raw(frame)?, client.body(frame)?, &seen)?
            };

            if action.pins {
                pinned = true;
                if let Some(text) = statement_text(frame.tag, client.body(frame)?, &shapes) {
                    remember_setting(&mut settings, &text);
                }
            }

            if action.synthesise_parse_complete {
                scratch.clear();
                shahrah_protocol::messages::parse_complete(scratch)?;
                client.write_all(scratch.as_bytes()).await?;
                client.flush().await?;
            }

            if !action.skip && backend_failed.is_none() {
                let backend = lease.connection()?;
                let sent = match action.replacement {
                    Some(bytes) => backend.write_all(&bytes).await,
                    None => backend.write_all(client.raw(frame)?).await,
                };
                if let Err(cause) = sent {
                    backend_failed = Some(cause);
                } else {
                    wrote_to_backend = true;
                }
            }

            if let Some(name) = action.closed
                && let Some(lease) = held.as_mut()
            {
                lease.connection()?.forget_one_prepared(&name);
            }
            if let Some(name) = action.prepared {
                pending_prepared.push(name);
            }

            if let Some(cause) = backend_failed {
                let simple = frame.tag == shahrah_protocol::messages::TAG_QUERY;
                client.consume(frame);
                progressed = true;
                report_backend_loss(
                    client, scratch, &shared.health, &cause, simple,
                    &mut held, &mut held_address, &mut statements,
                    &mut in_transaction, &mut poisoned, &mut skip_until_sync,
                )
                .await?;
                continue;
            }

            let boundary_sent = matches!(
                frame.tag,
                shahrah_protocol::messages::TAG_SYNC | shahrah_protocol::messages::TAG_QUERY
            );
            client.consume(frame);
            progressed = true;
            if boundary_sent {
                break;
            }
        }

        if wrote_to_backend
            && let Some(lease) = held.as_mut()
            && let Err(cause) = lease.connection()?.flush().await
        {
            report_backend_loss(
                client, scratch, &shared.health, &cause, true,
                &mut held, &mut held_address, &mut statements,
                &mut in_transaction, &mut poisoned, &mut skip_until_sync,
            )
            .await?;
            continue;
        }

        let mut boundary = None;
        let mut lost: Option<SessionError> = None;
        if let Some(lease) = held.as_mut() {
            let backend = lease.connection()?;
            let mut wrote_to_client = false;
            let mut batch_failed = false;
            let mut commit: Vec<String> = Vec::new();
            while let Some(frame) = match backend.try_frame() {
                Ok(frame) => frame,
                Err(cause) => {
                    lost = Some(cause);
                    None
                }
            } {
                if statements.swallow(frame.tag) {
                    backend.consume(frame);
                    progressed = true;
                    continue;
                }
                if frame.tag == TAG_ERROR_RESPONSE {
                    batch_failed = true;
                    shared.traffic.error(&held_address);
                }
                if frame.tag == TAG_READY_FOR_QUERY {
                    let mut reader = Reader::new(backend.body(frame)?);
                    let status = reader.u8()?;
                    in_transaction = status != TRANSACTION_IDLE;
                    if !in_transaction {
                        held_generation = 0;
                    }
                    boundary = Some(status);
                    for seen in wrote.values_mut() {
                        if seen.target.is_none() {
                            seen.at = std::time::Instant::now();
                        }
                    }
                    if batch_failed {
                        pending_prepared.clear();
                        statements.clear_in_flight();
                    } else {
                        commit.append(&mut pending_prepared);
                        statements.commit_in_flight();
                    }
                    batch_failed = false;
                }
                client.write_all(backend.raw(frame)?).await?;
                backend.consume(frame);
                progressed = true;
                wrote_to_client = true;
            }
            for name in commit {
                backend.remember_prepared(name);
            }
            if wrote_to_client {
                client.flush().await?;
            }
        }

        if let Some(cause) = lost {
            report_backend_loss(
                client, scratch, &shared.health, &cause, true,
                &mut held, &mut held_address, &mut statements,
                &mut in_transaction, &mut poisoned, &mut skip_until_sync,
            )
            .await?;
            continue;
        }

        if boundary == Some(TRANSACTION_IDLE)
            && !pinned
            && let Some(lease) = held.take()
        {
            lease.release().await;
            held_address.clear();
            client.release_buffer();
            scratch.release();
        }

        if boundary == Some(TRANSACTION_IDLE) && *shared.shutdown.borrow() {
            info!("draining an idle session for shutdown");
            scratch.clear();
            error_response(
                scratch,
                SEVERITY_FATAL,
                SQLSTATE_ADMIN_SHUTDOWN,
                b"shahrah is shutting down",
            )?;
            client.write_all(scratch.as_bytes()).await?;
            client.flush().await?;
            return Ok(());
        }

        if progressed {
            continue;
        }

        let (outcome, from_backend) = match held.as_mut() {
            Some(lease) => {
                let backend = lease.connection()?;
                tokio::select! {
                    result = client.wait_readable() => (result, false),
                    result = backend.wait_readable() => (result, true),
                }
            }
            None => (client.wait_readable().await, false),
        };

        if from_backend
            && let Err(cause) = outcome
        {
            report_backend_loss(
                client, scratch, &shared.health, &cause, true,
                &mut held, &mut held_address, &mut statements,
                &mut in_transaction, &mut poisoned, &mut skip_until_sync,
            )
            .await?;
            continue;
        }

        match outcome {
            Ok(()) => {}
            Err(SessionError::ClientClosed) => {
                if let Some(lease) = held.take() {
                    if pinned {
                        lease.release_deep().await;
                    } else {
                        lease.discard();
                    }
                }
                return Ok(());
            }
            Err(cause) => {
                if let Some(lease) = held.take() {
                    lease.discard();
                }
                return Err(cause);
            }
        }
    }
}

enum Target {
    Backend(String),
    Anywhere(String),
    Broadcast,
    Undecided,
    NeedsDirectory(Vec<u8>),
    Refuse { code: &'static [u8], message: String },
}

fn logical_of_frame(shared: &Shared, body: &[u8], tag: u8, shapes: &Shapes) -> Option<u16> {
    let loaded = shared.routing.load();
    let routing = loaded.as_deref()?;
    let sql = statement_text(tag, body, shapes)?;
    let analysis = shared.cache.analyse(&sql, &routing.policy).ok()?;
    let shahrah_sql::analysis::Routing::Single { source, key_type } = &analysis.routing else {
        return None;
    };
    let bind = (tag == shahrah_protocol::messages::TAG_BIND)
        .then(|| shahrah_protocol::messages::parse_bind(body).ok())
        .flatten();
    logical_for_source(source, *key_type, bind.as_ref()).map(|logical| logical.get())
}

fn target_for(
    shared: &Shared,
    body: &[u8],
    tag: u8,
    shapes: &Shapes,
    in_transaction: bool,
    wrote: &mut std::collections::HashMap<String, Wrote>,
) -> Target {
    let loaded = shared.routing.load();
    let Some(routing) = loaded.as_deref() else {
        return Target::Backend(shared.backend_address.clone());
    };

    let outcome = match tag {
        shahrah_protocol::messages::TAG_QUERY => {
            let mut reader = Reader::new(body);
            match reader.cstring() {
                Ok(raw) => resolve_sql(
                    shared,
                    routing,
                    &String::from_utf8_lossy(raw),
                    None,
                    in_transaction,
                    wrote,
                ),
                Err(_) => Outcome::Anywhere(Intent::Write),
            }
        }
        shahrah_protocol::messages::TAG_PARSE
        | shahrah_protocol::messages::TAG_DESCRIBE_STATEMENT
        | shahrah_protocol::messages::TAG_CLOSE => return Target::Undecided,
        shahrah_protocol::messages::TAG_BIND => match shahrah_protocol::messages::parse_bind(body) {
            Ok(bind) => match shapes.get(bind.statement) {
                Some((sql, _types)) => {
                    resolve_sql(shared, routing, sql, Some(&bind), in_transaction, wrote)
                }
                None => Outcome::Anywhere(Intent::Write),
            },
            Err(_) => Outcome::Anywhere(Intent::Write),
        },
        _ => Outcome::Anywhere(Intent::Write),
    };

    match outcome {
        Outcome::Shard(address) => Target::Backend(address),
        Outcome::Anywhere(intent) => {
            let address = anywhere_healthy(&routing.topology, &shared.health, intent);
            if decides_the_shard(tag) {
                shared.traffic.statement(&address);
            }
            Target::Anywhere(address)
        }
        Outcome::Broadcast => Target::Broadcast,
        Outcome::NeedsDirectory(key) => Target::NeedsDirectory(key),
        Outcome::Refuse { code, message } => Target::Refuse { code, message },
    }
}

enum Outcome {
    Shard(String),
    Anywhere(Intent),
    Broadcast,
    NeedsDirectory(Vec<u8>),
    Refuse {
        code: &'static [u8],
        message: String,
    },
}

const SYSTEM_SCHEMAS: &[&str] = &["pg_catalog", "information_schema", "pg_toast"];

fn is_system_table(table: &str) -> bool {
    let name = table.to_lowercase();
    if let Some((schema, _rest)) = name.split_once('.') {
        return SYSTEM_SCHEMAS.contains(&schema);
    }
    name.starts_with("pg_")
}

fn undeclared_table(
    analysis: &shahrah_sql::analysis::Analysis,
    routing: &crate::config::Loaded,
) -> Option<Outcome> {
    if routing.topology.regions().len() < 2 {
        return None;
    }
    let unknown: Vec<&str> = analysis
        .classes
        .iter()
        .filter(|(table, class)| class.is_none() && !is_system_table(table))
        .map(|(table, _class)| table.as_str())
        .collect();
    let named = unknown.first()?;
    warn!(
        table = named,
        "this topology holds more than one region and this table declares no placement class"
    );
    Some(Outcome::Refuse {
        code: SQLSTATE_FEATURE_NOT_SUPPORTED,
        message: format!(
            "table \"{named}\" declares no placement class, and this topology holds more than \
             one region, so serving it from the local one would be a guess about where its rows \
             live. Declare it geo-partitioned with a sharding key, or replicated with a writer \
             region"
        ),
    })
}

fn resolve_sql(
    shared: &Shared,
    routing: &crate::config::Loaded,
    sql: &str,
    bind: Option<&shahrah_protocol::messages::BindParameters<'_>>,
    in_transaction: bool,
    wrote: &mut std::collections::HashMap<String, Wrote>,
) -> Outcome {
    let analysis = match shared.cache.analyse(sql, &routing.policy) {
        Ok(analysis) => analysis,
        Err(cause) => {
            if shahrah_sql::analysis::touches_sharded(sql, &routing.policy) {
                warn!(%cause, "a statement shahrah cannot analyse names a sharded table");
                return Outcome::Refuse {
                    code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message: format!(
                        "shahrah could not work out how to route this statement ({cause}), and \
                         it names a sharded table, so answering from one shard would be a guess"
                    ),
                };
            }
            debug!(%cause, "statement did not analyse");
            return Outcome::Anywhere(Intent::Write);
        }
    };

    crate::metrics::Counters::bump(&shared.counters.statements);
    if let Some(refusal) = undeclared_table(&analysis, routing) {
        crate::metrics::Counters::bump(&shared.counters.refused);
        return refusal;
    }

    let intent = match analysis.access {
        shahrah_sql::analysis::Access::Read if !in_transaction => Intent::Read,
        _ => Intent::Write,
    };

    match &analysis.routing {
        shahrah_sql::analysis::Routing::Pinned { shard } => {
            let Some(physical) = shahrah_routing::shard::PhysicalShard::from_number(*shard) else {
                return Outcome::Refuse {
                    code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message: format!("a hint named shard {shard}, which is not a shard number"),
                };
            };
            match shahrah_routing::router::route_to_shard(&routing.topology, physical, intent) {
                Ok(decision) => {
                    info!(
                        shard = decision.physical.number(),
                        endpoint = %decision.address,
                        by_hint = true,
                        "routing a statement to the shard its hint named"
                    );
                    if !shared.health.usable(&decision.address) {
                        warn!(endpoint = %decision.address, "the shard a hint named is down");
                    }
                    Outcome::Shard(decision.address)
                }
                Err(cause) => Outcome::Refuse {
                    code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message: format!("a hint named shard {shard}, which shahrah cannot use: {cause}"),
                },
            }
        }
        shahrah_sql::analysis::Routing::Single { source, key_type } => {
            let Some(logical) = logical_for_source(source, *key_type, bind) else {
                return Outcome::Refuse {
                    code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message: if analysis.by_hint {
                        "a hint gave a sharding key this table's key type cannot accept"
                            .to_owned()
                    } else {
                        "shahrah could not read the sharding key from this statement".to_owned()
                    },
                };
            };
            let home = match home_region(shared, routing, source, *key_type, bind) {
                Ok(home) => home,
                Err(outcome) => return outcome,
            };
            match route_healthy(
                &routing.topology,
                home.as_deref(),
                logical,
                intent,
                &shared.health,
                wrote,
            ) {
                Ok(decision) => {
                    shared.traffic.statement(&decision.address);
                    if let (Some(here), Some(there)) =
                        (routing.topology.region(), home.as_deref())
                        && here != there
                    {
                        crate::metrics::Counters::bump(
                            &shared.counters.routed_outside_this_region,
                        );
                    }
                    let watched = owned_key_bytes(source, *key_type, bind);
                    if shared.tracing.wanted(watched.as_deref()) {
                    info!(
                        key = %describe_key(source, bind),
                        logical = decision.logical.map(|shard| shard.get()),
                        physical = decision.physical.number(),
                        endpoint = %decision.address,
                        role = ?decision.role,
                        region = decision.region.as_deref().unwrap_or("unset"),
                        local = decision.local_region,
                        intent = intent.as_str(),
                        why = decision.why.as_str(),
                        home = home.as_deref().unwrap_or("this proxy's own region"),
                        "routed"
                    );
                    }
                    Outcome::Shard(decision.address)
                }
                Err(cause) => {
                    warn!(%cause, "routing failed");
                    Outcome::Refuse {
                        code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                        message: format!("shahrah could not route this statement: {cause}"),
                    }
                }
            }
        }
        shahrah_sql::analysis::Routing::NoShardedTable => {
            match replicated_target(shared, routing, &analysis, wrote) {
                Some(outcome) => outcome,
                None => Outcome::Anywhere(match intent {
                    Intent::Read if wrote.is_empty() => Intent::Read,
                    _ => Intent::Write,
                }),
            }
        }
        shahrah_sql::analysis::Routing::KeyMissing { table } => {
            if analysis.access != shahrah_sql::analysis::Access::Read {
                return Outcome::Refuse {
                    code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message: format!(
                        "a write to \"{table}\" without its sharding key would have to touch \
                         every shard, which shahrah refuses rather than doing partially"
                    ),
                };
            }
            if routing.policy.broadcasts(table) {
                if analysis.mergeable {
                    {
                        crate::metrics::Counters::bump(&shared.counters.broadcasts);
                        Outcome::Broadcast
                    }
                } else {
                    Outcome::Refuse {
                        code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                        message: format!(
                            "a broadcast read of \"{table}\" with GROUP BY, HAVING, DISTINCT, \
                             OFFSET or a computed column cannot be merged across shards without \
                             answering wrongly, so shahrah refuses it"
                        ),
                    }
                }
            } else {
                Outcome::Refuse {
                    code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message: format!(
                        "a read of \"{table}\" without its sharding key would only see one \
                         shard; add the key, or let the table opt into broadcast"
                    ),
                }
            }
        }
        shahrah_sql::analysis::Routing::Unsupported(why) => Outcome::Refuse {
            code: SQLSTATE_FEATURE_NOT_SUPPORTED,
            message: format!("shahrah cannot route this statement: {why}"),
        },
        shahrah_sql::analysis::Routing::EveryShard { what, instead } => {
            let shards = routing.topology.shards().len();
            if shards > 1 {
                Outcome::Refuse {
                    code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message: format!("{what}. This cluster has {shards} shards. {instead}"),
                }
            } else {
                Outcome::Anywhere(Intent::Write)
            }
        }
    }
}

fn owned_key_bytes(
    source: &shahrah_sql::analysis::KeySource,
    key_type: shahrah_sql::analysis::KeyType,
    bind: Option<&shahrah_protocol::messages::BindParameters<'_>>,
) -> Option<Vec<u8>> {
    owned_for_source(source, key_type, bind).map(|owned| owned.bytes())
}

fn logical_for_source(
    source: &shahrah_sql::analysis::KeySource,
    key_type: shahrah_sql::analysis::KeyType,
    bind: Option<&shahrah_protocol::messages::BindParameters<'_>>,
) -> Option<LogicalShard> {
    let owned = owned_for_source(source, key_type, bind)?;
    Some(match &owned {
        shahrah_sql::analysis::OwnedKey::Int(value) => {
            logical_for(ShardKey::Int(*value), HashVersion::V1)
        }
        shahrah_sql::analysis::OwnedKey::Text(value) => {
            logical_for(ShardKey::Text(value), HashVersion::V1)
        }
        shahrah_sql::analysis::OwnedKey::Uuid(value) => {
            logical_for(ShardKey::Uuid(*value), HashVersion::V1)
        }
        shahrah_sql::analysis::OwnedKey::Bytes(value) => {
            logical_for(ShardKey::Bytes(value), HashVersion::V1)
        }
    })
}

fn owned_for_source(
    source: &shahrah_sql::analysis::KeySource,
    key_type: shahrah_sql::analysis::KeyType,
    bind: Option<&shahrah_protocol::messages::BindParameters<'_>>,
) -> Option<shahrah_sql::analysis::OwnedKey> {
    let owned = match source {
        shahrah_sql::analysis::KeySource::Int(value) => {
            shahrah_sql::analysis::OwnedKey::Int(*value)
        }
        shahrah_sql::analysis::KeySource::Text(value) => {
            match shahrah_sql::analysis::canonical(
                Some(value.as_bytes()),
                shahrah_sql::analysis::FORMAT_TEXT,
                key_type,
            ) {
                Ok(owned) => owned,
                Err(cause) => {
                    debug!(%cause, "literal key is not usable");
                    return None;
                }
            }
        }
        shahrah_sql::analysis::KeySource::Parameter(number) => {
            let bind = bind?;
            let index = usize::from(number.checked_sub(1)?);
            let raw = bind.values.get(index).copied().flatten();
            match shahrah_sql::analysis::canonical(raw, bind.format_for(index), key_type) {
                Ok(owned) => owned,
                Err(cause) => {
                    debug!(%cause, parameter = number, "bound key is not usable");
                    return None;
                }
            }
        }
    };
    Some(owned)
}

fn anywhere_healthy(
    topology: &shahrah_routing::topology::Topology,
    health: &crate::health::Health,
    intent: Intent,
) -> String {
    let usable = |address: &str| health.usable(address);
    shahrah_routing::router::anywhere(topology, intent, &usable)
        .map_or_else(String::new, |decision| decision.address)
}

#[derive(Debug, Clone, Copy)]
struct Wrote {
    at: std::time::Instant,
    target: Option<u64>,
}

fn caught_up(health: &crate::health::Health, origin: &str, copy: &str, wrote: &mut Wrote) -> bool {
    if wrote.target.is_none() {
        let Some((position, seen)) = health.position(origin) else {
            return false;
        };
        if seen <= wrote.at {
            return false;
        }
        wrote.target = Some(position);
    }
    let Some(target) = wrote.target else {
        return false;
    };
    let Some((position, seen)) = health.position(copy) else {
        return false;
    };
    seen > wrote.at && position >= target
}

fn replicated_target(
    shared: &Shared,
    routing: &crate::config::Loaded,
    analysis: &shahrah_sql::analysis::Analysis,
    wrote: &mut std::collections::HashMap<String, Wrote>,
) -> Option<Outcome> {
    let table = analysis.classes.iter().find_map(|(name, class)| {
        (*class == Some(shahrah_sql::analysis::TableClass::Replicated)).then_some(name.as_str())
    })?;

    let writing = analysis.access != shahrah_sql::analysis::Access::Read;
    let region = if writing {
        match routing.policy.writer_region(table) {
            Some(region) => Some(region.to_owned()),
            None => {
                return Some(Outcome::Refuse {
                    code: SQLSTATE_FEATURE_NOT_SUPPORTED,
                    message: format!(
                        "\"{table}\" is replicated but names no writer region, so shahrah has \
                         nowhere safe to send a write"
                    ),
                })
            }
        }
    } else {
        routing.topology.region().map(str::to_owned)
    };

    let Some(shard) = origin_shard(&routing.topology, region.as_deref()) else {
        return Some(Outcome::Refuse {
            code: SQLSTATE_FEATURE_NOT_SUPPORTED,
            message: format!(
                "\"{table}\" is replicated but this topology places no shard in region \"{}\"",
                region.as_deref().unwrap_or("<none>")
            ),
        });
    };

    let origin = origin_shard(&routing.topology, routing.policy.writer_region(table))
        .map(|shard| shard.primary.address.clone());
    if writing {
        wrote.insert(
            table.to_owned(),
            Wrote {
                at: std::time::Instant::now(),
                target: None,
            },
        );
    }
    let endpoint = if writing {
        shard.primary.address.clone()
    } else if let (Some(origin), Some(seen)) = (origin.as_deref(), wrote.get_mut(table)) {
        let local = shard.primary.address.clone();
        if local != origin && !caught_up(&shared.health, origin, &local, seen) {
            info!(
                table,
                origin,
                "this session wrote to a replicated table and the local copy has not caught up, \
                 so the read goes to the writer region rather than return an older row"
            );
            origin.to_owned()
        } else {
            if local == origin {
                wrote.remove(table);
            }
            local
        }
    } else {
        shard
            .replicas
            .iter()
            .find(|replica| replica.region.as_deref() == region.as_deref())
            .map_or_else(|| shard.primary.address.clone(), |replica| replica.address.clone())
    };
    if !shared.health.usable(&endpoint) {
        warn!(%endpoint, table, "the copy of a replicated table shahrah wanted is down");
    }
    info!(
        table,
        region = region.as_deref().unwrap_or("-"),
        endpoint = %endpoint,
        writing,
        "routing a replicated table"
    );
    Some(Outcome::Shard(endpoint))
}

fn origin_shard<'a>(
    topology: &'a shahrah_routing::topology::Topology,
    region: Option<&str>,
) -> Option<&'a shahrah_routing::topology::Shard> {
    topology
        .shards()
        .iter()
        .filter(|shard| region.is_none() || shard.region.as_deref() == region)
        .min_by_key(|shard| shard.id.number())
}

fn home_region(
    shared: &Shared,
    routing: &crate::config::Loaded,
    source: &shahrah_sql::analysis::KeySource,
    key_type: shahrah_sql::analysis::KeyType,
    bind: Option<&shahrah_protocol::messages::BindParameters<'_>>,
) -> Result<Option<String>, Outcome> {
    if routing.topology.placed_regions().len() < 2 {
        return Ok(routing.topology.region().map(str::to_owned));
    }
    let Some(key) = canonical_bytes(source, key_type, bind) else {
        return Err(Outcome::Refuse {
            code: SQLSTATE_FEATURE_NOT_SUPPORTED,
            message: "shahrah could not read this statement's key well enough to ask where its \
                      rows live"
                .to_owned(),
        });
    };
    if let Some(arrived) = routing.topology.region() {
        shared.relocations.saw(&key, arrived);
    }
    match shared.directory.cached(&key) {
        Some(shahrah_routing::directory::Known::Home(region)) => Ok(Some(region.to_string())),
        Some(shahrah_routing::directory::Known::Unplaced) => Err(Outcome::Refuse {
            code: SQLSTATE_FEATURE_NOT_SUPPORTED,
            message: "this key has no home region in the directory, and with more than one \
                      region shahrah will not choose one for it"
                .to_owned(),
        }),
        None => {
            shared.directory.record_miss();
            Err(Outcome::NeedsDirectory(key))
        }
    }
}

fn canonical_bytes(
    source: &shahrah_sql::analysis::KeySource,
    key_type: shahrah_sql::analysis::KeyType,
    bind: Option<&shahrah_protocol::messages::BindParameters<'_>>,
) -> Option<Vec<u8>> {
    let owned = owned_for_source(source, key_type, bind)?;
    Some(match owned {
        shahrah_sql::analysis::OwnedKey::Int(value) => value.to_le_bytes().to_vec(),
        shahrah_sql::analysis::OwnedKey::Uuid(value) => value.to_vec(),
        shahrah_sql::analysis::OwnedKey::Bytes(value) => value,
        shahrah_sql::analysis::OwnedKey::Text(value) => value.into_bytes(),
    })
}

fn route_healthy(
    topology: &shahrah_routing::topology::Topology,
    region: Option<&str>,
    logical: shahrah_hash::shard::LogicalShard,
    intent: Intent,
    health: &crate::health::Health,
    wrote: &mut std::collections::HashMap<String, Wrote>,
) -> Result<shahrah_routing::router::Decision, shahrah_routing::router::RouteError> {
    let primary = shahrah_routing::router::route_in(topology, region, logical, Intent::Write)?;
    if intent == Intent::Write {
        wrote.insert(
            primary.address.clone(),
            Wrote {
                at: std::time::Instant::now(),
                target: None,
            },
        );
    }

    let decision = shahrah_routing::router::route_in(topology, region, logical, intent)?;
    if intent == Intent::Read
        && decision.address != primary.address
        && let Some(behind) = health.too_far_behind(&primary.address, &decision.address)
        && health.usable(&primary.address)
    {
        warn!(
            replica = %decision.address,
            primary = %primary.address,
            behind,
            "this replica is further behind its primary than the read bound, so the read goes \
             to the primary instead"
        );
        return Ok(primary);
    }
    if intent == Intent::Read && decision.address != primary.address {
        let stale = match wrote.get_mut(&primary.address) {
            Some(seen) => !caught_up(health, &primary.address, &decision.address, seen),
            None => false,
        };
        if stale {
            info!(
                replica = %decision.address,
                primary = %primary.address,
                "this session wrote to this shard and the replica has not caught up, so the \
                 read goes to the primary rather than return an older row"
            );
            if health.usable(&primary.address) {
                return Ok(primary);
            }
        } else {
            wrote.remove(&primary.address);
        }
    }
    if health.usable(&decision.address) {
        return Ok(decision);
    }
    if intent == Intent::Read {
        let fallback = shahrah_routing::router::route_in(topology, region, logical, Intent::Write)?;
        if health.usable(&fallback.address) {
            warn!(
                unhealthy = %decision.address,
                using = %fallback.address,
                "the preferred replica is down, reading from the primary instead"
            );
            return Ok(fallback);
        }
    }
    if health.is_draining(&decision.address) {
        return Err(shahrah_routing::router::RouteError::Draining {
            endpoint: decision.address.clone(),
        });
    }
    warn!(
        endpoint = %decision.address,
        "the chosen endpoint is marked down and there is no healthy alternative"
    );
    Ok(decision)
}

fn describe_key(
    source: &shahrah_sql::analysis::KeySource,
    bind: Option<&shahrah_protocol::messages::BindParameters<'_>>,
) -> String {
    match source {
        shahrah_sql::analysis::KeySource::Int(value) => format!("literal {value}"),
        shahrah_sql::analysis::KeySource::Text(value) => format!("literal {value:?}"),
        shahrah_sql::analysis::KeySource::Parameter(number) => {
            let format = bind
                .and_then(|bind| {
                    usize::from(number.checked_sub(1)?)
                        .checked_add(0)
                        .map(|index| bind.format_for(index))
                })
                .map_or("unbound", |code| {
                    if code == shahrah_sql::analysis::FORMAT_BINARY {
                        "binary"
                    } else {
                        "text"
                    }
                });
            format!("parameter ${number} in {format} format")
        }
    }
}

type Shapes = std::collections::HashMap<Vec<u8>, (String, Vec<u8>)>;

fn statement_types(body: &[u8], shapes: &Shapes) -> Vec<u8> {
    shahrah_protocol::messages::parse_bind(body)
        .ok()
        .and_then(|bind| shapes.get(bind.statement).map(|(_sql, types)| types.clone()))
        .unwrap_or_default()
}

fn statement_text(tag: u8, body: &[u8], shapes: &Shapes) -> Option<String> {
    match tag {
        shahrah_protocol::messages::TAG_QUERY => {
            let mut reader = Reader::new(body);
            reader
                .cstring()
                .ok()
                .map(|raw| String::from_utf8_lossy(raw).into_owned())
        }
        shahrah_protocol::messages::TAG_BIND => shahrah_protocol::messages::parse_bind(body)
            .ok()
            .and_then(|bind| shapes.get(bind.statement).map(|(sql, _types)| sql.clone())),
        shahrah_protocol::messages::TAG_PARSE => {
            shahrah_protocol::messages::parse_sql(body)
                .ok()
                .map(|raw| String::from_utf8_lossy(raw).into_owned())
        }
        _ => None,
    }
}

fn opens_with(sql: &str, word: &str) -> bool {
    sql.get(..word.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(word))
}

fn begins_transaction(sql: &str) -> bool {
    let trimmed = sql.trim_start();
    opens_with(trimmed, "BEGIN") || opens_with(trimmed, "START TRANSACTION")
}

fn carries_only_a_begin(sql: &str) -> bool {
    begins_transaction(sql) && shahrah_sql::analysis::one_statement(sql)
}

fn carries_only_an_end(sql: &str) -> bool {
    ends_transaction(sql) && shahrah_sql::analysis::one_statement(sql)
}

fn end_tag(sql: &str) -> &'static str {
    let trimmed = sql.trim_start();
    if opens_with(trimmed, "ROLLBACK") || opens_with(trimmed, "ABORT") {
        "ROLLBACK"
    } else {
        "COMMIT"
    }
}

fn ends_transaction(sql: &str) -> bool {
    let trimmed = sql.trim_start();
    opens_with(trimmed, "COMMIT")
        || opens_with(trimmed, "ROLLBACK")
        || opens_with(trimmed, "END")
        || opens_with(trimmed, "ABORT")
}

async fn rollback_and_release(mut lease: Lease, deep: bool) -> Result<(), SessionError> {
    let backend = lease.connection()?;
    let _rows = backend.simple_query("ROLLBACK").await;
    if deep {
        lease.release_deep().await;
    } else {
        lease.release().await;
    }
    Ok(())
}

async fn refuse_statement(
    client: &mut Connection,
    scratch: &mut Writer,
    code: &[u8],
    message: &[u8],
    simple: bool,
    status: u8,
) -> Result<(), SessionError> {
    scratch.clear();
    error_response(scratch, SEVERITY_ERROR, code, message)?;
    if simple {
        ready_for_query(scratch, status)?;
    }
    client.write_all(scratch.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

pub fn warm_for_role(shared: &Shared, database: &str, user: &str) {
    if shared.warm_per_shard == 0 {
        return;
    }
    {
        let mut warmed = shared
            .warmed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !warmed.insert(format!("{database}\u{1}{user}")) {
            return;
        }
    }
    let loaded = shared.routing.load();
    let Some(routing) = loaded.as_deref() else {
        return;
    };
    let targets: Vec<String> = routing
        .topology
        .shards()
        .iter()
        .map(|shard| shard.primary.address.clone())
        .collect();
    let pool = Arc::clone(&shared.pool);
    let database = database.to_owned();
    let user = user.to_owned();
    let wanted = shared.warm_per_shard;
    tokio::spawn(async move {
        let mut opened = 0usize;
        for address in &targets {
            match pool.warm(address, &database, Some(&user), wanted).await {
                Ok(count) => opened = opened.saturating_add(count),
                Err(cause) => debug!(endpoint = %address, %cause, "could not warm this shard"),
            }
        }
        info!(
            user,
            connections = opened,
            shards = targets.len(),
            "opened connections for this role so its next region costs no handshake"
        );
    });
}

async fn look_up_home(
    shared: &Shared,
    key: &[u8],
    database: &str,
) -> Result<(), SessionError> {
    let loaded = shared.routing.load();
    let Some(routing) = loaded.as_deref() else {
        return Err(SessionError::PoolClosed);
    };
    let logical = shahrah_hash::shard::LogicalShard::of(
        shahrah_hash::key::ShardKey::Bytes(key),
        HashVersion::V1,
    );
    let decision = shahrah_routing::router::route_in(
        &routing.topology,
        routing.topology.region(),
        logical,
        Intent::Write,
    )
    .map_err(|cause| SessionError::Tls(cause.to_string()))?;

    let mut lease = match shared.pool.acquire(&decision.address, database, None).await {
        Ok(lease) => lease,
        Err(cause) => {
            shared.directory.record_lookup(true);
            return Err(cause);
        }
    };
    let sql = shared.directory.statement_for(key);
    let answered = match lease.connection() {
        Ok(backend) => backend.collect_query(&sql).await,
        Err(cause) => Err(cause),
    };
    match &answered {
        Ok(_rows) => lease.release().await,
        Err(_cause) => lease.discard(),
    }
    let collected = match answered {
        Ok(collected) => collected,
        Err(cause) => {
            shared.directory.record_lookup(true);
            return Err(cause);
        }
    };
    if let Some(failure) = collected.failure {
        shared.directory.record_lookup(true);
        return Err(failure);
    }
    shared.directory.record_lookup(false);
    let home = match collected.rows.first() {
        Some(row) => shahrah_protocol::messages::data_row_fields(row.get(5..).unwrap_or(&[]))?
            .first()
            .and_then(Option::as_ref)
            .map(|value| String::from_utf8_lossy(value).into_owned()),
        None => None,
    };
    debug!(
        looked_up = %decision.address,
        home = home.as_deref().unwrap_or("<unplaced>"),
        "the directory answered where this key lives"
    );
    shared.directory.remember(key, home.as_deref());
    Ok(())
}

const fn decides_the_shard(tag: u8) -> bool {
    matches!(
        tag,
        shahrah_protocol::messages::TAG_BIND | shahrah_protocol::messages::TAG_QUERY
    )
}

async fn open_lease(
    shared: &Shared,
    address: &str,
    database: &str,
    user: &str,
    pending_begin: &mut Option<String>,
    decides: &bool,
    held: &mut Option<crate::pool::Held>,
) -> Result<Lease, SessionError> {
    let known = match held.take() {
        Some(known) if known.is(address, database, Some(user)) => known,
        _ => shared.pool.held(address, database, Some(user)),
    };
    let mut lease = shared.pool.acquire_held(&known, address, Some(user)).await?;
    *held = Some(known);
    if *decides
        && let Some(opening) = pending_begin.as_deref()
    {
        lease.connection()?.simple_query(opening).await?;
        *pending_begin = None;
    }
    Ok(lease)
}

#[allow(clippy::too_many_arguments)]
async fn report_backend_loss(
    client: &mut Connection,
    scratch: &mut Writer,
    health: &crate::health::Health,
    cause: &SessionError,
    simple: bool,
    held: &mut Option<Lease>,
    held_address: &mut String,
    statements: &mut Statements,
    in_transaction: &mut bool,
    poisoned: &mut bool,
    skip_until_sync: &mut bool,
) -> Result<(), SessionError> {
    let pressure = matches!(cause, SessionError::PoolBusy { .. });
    if pressure {
        warn!(endpoint = %held_address, %cause, "the pool for this endpoint is at its limit");
    } else {
        warn!(endpoint = %held_address, %cause, "backend connection lost, the session survives");
        if !held_address.is_empty() {
            health.observed_failure(held_address, &cause.to_string());
        }
    }
    if let Some(lease) = held.take() {
        lease.discard();
    }
    held_address.clear();
    statements.clear_in_flight();
    let status = if *in_transaction {
        *poisoned = true;
        TRANSACTION_FAILED
    } else {
        TRANSACTION_IDLE
    };
    let (code, message) = if pressure {
        (
            shahrah_protocol::messages::SQLSTATE_TOO_MANY_CONNECTIONS,
            cause.to_string(),
        )
    } else {
        (
            SQLSTATE_CONNECTION_FAILURE,
            format!("the backend serving this statement was lost: {cause}"),
        )
    };
    refuse_statement(client, scratch, code, message.as_bytes(), simple, status).await?;
    if !simple {
        *skip_until_sync = true;
    }
    Ok(())
}

fn extended_request(
    sql: &str,
    bind_body: &[u8],
    param_types: &[u8],
) -> Result<Vec<u8>, SessionError> {
    let mut reader = Reader::new(bind_body);
    let _portal = reader.cstring()?;
    let _statement = reader.cstring()?;
    let tail = reader.remaining();

    let mut writer =
        Writer::with_capacity(sql.len().saturating_add(bind_body.len()).saturating_add(48));
    writer.begin(shahrah_protocol::messages::TAG_PARSE)?;
    writer.cstring(b"");
    writer.cstring(sql.as_bytes());
    if param_types.is_empty() {
        writer.i16(0);
    } else {
        writer.bytes(param_types);
    }
    writer.end()?;

    writer.begin(shahrah_protocol::messages::TAG_BIND)?;
    writer.cstring(b"");
    writer.cstring(b"");
    writer.bytes(tail);
    writer.end()?;

    writer.begin(shahrah_protocol::messages::TAG_DESCRIBE)?;
    writer.u8(b'P');
    writer.cstring(b"");
    writer.end()?;

    writer.begin(shahrah_protocol::messages::TAG_EXECUTE)?;
    writer.cstring(b"");
    writer.i32(0);
    writer.end()?;

    writer.begin(shahrah_protocol::messages::TAG_SYNC)?;
    writer.end()?;
    Ok(writer.as_bytes().to_vec())
}

async fn collation_ranks(
    shared: &Shared,
    routing: &crate::config::Loaded,
    database: &str,
    user: &str,
    parts: &[crate::connection::Collected],
    analysis: &shahrah_sql::analysis::Analysis,
) -> crate::broadcast::TextOrder {
    if analysis.order_by.is_empty() {
        return crate::broadcast::TextOrder::Bytes;
    }
    let description = parts.iter().find_map(|part| part.description.as_deref());
    let columns = crate::broadcast::text_columns_in_order(&analysis.order_by, description);
    if columns.is_empty() {
        return crate::broadcast::TextOrder::Bytes;
    }

    let mut distinct: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for index in columns {
        for part in parts {
            for value in crate::broadcast::values_at(&part.rows, index) {
                distinct.insert(value);
            }
        }
    }
    if distinct.len() > crate::broadcast::MAX_RANKED_VALUES {
        warn!(
            values = distinct.len(),
            cap = crate::broadcast::MAX_RANKED_VALUES,
            "too many distinct text values to have a shard order them"
        );
        return crate::broadcast::TextOrder::Unavailable;
    }
    if distinct.is_empty() {
        return crate::broadcast::TextOrder::Bytes;
    }

    let values: Vec<Vec<u8>> = distinct.into_iter().collect();
    let mut sql = String::with_capacity(values.len().saturating_mul(16).saturating_add(64));
    sql.push_str("select v from (values ");
    for (position, value) in values.iter().enumerate() {
        if position > 0 {
            sql.push(',');
        }
        sql.push_str("('");
        sql.push_str(&String::from_utf8_lossy(value).replace('\'', "''"));
        sql.push_str("')");
    }
    sql.push_str(") t(v) order by v");

    let address = anywhere_healthy(&routing.topology, &shared.health, Intent::Read);
    if address.is_empty() {
        return crate::broadcast::TextOrder::Unavailable;
    }
    let Ok(mut lease) = shared.pool.acquire(&address, database, Some(user)).await else {
        return crate::broadcast::TextOrder::Unavailable;
    };
    let answered = match lease.connection() {
        Ok(backend) => backend.collect_query(&sql).await,
        Err(_cause) => {
            lease.discard();
            return crate::broadcast::TextOrder::Unavailable;
        }
    };
    lease.release().await;
    let Ok(collected) = answered else {
        return crate::broadcast::TextOrder::Unavailable;
    };

    let mut ranks = std::collections::HashMap::with_capacity(values.len());
    for (position, row) in collected.rows.iter().enumerate() {
        let Ok(fields) = shahrah_protocol::messages::data_row_fields(row.get(5..).unwrap_or(&[]))
        else {
            return crate::broadcast::TextOrder::Unavailable;
        };
        if let Some(Some(value)) = fields.first() {
            ranks.insert(value.clone(), i64::try_from(position).unwrap_or(i64::MAX));
        }
    }
    if ranks.len() != values.len() {
        warn!(
            asked = values.len(),
            got = ranks.len(),
            "a shard did not order every value shahrah sent it"
        );
        return crate::broadcast::TextOrder::Unavailable;
    }
    debug!(values = ranks.len(), "a shard supplied the collation order");
    crate::broadcast::TextOrder::Ranked(ranks)
}

async fn sorts_text_by_bytes(lease: &mut Lease) -> bool {
    let Ok(backend) = lease.connection() else {
        return false;
    };
    let Ok(rows) = backend
        .collect_query("select current_setting('lc_collate')")
        .await
    else {
        return false;
    };
    let name = rows
        .rows
        .first()
        .and_then(|row| row.get(5..))
        .and_then(|body| shahrah_protocol::messages::data_row_fields(body).ok())
        .and_then(|fields| fields.first().and_then(Clone::clone))
        .map(|value| String::from_utf8_lossy(&value).into_owned())
        .unwrap_or_default();
    let byte_ordered = matches!(name.as_str(), "C" | "POSIX" | "C.UTF-8" | "C.utf8");
    info!(
        collation = %name,
        byte_ordered,
        "the shards' text collation decides whether shahrah can merge an ORDER BY on text"
    );
    byte_ordered
}

#[allow(clippy::too_many_arguments)]
async fn run_broadcast(
    client: &mut Connection,
    scratch: &mut Writer,
    shared: &Shared,
    database: &str,
    user: &str,
    sql: &str,
    bind_body: Option<(&[u8], &[u8])>,
    framing: crate::broadcast::Framing,
    settings: &[(String, String)],
) -> Result<(), SessionError> {
    let loaded = shared.routing.load();
    let Some(routing) = loaded.as_deref() else {
        return Ok(());
    };
    let analysis = match shared.cache.analyse(sql, &routing.policy) {
        Ok(analysis) => analysis,
        Err(_) => return Ok(()),
    };

    let mut collation: Option<bool> = shared.text_sorts_by_bytes.get().copied();
    let mut parts = Vec::with_capacity(routing.topology.len());
    let mut failure = None;
    for shard in routing.topology.shards() {
        let address = shard.primary.address.clone();
        let mut lease = match shared.pool.acquire(&address, database, Some(user)).await {
            Ok(lease) => lease,
            Err(cause) => {
                shared.health.observed_failure(&address, &cause.to_string());
                failure = Some(cause);
                break;
            }
        };
        replay_settings(&mut lease, settings).await;
        let outcome = match bind_body {
            Some((body, types)) => match extended_request(sql, body, types) {
                Ok(request) => match lease.connection() {
                    Ok(backend) => backend.collect_raw(&request).await,
                    Err(cause) => Err(cause),
                },
                Err(cause) => Err(cause),
            },
            None => match lease.connection() {
                Ok(backend) => backend.collect_query(sql).await,
                Err(cause) => Err(cause),
            },
        };
        if collation.is_none() && outcome.is_ok() {
            collation = Some(sorts_text_by_bytes(&mut lease).await);
        }
        if outcome.is_err() {
            shared
                .health
                .observed_failure(&address, "a broadcast read lost this shard");
            shared.traffic.error(&address);
            lease.discard();
        } else if settings.is_empty() {
            lease.release().await;
        } else {
            lease.release_deep().await;
        }
        match outcome {
            Ok(part) => parts.push(part),
            Err(cause) => {
                failure = Some(cause);
                break;
            }
        }
    }

    if let Some(cause) = failure {
        warn!(%cause, "a shard failed during a broadcast read");
        return refuse_statement(
            client,
            scratch,
            SQLSTATE_CONNECTION_FAILURE,
            format!(
                "a broadcast read could not reach every shard, so shahrah has no complete \
                 answer to give: {cause}"
            )
            .as_bytes(),
            !framing.is_extended(),
            TRANSACTION_IDLE,
        )
        .await;
    }

    let shards = parts.len();
    let byte_ordered = *shared.text_sorts_by_bytes.get_or_init(|| collation.unwrap_or(false));
    let text_order = if byte_ordered {
        crate::broadcast::TextOrder::Bytes
    } else {
        collation_ranks(shared, routing, database, user, &parts, &analysis).await
    };
    match crate::broadcast::merge(parts, &analysis, scratch, framing, &text_order) {
        Ok(merged) => {
            debug!(shards, "broadcast read merged");
            client.write_all(&merged.bytes).await?;
            client.flush().await?;
            Ok(())
        }
        Err(cause) => {
            warn!(%cause, "broadcast merge refused");
            refuse_statement(
                client,
                scratch,
                SQLSTATE_FEATURE_NOT_SUPPORTED,
                cause.to_string().as_bytes(),
                !framing.is_extended(),
                TRANSACTION_IDLE,
            )
            .await
        }
    }
}

async fn forward_cancel(route: &BackendRoute, shared: &Shared) -> Result<(), SessionError> {
    let mut backend =
        Connection::connect(&route.address, shared.backend_tls, &shared.connector).await?;
    let mut writer = Writer::with_capacity(16);
    writer.begin_untagged()?;
    writer.i32(CANCEL_REQUEST_CODE);
    writer.i32(route.key.process_id);
    writer.i32(route.key.secret_key);
    writer.end()?;
    backend.write_all(writer.as_bytes()).await?;
    backend.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        begins_transaction, carries_only_a_begin, carries_only_an_end, end_tag, ends_transaction,
    };

    #[test]
    fn a_transaction_opens_whatever_case_it_is_written_in() {
        assert!(begins_transaction("BEGIN"));
        assert!(begins_transaction("begin"));
        assert!(begins_transaction("  \n\t begin transaction"));
        assert!(begins_transaction("Start Transaction"));
        assert!(!begins_transaction("select 1"));
        assert!(!begins_transaction("beg"));
        assert!(!begins_transaction(""));
    }

    #[test]
    fn a_transaction_closes_whatever_case_it_is_written_in() {
        assert!(ends_transaction("COMMIT"));
        assert!(ends_transaction("commit"));
        assert!(ends_transaction("  rollback"));
        assert!(ends_transaction("End"));
        assert!(ends_transaction("abort"));
        assert!(!ends_transaction("select 1"));
        assert!(!ends_transaction(""));
    }

    #[test]
    fn a_transaction_that_asks_for_more_than_a_bare_begin_is_still_a_begin() {
        assert!(carries_only_a_begin("begin isolation level serializable"));
        assert!(carries_only_a_begin("BEGIN READ ONLY"));
        assert!(carries_only_a_begin("begin transaction isolation level repeatable read"));
        assert!(carries_only_a_begin(
            "start transaction isolation level serializable, read only, deferrable"
        ));
    }

    #[test]
    fn an_end_is_reported_as_the_verb_the_client_used() {
        assert_eq!(end_tag("commit"), "COMMIT");
        assert_eq!(end_tag("  COMMIT"), "COMMIT");
        assert_eq!(end_tag("end"), "COMMIT");
        assert_eq!(end_tag("End Transaction"), "COMMIT");
        assert_eq!(end_tag("rollback"), "ROLLBACK");
        assert_eq!(end_tag("  ROLLBACK"), "ROLLBACK");
        assert_eq!(end_tag("abort"), "ROLLBACK");
        assert_eq!(end_tag("Abort Transaction"), "ROLLBACK");
    }

    #[test]
    fn a_frame_carrying_more_than_a_begin_is_not_answered_as_one() {
        assert!(carries_only_a_begin("begin"));
        assert!(carries_only_a_begin("begin;"));
        assert!(!carries_only_a_begin("begin; select 42; commit"));
        assert!(!carries_only_an_end("commit; select 42"));
        assert!(carries_only_an_end("commit"));
    }
}
