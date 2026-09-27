use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::connection::Connection;
use crate::error::SessionError;
use crate::tls::BackendTls;

pub const WAIT_ENV: &str = "SHAHRAH_POOL_WAIT";
pub const DEFAULT_WAIT: Duration = Duration::from_secs(10);
pub const WAIT_BOUNDS_MICROS: [u64; 8] =
    [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 1_000_000];

pub const RESET_ON_RELEASE: &str = "";
pub const DEEP_RESET_ON_RELEASE: &str = "DISCARD ALL";
pub const RESET_ENV: &str = "SHAHRAH_RESET_QUERY";

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub user: String,
    pub password: String,
    pub max_per_database: usize,
    pub idle_timeout: Duration,
    pub wait: Option<Duration>,
    pub backend_tls: BackendTls,
}

#[derive(Debug, Default)]
pub struct Waited {
    buckets: [AtomicU64; 8],
    over: AtomicU64,
    micros: AtomicU64,
    waits: AtomicU64,
}

impl Waited {
    fn record(&self, took: Duration) {
        let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        self.waits.fetch_add(1, Ordering::Relaxed);
        self.micros.fetch_add(micros, Ordering::Relaxed);
        let mut placed = false;
        for (at, bound) in WAIT_BOUNDS_MICROS.iter().enumerate() {
            if micros <= *bound
                && let Some(bucket) = self.buckets.get(at)
            {
                bucket.fetch_add(1, Ordering::Relaxed);
                placed = true;
                break;
            }
        }
        if !placed {
            self.over.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn read(&self) -> ([u64; 8], u64, u64, u64) {
        let mut counts = [0u64; 8];
        for (at, bucket) in self.buckets.iter().enumerate() {
            if let Some(slot) = counts.get_mut(at) {
                *slot = bucket.load(Ordering::Relaxed);
            }
        }
        (
            counts,
            self.over.load(Ordering::Relaxed),
            self.micros.load(Ordering::Relaxed),
            self.waits.load(Ordering::Relaxed),
        )
    }
}

struct Idle {
    connection: Connection,
    since: Instant,
}

struct Slot {
    name: String,
    idle: Mutex<Vec<Idle>>,
    permits: Arc<Semaphore>,
    opened: AtomicU64,
}

impl Slot {
    fn database(&self) -> &str {
        let mut fields = self.name.split('\u{1}');
        let _address = fields.next();
        fields.next().unwrap_or("")
    }

    fn take(&self, timeout: Duration) -> Option<Connection> {
        let mut stale: Vec<Connection> = Vec::new();
        let mut taken = None;
        {
            let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
            while let Some(entry) = idle.pop() {
                if entry.since.elapsed() < timeout {
                    taken = Some(entry.connection);
                    break;
                }
                stale.push(entry.connection);
            }
        }
        drop(stale);
        taken
    }
}

pub struct Pool {
    config: PoolConfig,
    connector: TlsConnector,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    parameters: Mutex<Vec<(String, String)>>,
    reset: String,
    waited: Waited,
}

impl Pool {
    #[must_use]
    pub fn new(config: PoolConfig, connector: TlsConnector) -> Arc<Self> {
        Arc::new(Self {
            config,
            connector,
            slots: Mutex::new(HashMap::new()),
            parameters: Mutex::new(Vec::new()),
            reset: std::env::var(RESET_ENV).unwrap_or_else(|_| RESET_ON_RELEASE.to_owned()),
            waited: Waited::default(),
        })
    }

    #[must_use]
    pub const fn waited(&self) -> &Waited {
        &self.waited
    }

    async fn permit_for(
        &self,
        slot: &Arc<Slot>,
        address: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, SessionError> {
        match Arc::clone(&slot.permits).try_acquire_owned() {
            Ok(permit) => return Ok(permit),
            Err(tokio::sync::TryAcquireError::Closed) => return Err(SessionError::PoolClosed),
            Err(tokio::sync::TryAcquireError::NoPermits) => {}
        }
        let began = Instant::now();
        let waiting = Arc::clone(&slot.permits).acquire_owned();
        let outcome = match self.config.wait {
            Some(limit) => tokio::time::timeout(limit, waiting).await,
            None => Ok(waiting.await),
        };
        let took = began.elapsed();
        self.waited.record(took);
        match outcome {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_closed)) => Err(SessionError::PoolClosed),
            Err(_elapsed) => Err(SessionError::PoolBusy {
                address: address.to_owned(),
                seconds: took.as_secs_f64(),
                limit: self.config.max_per_database,
            }),
        }
    }

    fn slot(&self, key: &str) -> Arc<Slot> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = slots.get(key) {
            return Arc::clone(found);
        }
        let fresh = Arc::new(Slot {
            name: key.to_owned(),
            idle: Mutex::new(Vec::new()),
            permits: Arc::new(Semaphore::new(self.config.max_per_database)),
            opened: AtomicU64::new(0),
        });
        slots.insert(key.to_owned(), Arc::clone(&fresh));
        fresh
    }

    #[must_use]
    pub fn held(&self, address: &str, database: &str, role: Option<&str>) -> Held {
        let key = pool_key(address, database, role);
        Held {
            slot: self.slot(key.as_str()),
        }
    }

    pub async fn acquire(
        self: &Arc<Self>,
        address: &str,
        database: &str,
        role: Option<&str>,
    ) -> Result<Lease, SessionError> {
        let key = pool_key(address, database, role);
        let slot = self.slot(key.as_str());
        let permit = self.permit_for(&slot, address).await?;

        if let Some(connection) = slot.take(self.config.idle_timeout) {
            return Ok(Lease {
                pool: Arc::clone(self),
                slot,
                connection: Some(connection),
                permit: Some(permit),
            });
        }

        let connection = Connection::open_backend(
            address,
            self.config.backend_tls,
            &self.connector,
            &self.config.user,
            &self.config.password,
            key.database(),
            role,
        )
        .await?;

        {
            let mut parameters = self
                .parameters
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if parameters.is_empty() {
                *parameters = connection.parameters().to_vec();
            }
        }
        slot.opened.fetch_add(1, Ordering::Relaxed);
        debug!(database = key.as_str(), "opened a backend connection");
        Ok(Lease {
            pool: Arc::clone(self),
            slot,
            connection: Some(connection),
            permit: Some(permit),
        })
    }

    pub async fn warm(
        self: &Arc<Self>,
        address: &str,
        database: &str,
        role: Option<&str>,
        wanted: usize,
    ) -> Result<usize, SessionError> {
        let key = pool_key(address, database, role);
        let already = {
            let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
            slots.get(key.as_str()).map_or(0, |slot| {
                slot.idle.lock().unwrap_or_else(PoisonError::into_inner).len()
            })
        };
        let mut opened = 0;
        let mut held = Vec::new();
        while already.saturating_add(opened) < wanted.min(self.config.max_per_database) {
            let lease = self.acquire(address, database, role).await?;
            held.push(lease);
            opened = opened.saturating_add(1);
        }
        for lease in held {
            lease.release().await;
        }
        Ok(opened)
    }

    pub fn evict(&self, address: &str) -> usize {
        let wanted: Vec<Arc<Slot>> = {
            let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
            slots
                .iter()
                .filter(|(key, _slot)| key.split('\u{1}').next() == Some(address))
                .map(|(_key, slot)| Arc::clone(slot))
                .collect()
        };
        let mut dropped: usize = 0;
        let mut stale: Vec<Idle> = Vec::new();
        for slot in wanted {
            let mut idle = slot.idle.lock().unwrap_or_else(PoisonError::into_inner);
            dropped = dropped.saturating_add(idle.len());
            stale.append(&mut idle);
        }
        drop(stale);
        dropped
    }

    #[must_use]
    pub fn parameters(&self) -> Vec<(String, String)> {
        self.parameters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn stats(&self) -> Vec<(String, usize, u64)> {
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let mut rows: Vec<(String, usize, u64)> = slots
            .values()
            .map(|slot| {
                (
                    slot.name.replace('\u{1}', " / "),
                    slot.idle.lock().unwrap_or_else(PoisonError::into_inner).len(),
                    slot.opened.load(Ordering::Relaxed),
                )
            })
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }
}

#[derive(Clone)]
pub struct Held {
    slot: Arc<Slot>,
}

impl Held {
    #[must_use]
    pub fn is(&self, address: &str, database: &str, role: Option<&str>) -> bool {
        let key = pool_key(address, database, role);
        self.slot.name == key.as_str()
    }
}

impl Pool {
    pub async fn acquire_held(
        self: &Arc<Self>,
        held: &Held,
        address: &str,
        role: Option<&str>,
    ) -> Result<Lease, SessionError> {
        let slot = Arc::clone(&held.slot);
        let permit = self.permit_for(&slot, address).await?;

        if let Some(connection) = slot.take(self.config.idle_timeout) {
            return Ok(Lease {
                pool: Arc::clone(self),
                slot,
                connection: Some(connection),
                permit: Some(permit),
            });
        }

        let connection = Connection::open_backend(
            address,
            self.config.backend_tls,
            &self.connector,
            &self.config.user,
            &self.config.password,
            slot.database(),
            role,
        )
        .await?;

        {
            let mut parameters = self
                .parameters
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if parameters.is_empty() {
                *parameters = connection.parameters().to_vec();
            }
        }

        slot.opened.fetch_add(1, Ordering::Relaxed);
        debug!(database = slot.name.as_str(), "opened a backend connection");
        Ok(Lease {
            pool: Arc::clone(self),
            slot,
            connection: Some(connection),
            permit: Some(permit),
        })
    }
}

pub struct Lease {
    pool: Arc<Pool>,
    slot: Arc<Slot>,
    connection: Option<Connection>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Lease {
    pub fn connection(&mut self) -> Result<&mut Connection, SessionError> {
        self.connection.as_mut().ok_or(SessionError::PoolClosed)
    }

    pub async fn release(mut self) {
        let reset = self.pool.reset.clone();
        self.return_with(&reset, false).await;
    }

    pub async fn release_deep(mut self) {
        self.return_with(DEEP_RESET_ON_RELEASE, true).await;
    }

    async fn return_with(&mut self, reset: &str, forget_prepared: bool) {
        let Some(mut connection) = self.connection.take() else {
            return;
        };
        let mut outcome = if reset.is_empty() {
            Ok(Vec::new())
        } else {
            connection.simple_query(reset).await
        };

        if outcome.is_ok() && !reset.is_empty() {
            if let Err(cause) = connection.pin_rendering().await {
                outcome = Err(cause);
            } else if connection.role().is_some()
                && let Err(cause) = connection.assume_role().await
            {
                outcome = Err(cause);
            }
        }

        match outcome {
            Ok(_rows) => {
                if forget_prepared {
                    connection.forget_prepared();
                }
                self.slot
                    .idle
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(Idle {
                        connection,
                        since: Instant::now(),
                    });
            }
            Err(cause) => {
                warn!(%cause, "discarding a backend connection that would not reset");
            }
        }
        drop(self.permit.take());
    }

    pub fn discard(mut self) {
        self.connection.take();
        drop(self.permit.take());
    }
}

#[derive(Debug, Clone)]
pub struct PoolKey {
    joined: String,
    database_start: usize,
    database_len: usize,
}

impl PoolKey {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.joined
    }

    #[must_use]
    pub fn database(&self) -> &str {
        let end = self.database_start.saturating_add(self.database_len);
        self.joined.get(self.database_start..end).unwrap_or("")
    }
}

#[must_use]
pub fn pool_key(address: &str, database: &str, role: Option<&str>) -> PoolKey {
    let width = address
        .len()
        .saturating_add(database.len())
        .saturating_add(role.map_or(0, str::len))
        .saturating_add(2);
    let mut joined = String::with_capacity(width);
    joined.push_str(address);
    joined.push('\u{1}');
    joined.push_str(database);
    if let Some(role) = role {
        joined.push('\u{1}');
        joined.push_str(role);
    }
    PoolKey {
        joined,
        database_start: address.len().saturating_add(1),
        database_len: database.len(),
    }
}
