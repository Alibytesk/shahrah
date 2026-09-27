use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::connection::Connection;
use crate::tls::BackendTls;

pub const PROBE_INTERVAL: Duration = Duration::from_secs(2);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
pub const READ_LAG_LIMIT_ENV: &str = "SHAHRAH_REPLICA_LAG_LIMIT";
pub const DEFAULT_READ_LAG_LIMIT_MIB: usize = 256;
pub const BYTES_PER_MIB: usize = 1024 * 1024;
pub const FAILURES_TO_DOWN: u32 = 3;
pub const SUCCESSES_TO_UP: u32 = 3;
pub const RECENT_PROBES: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Up,
    Suspect,
    Down,
    Recovering,
}

impl State {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Suspect => "suspect",
            Self::Down => "down",
            Self::Recovering => "recovering",
        }
    }

    #[must_use]
    pub const fn usable(self) -> bool {
        matches!(self, Self::Up | Self::Suspect)
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub state: State,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_error: Option<String>,
    pub lag_bytes: Option<i64>,
    pub is_replica: bool,
    pub in_recovery: Option<bool>,
    pub role_matches_config: bool,
    pub last_probe: Option<Instant>,
    pub probes: u64,
    pub position: Option<u64>,
    pub position_seen: Option<Instant>,
    pub drained: bool,
    pub connect_micros: Option<u64>,
    pub query_micros: Option<u64>,
    pub recent_micros: Vec<u64>,
}

impl Endpoint {
    #[must_use]
    pub fn typical_micros(&self) -> Option<u64> {
        if self.recent_micros.is_empty() {
            return None;
        }
        let mut sorted = self.recent_micros.clone();
        sorted.sort_unstable();
        sorted.get(sorted.len().checked_div(2)?).copied()
    }

    #[must_use]
    pub fn worst_micros(&self) -> Option<u64> {
        self.recent_micros.iter().max().copied()
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            state: State::Up,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_error: None,
            lag_bytes: None,
            is_replica: false,
            in_recovery: None,
            role_matches_config: true,
            last_probe: None,
            probes: 0,
            position: None,
            position_seen: None,
            drained: false,
            connect_micros: None,
            query_micros: None,
            recent_micros: Vec::new(),
        }
    }
}

#[derive(Default)]
pub struct Health {
    endpoints: arc_swap::ArcSwap<HashMap<String, Endpoint>>,
    writing: Mutex<()>,
    pool: std::sync::OnceLock<Arc<crate::pool::Pool>>,
    read_lag_limit: Option<i64>,
    reads_moved_off_lag: std::sync::atomic::AtomicU64,
}

struct Settled {
    before: State,
    now: State,
    reason: String,
    was_matching: bool,
    matching: bool,
    recovering: Option<bool>,
}

impl Health {
    #[must_use]
    pub fn new(read_lag_limit: Option<i64>) -> Arc<Self> {
        Arc::new(Self {
            read_lag_limit,
            ..Self::default()
        })
    }

    #[must_use]
    pub const fn read_lag_limit(&self) -> Option<i64> {
        self.read_lag_limit
    }

    #[must_use]
    pub fn behind(&self, primary: &str, replica: &str) -> Option<i64> {
        let endpoints = self.endpoints.load();
        let ahead = endpoints.get(primary)?.position?;
        let here = endpoints.get(replica)?.position?;
        Some(i64::try_from(ahead.saturating_sub(here)).unwrap_or(i64::MAX))
    }

    #[must_use]
    pub fn too_far_behind(&self, primary: &str, replica: &str) -> Option<i64> {
        let limit = self.read_lag_limit?;
        let behind = self.behind(primary, replica)?;
        if behind <= limit {
            return None;
        }
        self.reads_moved_off_lag
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(behind)
    }

    #[must_use]
    pub fn reads_moved_off_lag(&self) -> u64 {
        self.reads_moved_off_lag
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn attach_pool(&self, pool: Arc<crate::pool::Pool>) {
        let _existing = self.pool.set(pool);
    }

    fn change<R>(&self, address: &str, edit: impl FnOnce(&mut Endpoint) -> R) -> R {
        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.endpoints.load();
        let mut next = (**current).clone();
        let outcome = edit(next.entry(address.to_owned()).or_default());
        self.endpoints.store(Arc::new(next));
        outcome
    }

    fn evict(&self, address: &str) {
        if let Some(pool) = self.pool.get() {
            let dropped = pool.evict(address);
            if dropped > 0 {
                warn!(
                    address,
                    dropped, "dropped the idle connections held for a down endpoint"
                );
            }
        }
    }

    #[must_use]
    pub fn usable(&self, address: &str) -> bool {
        self.endpoints
            .load()
            .get(address)
            .is_none_or(|endpoint| endpoint.state.usable() && !endpoint.drained)
    }

    #[must_use]
    pub fn is_draining(&self, address: &str) -> bool {
        self.endpoints
            .load()
            .get(address)
            .is_some_and(|endpoint| endpoint.drained)
    }

    pub fn set_drained(&self, address: &str, drained: bool) {
        self.change(address, |endpoint| endpoint.drained = drained);
        if drained {
            self.evict(address);
            warn!(
                address,
                "this endpoint is draining: it takes no new work, and the transactions already \
                 on it finish where they are"
            );
        } else {
            info!(address, "this endpoint takes work again");
        }
    }

    #[must_use]
    pub fn position(&self, address: &str) -> Option<(u64, Instant)> {
        let endpoints = self.endpoints.load();
        let found = endpoints.get(address)?;
        Some((found.position?, found.position_seen?))
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, Endpoint)> {
        let mut rows: Vec<(String, Endpoint)> = self
            .endpoints
            .load()
            .iter()
            .map(|(address, endpoint)| (address.clone(), endpoint.clone()))
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }

    pub fn observed_failure(&self, address: &str, cause: &str) {
        let Some(before) = self.change(address, |endpoint| {
            if endpoint.state == State::Down {
                return None;
            }
            let before = endpoint.state;
            endpoint.state = State::Down;
            endpoint.consecutive_successes = 0;
            endpoint.consecutive_failures = FAILURES_TO_DOWN;
            endpoint.last_error = Some(cause.to_owned());
            Some(before)
        }) else {
            return;
        };
        self.evict(address);
        warn!(
            address,
            from = before.as_str(),
            reason = cause,
            "the data path lost this endpoint, marking it down without waiting for a probe"
        );
    }

    fn record(&self, address: &str, is_replica: bool, outcome: Result<Observation, String>) {
        let settled = self.change(address, |endpoint| {
            endpoint.is_replica = is_replica;
            endpoint.last_probe = Some(Instant::now());
            endpoint.probes = endpoint.probes.saturating_add(1);

            let before = endpoint.state;
            let was_matching = endpoint.role_matches_config;
            match outcome {
                Ok(observation) => {
                    endpoint.lag_bytes = observation.lag;
                    endpoint.connect_micros = Some(observation.connect_micros);
                    endpoint.query_micros = Some(observation.query_micros);
                    if endpoint.recent_micros.len() >= RECENT_PROBES {
                        let _oldest = endpoint.recent_micros.remove(0);
                    }
                    endpoint.recent_micros.push(observation.query_micros);
                    if let Some(position) = observation.position {
                        endpoint.position = Some(position);
                        endpoint.position_seen = Some(Instant::now());
                    }
                    endpoint.in_recovery = Some(observation.in_recovery);
                    endpoint.role_matches_config = observation.in_recovery == is_replica;
                    endpoint.last_error = None;
                    endpoint.consecutive_failures = 0;
                    endpoint.consecutive_successes =
                        endpoint.consecutive_successes.saturating_add(1);
                    endpoint.state = match endpoint.state {
                        State::Up => State::Up,
                        State::Suspect => State::Up,
                        State::Down | State::Recovering => {
                            if endpoint.consecutive_successes >= SUCCESSES_TO_UP {
                                State::Up
                            } else {
                                State::Recovering
                            }
                        }
                    };
                }
                Err(cause) => {
                    endpoint.last_error = Some(cause);
                    endpoint.query_micros = None;
                    endpoint.consecutive_successes = 0;
                    endpoint.consecutive_failures =
                        endpoint.consecutive_failures.saturating_add(1);
                    endpoint.state = if endpoint.consecutive_failures >= FAILURES_TO_DOWN {
                        State::Down
                    } else {
                        State::Suspect
                    };
                }
            }

            Settled {
                before,
                now: endpoint.state,
                reason: endpoint.last_error.clone().unwrap_or_default(),
                was_matching,
                matching: endpoint.role_matches_config,
                recovering: endpoint.in_recovery,
            }
        });

        if settled.matching != settled.was_matching && !settled.matching {
            warn!(
                address,
                configured = if is_replica { "replica" } else { "primary" },
                reports_in_recovery = ?settled.recovering,
                "this endpoint no longer plays the role the topology gives it; \
                 a promotion or demotion happened outside shahrah. shahrah observes \
                 and never promotes (R5), so the topology has to be corrected"
            );
        } else if settled.matching != settled.was_matching {
            info!(address, "the endpoint's role matches the topology again");
        }

        if settled.now != settled.before {
            if settled.now == State::Up {
                info!(address, from = settled.before.as_str(), "endpoint recovered");
            } else {
                if settled.now == State::Down {
                    self.evict(address);
                }
                warn!(
                    address,
                    from = settled.before.as_str(),
                    to = settled.now.as_str(),
                    reason = settled.reason,
                    "endpoint state changed"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub in_recovery: bool,
    pub lag: Option<i64>,
    pub position: Option<u64>,
    pub connect_micros: u64,
    pub query_micros: u64,
}

pub struct Prober {
    pub health: Arc<Health>,
    pub routing: Arc<arc_swap::ArcSwapOption<crate::config::Loaded>>,
    pub connector: TlsConnector,
    pub backend_tls: BackendTls,
    pub user: String,
    pub password: String,
    pub database: String,
}

impl Prober {
    pub async fn run(self) {
        let shared = Arc::new(self);
        loop {
            let targets = shared.targets();
            let mut cycle = tokio::task::JoinSet::new();
            for (address, is_replica) in targets {
                let prober = Arc::clone(&shared);
                cycle.spawn(async move {
                    let outcome = prober.probe(&address, is_replica).await;
                    prober.health.record(&address, is_replica, outcome);
                });
            }
            while cycle.join_next().await.is_some() {}
            tokio::time::sleep(PROBE_INTERVAL).await;
        }
    }

    fn targets(&self) -> Vec<(String, bool)> {
        let loaded = self.routing.load();
        let Some(routing) = loaded.as_deref() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for shard in routing.topology.shards() {
            out.push((shard.primary.address.clone(), false));
            for replica in &shard.replicas {
                out.push((replica.address.clone(), true));
            }
        }
        out
    }

    async fn probe(&self, address: &str, is_replica: bool) -> Result<Observation, String> {
        let _configured = is_replica;
        let sql = "SELECT pg_is_in_recovery()::text, \
                   COALESCE(pg_wal_lsn_diff(pg_last_wal_receive_lsn(), \
                   pg_last_wal_replay_lsn()), 0)::text, \
                   COALESCE(( \
                     CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn() \
                          ELSE pg_current_wal_lsn() END \
                   ) - '0/0'::pg_lsn, 0)::text, \
                   COALESCE((SELECT MIN(latest_end_lsn) - '0/0'::pg_lsn \
                             FROM pg_stat_subscription \
                             WHERE latest_end_lsn IS NOT NULL), -1)::text";

        let attempt = tokio::time::timeout(PROBE_TIMEOUT, async {
            let opening = std::time::Instant::now();
            let mut connection = Connection::open_backend(
                address,
                self.backend_tls,
                &self.connector,
                &self.user,
                &self.password,
                &self.database,
                None,
            )
            .await?;
            let opened = opening.elapsed();
            let asking = std::time::Instant::now();
            let rows = connection.simple_query(sql).await?;
            Ok::<_, crate::error::SessionError>((rows, opened, asking.elapsed()))
        })
        .await;

        match attempt {
            Err(_elapsed) => Err(format!("probe timed out after {PROBE_TIMEOUT:?}")),
            Ok(Err(cause)) => Err(cause.to_string()),
            Ok(Ok((rows, opened, asked))) => {
                let field = |index: usize| {
                    rows.first()
                        .and_then(|row| row.get(index))
                        .and_then(Option::as_ref)
                        .and_then(|raw| core::str::from_utf8(raw).ok())
                        .map(str::trim)
                };
                let own = field(2).and_then(|text| text.parse::<u64>().ok());
                let subscribed = field(3)
                    .and_then(|text| text.parse::<i64>().ok())
                    .filter(|value| *value >= 0)
                    .and_then(|value| u64::try_from(value).ok());
                Ok(Observation {
                    in_recovery: matches!(field(0), Some("t" | "true" | "on" | "1")),
                    lag: field(1).and_then(|text| text.parse::<i64>().ok()),
                    position: subscribed.or(own),
                    connect_micros: u64::try_from(opened.as_micros()).unwrap_or(u64::MAX),
                    query_micros: u64::try_from(asked.as_micros()).unwrap_or(u64::MAX),
                })
            }
        }
    }
}
