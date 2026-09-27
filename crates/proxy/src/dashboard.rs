use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::Serialize;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;

use crate::session::Shared;

pub const PAGE: &str = include_str!("dashboard.html");
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
pub const HISTORY: usize = 180;
const WEBSOCKET_MAGIC: &str = "258EAFA5-E914-47DA-95CA-5AB0DC85B39A";
const FRAME_TEXT: u8 = 0x81;
const OPCODE_CLOSE: u8 = 0x8;
const MAX_CLIENT_FRAME: usize = 4096;

#[derive(Serialize, Clone, Copy, Default)]
pub struct Point {
    pub at: u64,
    pub statements: u64,
    pub refused: u64,
    pub broadcasts: u64,
    pub outside: u64,
    pub relocations: u64,
    pub waits: u64,
    pub errors: u64,
    pub served: u64,
    pub directory_hits: u64,
    pub directory_misses: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub idle: u64,
    pub opened: u64,
}

#[derive(Serialize)]
struct EndpointView {
    address: String,
    region: String,
    shard: Option<u16>,
    state: String,
    role: String,
    role_matches: bool,
    failures: u32,
    behind: Option<i64>,
    probes: u64,
    last_error: Option<String>,
    latency_us: Option<u64>,
    typical_us: Option<u64>,
    worst_us: Option<u64>,
    connect_us: Option<u64>,
    statements: u64,
    errors: u64,
    idle: usize,
    opened: u64,
}

#[derive(Serialize)]
struct ShardView {
    number: u16,
    region: String,
    primary: String,
    replicas: Vec<String>,
    logical: u32,
}

#[derive(Serialize)]
struct AlertView {
    name: String,
    subject: String,
    detail: String,
}

#[derive(Serialize)]
struct PeerView {
    name: String,
    reachable: bool,
    endpoints: usize,
}

#[derive(Serialize)]
pub struct Snapshot {
    full: bool,
    region: String,
    at: u64,
    uptime: u64,
    alerts: Vec<AlertView>,
    endpoints: Vec<EndpointView>,
    shards: Vec<ShardView>,
    peers: Vec<PeerView>,
    totals: Point,
    history: Vec<Point>,
    directory_entries: usize,
    cache_entries: usize,
    logical_shards: u32,
    regions: Vec<String>,
}

pub struct Sampler {
    points: Mutex<VecDeque<Point>>,
    started: SystemTime,
}

impl Default for Sampler {
    fn default() -> Self {
        Self {
            points: Mutex::new(VecDeque::with_capacity(HISTORY)),
            started: SystemTime::now(),
        }
    }
}

impl Sampler {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn record(&self, point: Point) {
        let mut points = self.points.lock().unwrap_or_else(PoisonError::into_inner);
        if points.len() >= HISTORY {
            let _oldest = points.pop_front();
        }
        points.push_back(point);
    }

    fn newest(&self) -> Vec<Point> {
        self.points
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .back()
            .copied()
            .into_iter()
            .collect()
    }

    fn recent(&self) -> Vec<Point> {
        self.points
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect()
    }

    fn uptime(&self) -> u64 {
        self.started
            .elapsed()
            .map_or(0, |gone| gone.as_secs())
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |gone| u64::try_from(gone.as_millis()).unwrap_or(u64::MAX))
}

fn totals(shared: &Shared) -> Point {
    let counters = &shared.counters;
    let directory = shared.directory.counts();
    let cache = shared.cache.counts();
    let mut errors = 0u64;
    let mut served = 0u64;
    for (_address, statements, failed) in shared.traffic.snapshot() {
        served = served.saturating_add(statements);
        errors = errors.saturating_add(failed);
    }
    let mut idle = 0u64;
    let mut opened = 0u64;
    for (_key, waiting, made) in shared.pool.stats() {
        idle = idle.saturating_add(u64::try_from(waiting).unwrap_or(0));
        opened = opened.saturating_add(made);
    }
    Point {
        at: now_millis(),
        statements: counters.statements.load(Ordering::Relaxed),
        refused: counters.refused.load(Ordering::Relaxed),
        broadcasts: counters.broadcasts.load(Ordering::Relaxed),
        outside: counters.routed_outside_this_region.load(Ordering::Relaxed),
        relocations: counters.relocations.load(Ordering::Relaxed),
        waits: counters.directory_waits.load(Ordering::Relaxed),
        errors,
        served,
        directory_hits: directory.hits.saturating_add(directory.negative_hits),
        directory_misses: directory.misses,
        cache_hits: cache.hits,
        cache_misses: cache.misses,
        idle,
        opened,
    }
}

fn shard_of(shared: &Shared, address: &str) -> (Option<u16>, String) {
    let loaded = shared.routing.load();
    let Some(routing) = loaded.as_deref() else {
        return (None, String::new());
    };
    for shard in routing.topology.shards() {
        let mine = shard.primary.address == address
            || shard.replicas.iter().any(|one| one.address == address);
        if mine {
            let region = shard
                .region
                .clone()
                .or_else(|| shard.primary.region.clone())
                .unwrap_or_default();
            return (Some(shard.id.number()), region);
        }
    }
    (None, String::new())
}

pub async fn snapshot(shared: &Shared, sampler: &Sampler) -> Snapshot {
    build(shared, sampler, true).await
}

async fn build(shared: &Shared, sampler: &Sampler, full: bool) -> Snapshot {
    let loaded = shared.routing.load();
    let region = loaded
        .as_deref()
        .and_then(|routing| routing.topology.region().map(str::to_owned))
        .unwrap_or_else(|| "unset".to_owned());

    let mut traffic = std::collections::HashMap::new();
    for (address, statements, errors) in shared.traffic.snapshot() {
        let _seen = traffic.insert(address, (statements, errors));
    }
    let mut pooled: std::collections::HashMap<String, (usize, u64)> =
        std::collections::HashMap::new();
    for (key, idle, opened) in shared.pool.stats() {
        let address = key.split(' ').next().unwrap_or(&key).to_owned();
        let seen = pooled.entry(address).or_default();
        seen.0 = seen.0.saturating_add(idle);
        seen.1 = seen.1.saturating_add(opened);
    }

    let mut endpoints = Vec::new();
    for (address, endpoint) in shared.health.snapshot() {
        let (shard, region_of) = shard_of(shared, &address);
        let (statements, errors) = traffic.get(&address).copied().unwrap_or((0, 0));
        let (idle, opened) = pooled.get(&address).copied().unwrap_or((0, 0));
        endpoints.push(EndpointView {
            state: if endpoint.drained {
                "draining".to_owned()
            } else {
                endpoint.state.as_str().to_owned()
            },
            role: if endpoint.is_replica { "replica" } else { "primary" }.to_owned(),
            role_matches: endpoint.role_matches_config,
            failures: endpoint.consecutive_failures,
            behind: crate::admin::behind_primary(shared, &address),
            probes: endpoint.probes,
            last_error: endpoint.last_error.clone(),
            latency_us: endpoint.query_micros,
            typical_us: endpoint.typical_micros(),
            worst_us: endpoint.worst_micros(),
            connect_us: endpoint.connect_micros,
            region: region_of,
            shard,
            statements,
            errors,
            idle,
            opened,
            address,
        });
    }
    endpoints.sort_by(|left, right| {
        left.region
            .cmp(&right.region)
            .then(left.shard.cmp(&right.shard))
            .then(left.address.cmp(&right.address))
    });

    let mut shards = Vec::new();
    let mut regions: Vec<String> = Vec::new();
    let mut logical_shards = 0u32;
    if let Some(routing) = loaded.as_deref() {
        for shard in routing.topology.shards() {
            let region_of = shard
                .region
                .clone()
                .or_else(|| shard.primary.region.clone())
                .unwrap_or_default();
            if !region_of.is_empty() && !regions.contains(&region_of) {
                regions.push(region_of.clone());
            }
            shards.push(ShardView {
                number: shard.id.number(),
                region: region_of,
                primary: shard.primary.address.clone(),
                replicas: shard.replicas.iter().map(|one| one.address.clone()).collect(),
                logical: 0,
            });
        }
        logical_shards = u32::try_from(routing.topology.len()).unwrap_or(0);
    }

    let alerts = crate::admin::alerts(shared)
        .into_iter()
        .map(|alert| AlertView {
            name: alert.name.to_owned(),
            subject: alert.subject,
            detail: alert.detail,
        })
        .collect();

    let mut peers = Vec::new();
    for (name, rows) in crate::admin::fleet_rows(shared, "HEALTH").await {
        peers.push(PeerView {
            reachable: !rows.is_empty(),
            endpoints: rows.len(),
            name,
        });
    }

    let directory_entries = shared.directory.counts().entries;
    let cache_entries = shared.cache.counts().entries;

    Snapshot {
        full,
        region,
        at: now_millis(),
        uptime: sampler.uptime(),
        alerts,
        endpoints,
        shards,
        peers,
        totals: totals(shared),
        history: if full { sampler.recent() } else { sampler.newest() },
        directory_entries,
        cache_entries,
        logical_shards,
        regions,
    }
}

pub fn sample_forever(shared: Shared, sampler: Arc<Sampler>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let _tick = ticker.tick().await;
            sampler.record(totals(&shared));
        }
    });
}

#[must_use]
pub fn accept_key(offered: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(offered.trim().as_bytes());
    hasher.update(WEBSOCKET_MAGIC.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

#[must_use]
pub fn text_frame(payload: &str) -> Vec<u8> {
    let bytes = payload.as_bytes();
    let mut frame = Vec::with_capacity(bytes.len().saturating_add(10));
    frame.push(FRAME_TEXT);
    let width = bytes.len();
    if width < 126 {
        frame.push(u8::try_from(width).unwrap_or(125));
    } else if let Ok(short) = u16::try_from(width) {
        frame.push(126);
        frame.extend_from_slice(&short.to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&u64::try_from(width).unwrap_or(0).to_be_bytes());
    }
    frame.extend_from_slice(bytes);
    frame
}

async fn watch_for_close<S: AsyncRead + Unpin>(
    mut half: tokio::io::ReadHalf<S>,
    closed: Arc<Notify>,
) {
    loop {
        let mut head = [0u8; 2];
        if half.read_exact(&mut head).await.is_err() {
            break;
        }
        let (Some(first), Some(second)) = (head.first(), head.get(1)) else {
            break;
        };
        let opcode = first & 0x0f;
        let masked = second & 0x80 != 0;
        let width = match second & 0x7f {
            126 => {
                let mut wide = [0u8; 2];
                if half.read_exact(&mut wide).await.is_err() {
                    break;
                }
                usize::from(u16::from_be_bytes(wide))
            }
            127 => break,
            other => usize::from(other),
        };
        if width > MAX_CLIENT_FRAME {
            break;
        }
        if masked {
            let mut key = [0u8; 4];
            if half.read_exact(&mut key).await.is_err() {
                break;
            }
        }
        let mut body = vec![0u8; width];
        if half.read_exact(&mut body).await.is_err() {
            break;
        }
        if opcode == OPCODE_CLOSE {
            break;
        }
    }
    closed.notify_waiters();
}

pub async fn live<S>(
    mut stream: S,
    shared: &Shared,
    sampler: &Arc<Sampler>,
    offered: &str,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(offered)
    );
    stream.write_all(handshake.as_bytes()).await?;
    stream.flush().await?;

    let (reading, mut writing) = tokio::io::split(stream);
    let closed = Arc::new(Notify::new());
    let telling = Arc::clone(&closed);
    let watcher = tokio::spawn(async move { watch_for_close(reading, telling).await });

    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut first = true;
    let outcome = loop {
        let taken = build(shared, sampler, first).await;
        first = false;
        let Ok(rendered) = serde_json::to_string(&taken) else {
            break Ok(());
        };
        if let Err(cause) = writing.write_all(&text_frame(&rendered)).await {
            break Err(cause);
        }
        if let Err(cause) = writing.flush().await {
            break Err(cause);
        }
        tokio::select! {
            _tick = ticker.tick() => {}
            () = closed.notified() => break Ok(()),
        }
    };
    watcher.abort();
    outcome
}

#[cfg(test)]
mod tests {
    use super::{accept_key, text_frame};

    #[test]
    fn the_handshake_agrees_with_an_independent_sha1() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "CPWQ34XzCEpqkRbr9NJspuqlRjs=",
            "a browser checks this byte for byte and hangs up when it disagrees"
        );
        assert_eq!(
            accept_key("x3JJHMbDL1EzLkh9GBhXDw=="),
            "i96KWX1QWITmGXcbpOgRvG5Qatg="
        );
    }

    #[test]
    fn the_handshake_ignores_the_whitespace_a_header_may_carry() {
        assert_eq!(
            accept_key("  dGhlIHNhbXBsZSBub25jZQ==\r\n"),
            accept_key("dGhlIHNhbXBsZSBub25jZQ==")
        );
    }

    #[test]
    fn a_short_frame_carries_its_length_in_one_byte() {
        let frame = text_frame("hi");
        assert_eq!(frame.first(), Some(&0x81));
        assert_eq!(frame.get(1), Some(&2));
        assert_eq!(frame.get(2..), Some(b"hi".as_slice()));
    }

    #[test]
    fn a_frame_over_125_bytes_grows_a_two_byte_length() {
        let body = "x".repeat(200);
        let frame = text_frame(&body);
        assert_eq!(frame.get(1), Some(&126));
        assert_eq!(frame.get(2..4), Some([0u8, 200].as_slice()));
        assert_eq!(frame.len(), 204);
    }
}
