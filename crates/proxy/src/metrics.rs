use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::session::Shared;

pub const LISTEN_ENV: &str = "SHAHRAH_METRICS_LISTEN";

#[derive(Default)]
pub struct Endpoint {
    pub statements: AtomicU64,
    pub errors: AtomicU64,
}

#[derive(Default)]
pub struct Traffic {
    by_endpoint: arc_swap::ArcSwap<std::collections::HashMap<String, std::sync::Arc<Endpoint>>>,
}

impl Traffic {
    pub fn learn(&self, endpoints: &[String]) {
        let current = self.by_endpoint.load();
        let mut next = (**current).clone();
        for address in endpoints {
            next.entry(address.clone())
                .or_insert_with(|| std::sync::Arc::new(Endpoint::default()));
        }
        self.by_endpoint.store(std::sync::Arc::new(next));
    }

    pub fn statement(&self, endpoint: &str) {
        if let Some(found) = self.by_endpoint.load().get(endpoint) {
            found.statements.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn error(&self, endpoint: &str) {
        if let Some(found) = self.by_endpoint.load().get(endpoint) {
            found.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, u64, u64)> {
        let mut rows: Vec<(String, u64, u64)> = self
            .by_endpoint
            .load()
            .iter()
            .map(|(address, counts)| {
                (
                    address.clone(),
                    counts.statements.load(Ordering::Relaxed),
                    counts.errors.load(Ordering::Relaxed),
                )
            })
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }
}

pub const SAMPLE_ENV: &str = "SHAHRAH_TRACE_SAMPLE";

const HEAD_BYTES: u64 = 8192;
const BODY_BYTES: usize = 4096;
const HEAD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
const BODY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
const TLS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
const OPEN_CONNECTIONS: usize = 256;

pub struct Tracing {
    every: AtomicU64,
    seen: AtomicU64,
    watched: std::sync::Mutex<std::collections::HashSet<Vec<u8>>>,
    traced: AtomicU64,
}

impl Default for Tracing {
    fn default() -> Self {
        let every = std::env::var(SAMPLE_ENV)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .unwrap_or(1);
        Self {
            every: AtomicU64::new(every.max(1)),
            seen: AtomicU64::new(0),
            watched: std::sync::Mutex::new(std::collections::HashSet::new()),
            traced: AtomicU64::new(0),
        }
    }
}

impl Tracing {
    #[must_use]
    pub fn wanted(&self, key: Option<&[u8]>) -> bool {
        if let Some(key) = key
            && !self
                .watched
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
            && self
                .watched
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(key)
        {
            self.traced.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        let every = self.every.load(Ordering::Relaxed).max(1);
        if every == 1 {
            self.traced.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        let at = self.seen.fetch_add(1, Ordering::Relaxed);
        let take = at.is_multiple_of(every);
        if take {
            self.traced.fetch_add(1, Ordering::Relaxed);
        }
        take
    }

    pub fn watch(&self, key: Vec<u8>) {
        self.watched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key);
    }

    pub fn unwatch_all(&self) -> usize {
        let mut held = self
            .watched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = held.len();
        held.clear();
        count
    }

    pub fn sample_every(&self, every: u64) {
        self.every.store(every.max(1), Ordering::Relaxed);
    }

    #[must_use]
    pub fn state(&self) -> (u64, usize, u64, u64) {
        (
            self.every.load(Ordering::Relaxed),
            self.watched
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            self.seen.load(Ordering::Relaxed),
            self.traced.load(Ordering::Relaxed),
        )
    }
}

#[derive(Default)]
pub struct Counters {
    pub statements: AtomicU64,
    pub refused: AtomicU64,
    pub broadcasts: AtomicU64,
    pub routed_outside_this_region: AtomicU64,
    pub relocations: AtomicU64,
    pub directory_waits: AtomicU64,
    pub clients_refused: AtomicU64,
}

impl Counters {
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn read(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

fn latency_series(out: &mut String, shared: &Shared, here: &str) {
    gauge_open(
        out,
        "shahrah_endpoint_probe_seconds",
        "how long this endpoint took to answer the health probe, median of the last 30",
    );
    for (address, endpoint) in shared.health.snapshot() {
        let Some(micros) = endpoint.typical_micros() else {
            continue;
        };
        let seconds = micros as f64 / 1_000_000.0;
        let _row = writeln!(
            out,
            "shahrah_endpoint_probe_seconds{{proxy=\"{}\",endpoint=\"{}\"}} {seconds}",
            escape(here),
            escape(&address)
        );
    }
    gauge_open(
        out,
        "shahrah_endpoint_connect_seconds",
        "how long a fresh backend connection to this endpoint took, including authentication",
    );
    for (address, endpoint) in shared.health.snapshot() {
        let Some(micros) = endpoint.connect_micros else {
            continue;
        };
        let seconds = micros as f64 / 1_000_000.0;
        let _row = writeln!(
            out,
            "shahrah_endpoint_connect_seconds{{proxy=\"{}\",endpoint=\"{}\"}} {seconds}",
            escape(here),
            escape(&address)
        );
    }
}

fn where_is(routing: Option<&crate::config::Loaded>, endpoint: &str) -> String {
    let Some(routing) = routing else {
        return String::new();
    };
    for shard in routing.topology.shards() {
        if shard.primary.address == endpoint {
            return shard
                .region
                .clone()
                .or_else(|| shard.primary.region.clone())
                .unwrap_or_default();
        }
        for replica in &shard.replicas {
            if replica.address == endpoint {
                return replica
                    .region
                    .clone()
                    .or_else(|| shard.region.clone())
                    .unwrap_or_default();
            }
        }
    }
    String::new()
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn counter(out: &mut String, name: &str, help: &str, value: u64, region: &str) {
    let _written = writeln!(out, "# HELP {name} {help}");
    let _typed = writeln!(out, "# TYPE {name} counter");
    let _row = writeln!(out, "{name}{{proxy=\"{}\"}} {value}", escape(region));
}

fn pool_wait_series(out: &mut String, shared: &Shared, region: &str) {
    let (counts, over, micros, waits) = shared.pool.waited().read();
    family(
        out,
        "shahrah_pool_wait_seconds",
        "how long a session waited for a pooled backend connection when none was free",
        "histogram",
    );
    let proxy = escape(region);
    let mut running = 0u64;
    for (at, bound) in crate::pool::WAIT_BOUNDS_MICROS.iter().enumerate() {
        running = running.saturating_add(counts.get(at).copied().unwrap_or(0));
        let edge = *bound as f64 / 1_000_000.0;
        let _row = writeln!(
            out,
            "shahrah_pool_wait_seconds_bucket{{proxy=\"{proxy}\",le=\"{edge}\"}} {running}"
        );
    }
    running = running.saturating_add(over);
    let _last = writeln!(
        out,
        "shahrah_pool_wait_seconds_bucket{{proxy=\"{proxy}\",le=\"+Inf\"}} {running}"
    );
    let seconds = micros as f64 / 1_000_000.0;
    let _sum = writeln!(out, "shahrah_pool_wait_seconds_sum{{proxy=\"{proxy}\"}} {seconds}");
    let _count = writeln!(out, "shahrah_pool_wait_seconds_count{{proxy=\"{proxy}\"}} {waits}");
}

fn family(out: &mut String, name: &str, help: &str, kind: &str) {
    let _written = writeln!(out, "# HELP {name} {help}");
    let _typed = writeln!(out, "# TYPE {name} {kind}");
}

fn gauge_open(out: &mut String, name: &str, help: &str) {
    family(out, name, help, "gauge");
}

fn counter_open(out: &mut String, name: &str, help: &str) {
    family(out, name, help, "counter");
}

#[must_use]
pub fn render(shared: &Shared) -> String {
    let loaded = shared.routing.load();
    let region = loaded
        .as_deref()
        .and_then(|routing| routing.topology.region())
        .unwrap_or("")
        .to_owned();
    let mut out = String::with_capacity(4096);

    let counters = &shared.counters;
    counter(&mut out, "shahrah_statements_total",
        "statements shahrah decided a route for", Counters::read(&counters.statements), &region);
    counter(&mut out, "shahrah_statements_refused_total",
        "statements shahrah refused rather than answer from a guess", Counters::read(&counters.refused), &region);
    counter(&mut out, "shahrah_broadcasts_total",
        "reads fanned out to every shard and merged", Counters::read(&counters.broadcasts), &region);
    counter(&mut out, "shahrah_routed_outside_region_total",
        "statements sent to a region other than this proxy's own", Counters::read(&counters.routed_outside_this_region), &region);
    counter(&mut out, "shahrah_relocations_total",
        "keys this proxy moved between regions", Counters::read(&counters.relocations), &region);
    counter(&mut out, "shahrah_directory_waits_total",
        "statements held while their key was being relocated", Counters::read(&counters.directory_waits), &region);
    counter(&mut out, "shahrah_clients_refused_total",
        "clients turned away because the connection cap was reached", Counters::read(&counters.clients_refused), &region);
    counter(&mut out, "shahrah_reads_moved_off_lagging_replica_total",
        "reads sent to the primary because the replica was past the lag bound", shared.health.reads_moved_off_lag(), &region);
    pool_wait_series(&mut out, shared, &region);

    let counts = shared.directory.counts();
    counter(&mut out, "shahrah_directory_hits_total", "home region answered from cache", counts.hits, &region);
    counter(&mut out, "shahrah_directory_misses_total", "home region not in cache", counts.misses, &region);
    counter(&mut out, "shahrah_directory_unplaced_hits_total",
        "cache answered that a key has no home", counts.negative_hits, &region);
    counter(&mut out, "shahrah_directory_lookups_total",
        "home region read from a shard", counts.lookups, &region);
    counter(&mut out, "shahrah_directory_lookup_failures_total",
        "home region could not be read", counts.failures, &region);
    counter(&mut out, "shahrah_directory_evictions_total", "cache entries dropped for room", counts.evictions, &region);
    gauge_open(&mut out, "shahrah_directory_entries", "home regions held in cache");
    let _entries = writeln!(
        out,
        "shahrah_directory_entries{{proxy=\"{}\"}} {}",
        escape(&region),
        counts.entries
    );

    let pools: Vec<(String, String, String)> = shared
        .pool
        .stats()
        .into_iter()
        .map(|(key, idle, opened)| {
            let mut parts = key.split(" / ");
            let endpoint = parts.next().unwrap_or("");
            let database = parts.next().unwrap_or("");
            let role = parts.next().unwrap_or("");
            let labels = format!(
                "proxy=\"{}\",region=\"{}\",endpoint=\"{}\",database=\"{}\",role=\"{}\"",
                escape(&region),
                escape(&where_is(loaded.as_deref(), endpoint)),
                escape(endpoint),
                escape(database),
                escape(role)
            );
            (labels, idle.to_string(), opened.to_string())
        })
        .collect();
    gauge_open(&mut out, "shahrah_pool_idle", "connections parked and ready");
    for (labels, idle, _opened) in &pools {
        let _idle = writeln!(out, "shahrah_pool_idle{{{labels}}} {idle}");
    }
    counter_open(&mut out, "shahrah_pool_opened_total", "connections this proxy has opened");
    for (labels, _idle, opened) in &pools {
        let _opened = writeln!(out, "shahrah_pool_opened_total{{{labels}}} {opened}");
    }

    let endpoints: Vec<(String, u8, Option<i64>, u64, u8)> = shared
        .health
        .snapshot()
        .into_iter()
        .map(|(address, endpoint)| {
            let kind = if endpoint.is_replica { "replica" } else { "primary" };
            let labels = format!(
                "proxy=\"{}\",region=\"{}\",endpoint=\"{}\",kind=\"{}\"",
                escape(&region),
                escape(&where_is(loaded.as_deref(), &address)),
                escape(&address),
                kind
            );
            let behind = crate::admin::behind_primary(shared, &address);
            (
                labels,
                u8::from(endpoint.state.usable() && !endpoint.drained),
                behind,
                endpoint.probes,
                u8::from(endpoint.role_matches_config),
            )
        })
        .collect();
    gauge_open(&mut out, "shahrah_endpoint_up", "1 when shahrah will send work to this endpoint");
    for (labels, up, _behind, _probes, _role) in &endpoints {
        let _up = writeln!(out, "shahrah_endpoint_up{{{labels}}} {up}");
    }
    gauge_open(&mut out, "shahrah_endpoint_behind_primary_bytes",
        "how far a replica's replayed position is behind its primary's current position");
    for (labels, _up, behind, _probes, _role) in &endpoints {
        if let Some(behind) = behind {
            let _lag = writeln!(out, "shahrah_endpoint_behind_primary_bytes{{{labels}}} {behind}");
        }
    }
    counter_open(&mut out, "shahrah_endpoint_probes_total", "health probes sent to this endpoint");
    for (labels, _up, _behind, probes, _role) in &endpoints {
        let _probes = writeln!(out, "shahrah_endpoint_probes_total{{{labels}}} {probes}");
    }
    gauge_open(&mut out, "shahrah_endpoint_role_matches", "1 when the endpoint plays the role the topology gives it");
    for (labels, _up, _behind, _probes, role) in &endpoints {
        let _role = writeln!(out, "shahrah_endpoint_role_matches{{{labels}}} {role}");
    }

    let sent: Vec<(String, u64, u64)> = shared
        .traffic
        .snapshot()
        .into_iter()
        .map(|(address, statements, errors)| {
            let labels = format!(
                "proxy=\"{}\",region=\"{}\",endpoint=\"{}\"",
                escape(&region),
                escape(&where_is(loaded.as_deref(), &address)),
                escape(&address)
            );
            (labels, statements, errors)
        })
        .collect();
    counter_open(&mut out, "shahrah_endpoint_statements_total",
        "statements this proxy sent to this endpoint");
    for (labels, statements, _errors) in &sent {
        let _sent = writeln!(out, "shahrah_endpoint_statements_total{{{labels}}} {statements}");
    }
    counter_open(&mut out, "shahrah_endpoint_errors_total",
        "statements that failed on this endpoint");
    for (labels, _statements, errors) in &sent {
        let _bad = writeln!(out, "shahrah_endpoint_errors_total{{{labels}}} {errors}");
    }

    gauge_open(&mut out, "shahrah_alert",
        "1 for each condition shahrah thinks is worth waking someone for");
    for alert in crate::admin::alerts(shared) {
        let _row = writeln!(
            out,
            "shahrah_alert{{proxy=\"{}\",alert=\"{}\",subject=\"{}\"}} 1",
            escape(&region),
            escape(alert.name),
            escape(&alert.subject)
        );
    }

    gauge_open(&mut out, "shahrah_shard_logical", "logical shards this physical shard owns in its region");
    if let Some(routing) = loaded.as_deref() {
        for shard in routing.topology.shards() {
            let placed = shard.region.as_deref().or(shard.primary.region.as_deref()).unwrap_or("");
            let owned = routing
                .topology
                .map_for(Some(placed))
                .map_or(0u32, |map| {
                    (0..=u16::MAX)
                        .filter(|index| {
                            map.get(shahrah_hash::shard::LogicalShard::from_index(*index)).number()
                                == shard.id.number()
                        })
                        .count()
                        .try_into()
                        .unwrap_or(0)
                });
            let _row = writeln!(
                out,
                "shahrah_shard_logical{{proxy=\"{}\",region=\"{}\",shard=\"{}\",\
                 endpoint=\"{}\"}} {owned}",
                escape(&region),
                escape(placed),
                shard.id.number(),
                escape(&shard.primary.address)
            );
        }
    }
    latency_series(&mut out, shared, &region);
    out
}

pub fn decoded(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    while let Some(byte) = bytes.get(at) {
        match byte {
            b'+' => out.push(b' '),
            b'%' => {
                let pair = value.get(at.saturating_add(1)..at.saturating_add(3));
                match pair.and_then(|pair| u8::from_str_radix(pair, 16).ok()) {
                    Some(decoded) => {
                        out.push(decoded);
                        at = at.saturating_add(2);
                    }
                    None => out.push(*byte),
                }
            }
            _ => out.push(*byte),
        }
        at = at.saturating_add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn key_page(shared: &Shared, table: &str, literal: &str) -> String {
    let loaded = shared.routing.load();
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut title = format!("{table} / {literal}");

    let Some(routing) = loaded.as_deref() else {
        return page(&title, &[("no topology is loaded".to_owned(), String::new())]);
    };
    let Some(key_type) = routing.policy.key_type(table) else {
        return page(
            &title,
            &[(
                "not geo-partitioned".to_owned(),
                format!("\"{table}\" declares no sharding key, so no key of it has a home"),
            )],
        );
    };
    let Ok(owned) = shahrah_sql::analysis::canonical(
        Some(literal.as_bytes()),
        shahrah_sql::analysis::FORMAT_TEXT,
        key_type,
    ) else {
        return page(
            &title,
            &[("not a usable key".to_owned(), format!("for table \"{table}\""))],
        );
    };
    let key = owned.bytes();
    let logical = shahrah_hash::shard::LogicalShard::of(
        match &owned {
            shahrah_sql::analysis::OwnedKey::Int(v) => shahrah_hash::key::ShardKey::Int(*v),
            shahrah_sql::analysis::OwnedKey::Uuid(v) => shahrah_hash::key::ShardKey::Uuid(*v),
            shahrah_sql::analysis::OwnedKey::Bytes(v) => shahrah_hash::key::ShardKey::Bytes(v),
            shahrah_sql::analysis::OwnedKey::Text(v) => shahrah_hash::key::ShardKey::Text(v),
        },
        shahrah_hash::shard::HashVersion::V1,
    );

    let (home, learned) = match shared.directory.cached(&key) {
        Some(shahrah_routing::directory::Known::Home(region)) => {
            (Some(region.to_string()), "this proxy's cache".to_owned())
        }
        Some(shahrah_routing::directory::Known::Unplaced) => {
            (None, "the cache, which holds it as unplaced".to_owned())
        }
        None => match crate::admin::ask_the_directory(shared, routing, &key, logical).await {
            Ok(Some(region)) => (Some(region), "the directory, read just now".to_owned()),
            Ok(None) => (None, "the directory, which has no row for it".to_owned()),
            Err(cause) => (None, format!("the directory could not be read: {cause}")),
        },
    };
    title = format!("{table} / {literal} — {}", home.as_deref().unwrap_or("unplaced"));

    rows.push(("home region".to_owned(), home.clone().unwrap_or_else(|| "unknown".to_owned())));
    rows.push(("shahrah learned that from".to_owned(), learned));
    rows.push(("logical shard".to_owned(), logical.get().to_string()));

    let here = routing.topology.region().unwrap_or("");
    for region in routing.topology.placed_regions() {
        let Ok(decision) = shahrah_routing::router::route_in(
            &routing.topology,
            Some(region),
            logical,
            shahrah_routing::router::Intent::Write,
        ) else {
            continue;
        };
        let mark = if Some(region) == home.as_deref() {
            " — where its rows live"
        } else {
            ""
        };
        rows.push((
            format!("in region {region}"),
            format!("shard {} at {}{mark}", decision.physical.number(), decision.address),
        ));
    }
    rows.push((
        "this proxy sits in".to_owned(),
        format!(
            "{here}{}",
            match home.as_deref() {
                Some(there) if there == here => " — the same region, so no crossing",
                Some(_) => " — a different region, so every statement crosses",
                None => "",
            }
        ),
    ));
    page(&title, &rows)
}

const DASHBOARD_STYLE: &str = "\
:root{color-scheme:light dark}\
body{font:14px/1.55 system-ui,sans-serif;margin:2rem auto;max-width:70rem;padding:0 1rem;color:#1a1a1a}\
h1{font-size:1.35rem;font-weight:600;margin:0}\
h2{font-size:1rem;font-weight:600;margin:2.2rem 0 .6rem;color:#444}\
.top{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap}\
.quiet{color:#777;font-size:.85rem}\
table{border-collapse:collapse;width:100%;margin-top:.4rem;font-variant-numeric:tabular-nums}\
th{text-align:left;font-weight:500;color:#777;font-size:.8rem;padding:.3rem .7rem;border-bottom:1px solid #ddd}\
td{padding:.42rem .7rem;border-bottom:1px solid #eee}\
tr:last-child td{border-bottom:none}\
.region{font-weight:600}\
.here{color:#0a7d33}\
.up{color:#0a7d33}.down{color:#c0392b;font-weight:600}.drain{color:#b8860b}\
.alert{background:#fdf0ee;border:1px solid #e8c4bd;border-radius:6px;padding:.7rem 1rem;margin:.5rem 0}\
.calm{color:#0a7d33;padding:.7rem 0}\
form{margin:.6rem 0 0}\
input,button{font:inherit;padding:.35rem .6rem;border:1px solid #ccc;border-radius:5px;background:transparent;color:inherit}\
button{cursor:pointer}\
@media(prefers-color-scheme:dark){\
body{background:#141414;color:#e8e8e8}h2{color:#bbb}.quiet{color:#8a8a8a}\
th{color:#999;border-color:#333}td{border-color:#262626}\
.alert{background:#2a1a18;border-color:#5a332c}\
.up,.here{color:#5fd68a}.down{color:#ff7b6b}.drain{color:#e0b34a}\
input,button{border-color:#3a3a3a}}";

fn cell(state: &str) -> &'static str {
    match state {
        "up" => "up",
        "draining" => "drain",
        _ => "down",
    }
}

pub async fn dashboard(shared: &Shared) -> String {
    let loaded = shared.routing.load();
    let here = loaded
        .as_deref()
        .and_then(|routing| routing.topology.region().map(str::to_owned))
        .unwrap_or_else(|| "no region".to_owned());

    let mut where_is: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    if let Some(routing) = loaded.as_deref() {
        for shard in routing.topology.shards() {
            let region = shard.region.clone().unwrap_or_else(|| "-".to_owned());
            where_is.insert(
                shard.primary.address.clone(),
                (region.clone(), shard.id.number().to_string()),
            );
            for replica in &shard.replicas {
                where_is.insert(
                    replica.address.clone(),
                    (region.clone(), shard.id.number().to_string()),
                );
            }
        }
    }

    let mut sent: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    for row in crate::admin::subject_rows(shared, "TRAFFIC") {
        if let (Some(endpoint), Some(statements), Some(errors)) =
            (row.first(), row.get(2), row.get(3))
        {
            sent.insert(endpoint.clone(), (statements.clone(), errors.clone()));
        }
    }

    let mut body = String::with_capacity(8192);
    let _open = write!(
        body,
        "<!doctype html><meta charset=\"utf-8\"><title>shahrah — {}</title>\
         <style>{DASHBOARD_STYLE}</style>\
         <div class=\"top\"><h1>shahrah</h1>\
         <span class=\"quiet\">this proxy sits in <b>{}</b> · <span id=\"tick\">refreshing \
         every 10s</span></span></div>\
         <script>setInterval(function(){{\
         if(document.activeElement&&document.activeElement.tagName==='INPUT'){{\
         document.getElementById('tick').textContent='held while you are typing';return;}}\
         location.reload();}},10000);</script>",
        html_escape(&here),
        html_escape(&here)
    );

    let raised = crate::admin::alerts(shared);
    let _heading = write!(body, "<h2>worth waking someone for</h2>");
    if raised.is_empty() {
        body.push_str("<div class=\"calm\">nothing is raising an alert</div>");
    }
    for alert in &raised {
        let _row = write!(
            body,
            "<div class=\"alert\"><b>{}</b> — {} <span class=\"quiet\">{}</span></div>",
            html_escape(alert.name),
            html_escape(&alert.subject),
            html_escape(&alert.detail)
        );
    }

    let _world = write!(
        body,
        "<h2>every database, wherever it is</h2><table>\
         <tr><th>region</th><th>shard</th><th>endpoint</th><th>state</th><th>role</th>\
         <th>right role</th><th>behind primary</th><th>statements</th><th>errors</th></tr>"
    );
    let mut health = crate::admin::subject_rows(shared, "HEALTH");
    health.sort_by_key(|row| {
        let address = row.first().cloned().unwrap_or_default();
        let (region, shard) = where_is.get(&address).cloned().unwrap_or_default();
        (region, shard, address)
    });
    let mut last = String::new();
    for row in &health {
        let address = row.first().cloned().unwrap_or_default();
        let (region, shard) = where_is
            .get(&address)
            .cloned()
            .unwrap_or_else(|| ("not in the topology".to_owned(), "-".to_owned()));
        let state = row.get(1).cloned().unwrap_or_default();
        let (statements, errors) = sent.get(&address).cloned().unwrap_or_default();
        let shown = if region == last {
            String::new()
        } else {
            last.clone_from(&region);
            let mine = if region == here { " here" } else { "" };
            format!("<span class=\"region{mine}\">{}</span>", html_escape(&region))
        };
        let _line = write!(
            body,
            "<tr><td>{shown}</td><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td>\
             <td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&shard),
            html_escape(&address),
            cell(&state),
            html_escape(&state),
            html_escape(row.get(2).map_or("", String::as_str)),
            html_escape(row.get(3).map_or("", String::as_str)),
            html_escape(row.get(5).map_or("", String::as_str)),
            html_escape(&statements),
            html_escape(&errors)
        );
    }
    body.push_str("</table>");

    let seen = crate::admin::fleet_rows(shared, "HEALTH").await;
    let _fleet = write!(
        body,
        "<h2>and what every other proxy sees</h2><table>\
         <tr><th>proxy</th><th>endpoints it can use</th><th>endpoints it cannot</th></tr>"
    );
    for (who, rows) in &seen {
        let trouble = rows
            .iter()
            .find(|row| row.first().is_some_and(|first| first.starts_with("unreachable")));
        if let Some(row) = trouble {
            let _line = write!(
                body,
                "<tr><td>{}</td><td colspan=\"2\" class=\"down\">{}</td></tr>",
                html_escape(who),
                html_escape(row.first().map_or("", String::as_str))
            );
            continue;
        }
        let usable = rows
            .iter()
            .filter(|row| row.get(1).is_some_and(|state| state == "up"))
            .count();
        let stuck = rows.len().saturating_sub(usable);
        let _line = write!(
            body,
            "<tr><td>{}</td><td class=\"up\">{usable}</td><td class=\"{}\">{stuck}</td></tr>",
            html_escape(who),
            if stuck == 0 { "quiet" } else { "down" }
        );
    }
    body.push_str("</table>");

    let tables = loaded
        .as_deref()
        .map(|routing| routing.policy.geo_tables())
        .unwrap_or_default();
    let first = tables.first().cloned().unwrap_or_else(|| "users".to_owned());
    let _ask = write!(
        body,
        "<h2>where is one user's data</h2>\
         <form action=\"/find\" method=\"get\">\
         <input name=\"table\" value=\"{}\" size=\"14\" aria-label=\"table\">\
         <input name=\"key\" placeholder=\"key\" size=\"18\" aria-label=\"key\">\
         <button type=\"submit\">look it up</button></form>\
         <p class=\"quiet\">geo-partitioned tables: {}</p>",
        html_escape(&first),
        html_escape(&tables.join(", "))
    );
    body
}

fn page(title: &str, rows: &[(String, String)]) -> String {
    let mut body = String::with_capacity(1024);
    let _open = write!(
        body,
        "<!doctype html><meta charset=\"utf-8\"><title>{}</title>\
         <style>body{{font:15px/1.6 system-ui,sans-serif;margin:3rem auto;max-width:44rem;\
         color:#1a1a1a}}h1{{font-size:1.3rem;font-weight:600}}\
         table{{border-collapse:collapse;width:100%;margin-top:1.5rem}}\
         td{{padding:.55rem .8rem;border-bottom:1px solid #e6e6e6;vertical-align:top}}\
         td:first-child{{color:#666;width:14rem}}\
         @media(prefers-color-scheme:dark){{body{{background:#141414;color:#e8e8e8}}\
         td{{border-color:#2c2c2c}}td:first-child{{color:#999}}}}</style>\
         <h1>{}</h1><table>",
        html_escape(title),
        html_escape(title)
    );
    for (name, value) in rows {
        let _row = write!(
            body,
            "<tr><td>{}</td><td>{}</td></tr>",
            html_escape(name),
            html_escape(value)
        );
    }
    body.push_str("</table>");
    body
}

pub async fn serve(
    listener: TcpListener,
    shared: std::sync::Arc<Shared>,
    sampler: std::sync::Arc<crate::dashboard::Sampler>,
    gate: std::sync::Arc<crate::guard::Gate>,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
) {
    let open = std::sync::Arc::new(tokio::sync::Semaphore::new(OPEN_CONNECTIONS));
    let mut trouble: u32 = 0;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => {
                trouble = 0;
                accepted
            }
            Err(cause) => {
                trouble = trouble.saturating_add(1);
                if trouble == 1 || trouble.is_multiple_of(1000) {
                    warn!(%cause, running = trouble, "the metrics listener could not accept");
                }
                tokio::time::sleep(crate::accept_backoff(trouble)).await;
                continue;
            }
        };
        let Ok(held) = std::sync::Arc::clone(&open).try_acquire_owned() else {
            debug!(%peer, OPEN_CONNECTIONS, "dropping a metrics connection, the port is full");
            continue;
        };
        let shared = std::sync::Arc::clone(&shared);
        let sampler = std::sync::Arc::clone(&sampler);
        let gate = std::sync::Arc::clone(&gate);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _open = held;
            let outcome = match acceptor {
                Some(acceptor) => {
                    match tokio::time::timeout(TLS_DEADLINE, acceptor.accept(stream)).await {
                        Ok(Ok(upgraded)) => {
                            answer(upgraded, &shared, &sampler, &gate, peer.ip(), true).await
                        }
                        Ok(Err(cause)) => {
                            debug!(%cause, "a metrics connection would not negotiate TLS");
                            return;
                        }
                        Err(_elapsed) => {
                            debug!(%peer, "a metrics connection stalled mid-TLS-handshake");
                            return;
                        }
                    }
                }
                None => answer(stream, &shared, &sampler, &gate, peer.ip(), false).await,
            };
            if let Err(cause) = outcome {
                debug!(%cause, "a metrics request went wrong");
            }
        });
    }
}

pub struct Head {
    pub request: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    fn value(&self, wanted: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _value)| name.eq_ignore_ascii_case(wanted))
            .map(|(_name, value)| value.as_str())
    }

    fn wants_websocket(&self) -> bool {
        self.value("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
            && self.value("sec-websocket-key").is_some()
    }
}

async fn read_head<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> Result<Option<Head>, std::io::Error> {
    let mut room = HEAD_BYTES;
    let mut request = String::new();
    {
        let mut limited = (&mut *reader).take(room);
        limited.read_line(&mut request).await?;
        room = limited.limit();
    }
    if room == 0 {
        return Ok(None);
    }
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        let mut limited = (&mut *reader).take(room);
        let read = limited.read_line(&mut header).await?;
        room = limited.limit();
        if room == 0 {
            return Ok(None);
        }
        if read == 0 || header.trim().is_empty() {
            return Ok(Some(Head { request, headers }));
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
}

async fn read_body<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    width: usize,
) -> Result<String, std::io::Error> {
    let mut body = vec![0u8; width.min(BODY_BYTES)];
    reader.read_exact(&mut body).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[allow(clippy::too_many_lines)]
async fn answer<S>(
    stream: S,
    shared: &Shared,
    sampler: &std::sync::Arc<crate::dashboard::Sampler>,
    gate: &std::sync::Arc<crate::guard::Gate>,
    caller: std::net::IpAddr,
    encrypted: bool,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(stream);
    let head = tokio::time::timeout(HEAD_DEADLINE, read_head(&mut reader))
        .await
        .map_err(|_elapsed| std::io::Error::other("a metrics request stalled mid-head"))??;

    let line = head.as_ref().map(|head| head.request.clone()).unwrap_or_default();
    let cookie = head
        .as_ref()
        .and_then(|head| crate::guard::cookie_from(head.value("cookie")));
    let offered = head
        .as_ref()
        .and_then(|head| crate::guard::password_from(head.value("authorization")));
    let verdict = gate.admits(caller, cookie.as_deref(), offered.as_deref());
    let asked_for = line
        .split_whitespace()
        .nth(1)
        .map(|target| target.split(['?', '#']).next().unwrap_or("/").to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let posting = line.split_whitespace().next().is_some_and(|word| word.eq_ignore_ascii_case("POST"));

    if asked_for == "/login" && posting {
        let width = head
            .as_ref()
            .and_then(|head| head.value("content-length"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let body = match tokio::time::timeout(BODY_DEADLINE, read_body(&mut reader, width)).await {
            Ok(Ok(body)) => body,
            Ok(Err(_partial)) => String::new(),
            Err(_elapsed) => {
                return Err(std::io::Error::other("a metrics request stalled mid-body"));
            }
        };
        let given = crate::guard::form_value(&body, "password").unwrap_or_default();
        let mut stream = reader.into_inner();
        return match gate.try_login(caller, &given) {
            Ok(token) => {
                let cookie = format!(
                    "{}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{}",
                    crate::guard::COOKIE,
                    crate::guard::SESSION_LIFE.as_secs(),
                    if encrypted { "; Secure" } else { "" }
                );
                let sent = format!(
                    "HTTP/1.1 303 See Other\r\nLocation: /\r\nSet-Cookie: {cookie}\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(sent.as_bytes()).await?;
                stream.flush().await
            }
            Err(refusal) => {
                tokio::time::sleep(crate::guard::Gate::slow_down_after_a_refusal()).await;
                let (status, words) = match refusal {
                    crate::guard::Verdict::LockedOut { after } => (
                        "429 Too Many Requests",
                        format!("too many wrong answers from this address; try again in {after}s"),
                    ),
                    _other => ("401 Unauthorized", "that is not the password".to_owned()),
                };
                let body = crate::guard::login_page(Some(&words));
                let sent = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
                     Cache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(sent.as_bytes()).await?;
                stream.write_all(body.as_bytes()).await?;
                stream.flush().await
            }
        };
    }

    if asked_for == "/logout" {
        if let Some(token) = cookie.as_deref() {
            gate.forget_session(token);
        }
        let mut stream = reader.into_inner();
        let sent = format!(
            "HTTP/1.1 303 See Other\r\nLocation: /login\r\nSet-Cookie: {}=; HttpOnly; \
             SameSite=Strict; Path=/; Max-Age=0\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
            crate::guard::COOKIE
        );
        stream.write_all(sent.as_bytes()).await?;
        return stream.flush().await;
    }

    if verdict != crate::guard::Verdict::Allowed {
        if offered.is_some() {
            tokio::time::sleep(crate::guard::Gate::slow_down_after_a_refusal()).await;
        }
        let mut stream = reader.into_inner();
        let (status, extra, body) = match verdict {
            crate::guard::Verdict::TooManyRequests { after } => (
                "429 Too Many Requests",
                format!("Retry-After: {after}\r\n"),
                format!("this address is asking too often; try again in {after}s\n"),
            ),
            crate::guard::Verdict::LockedOut { after } => (
                "429 Too Many Requests",
                format!("Retry-After: {after}\r\n"),
                crate::guard::login_page(Some(&format!(
                    "too many wrong answers from this address; try again in {after}s"
                ))),
            ),
            _needs_login => (
                "401 Unauthorized",
                String::new(),
                crate::guard::login_page(None),
            ),
        };
        let kind = if body.starts_with("<!doctype") {
            "text/html; charset=utf-8"
        } else {
            "text/plain; charset=utf-8"
        };
        let sent = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\n{extra}Cache-Control: no-store\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(sent.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        return stream.flush().await;
    }

    if asked_for == "/login" {
        let body = crate::guard::login_page(None);
        let mut stream = reader.into_inner();
        let sent = format!(
            "HTTP/1.1 303 See Other\r\nLocation: /\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(sent.as_bytes()).await?;
        return stream.flush().await;
    }

    if let Some(head) = head.as_ref()
        && head.wants_websocket()
        && line.split_whitespace().nth(1).is_some_and(|target| {
            target.split(['?', '#']).next().unwrap_or("/") == "/live"
        })
        && let Some(offered) = head.value("sec-websocket-key")
    {
        let offered = offered.to_owned();
        let stream = reader.into_inner();
        return crate::dashboard::live(stream, shared, sampler, &offered).await;
    }

    let mut words = line.split_whitespace();
    let method = words.next().unwrap_or_default().to_owned();
    let target = words.next().unwrap_or("/").to_owned();
    let path = target.split(['?', '#']).next().unwrap_or("/").to_owned();
    let wants_body = !method.eq_ignore_ascii_case("HEAD");

    let (status, kind, body) = if head.is_none() {
        ("431 Request Header Fields Too Large", "text/plain; charset=utf-8",
         format!("shahrah reads at most {HEAD_BYTES} bytes of request head\n"))
    } else if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        ("405 Method Not Allowed", "text/plain; charset=utf-8",
         "shahrah answers GET and HEAD\n".to_owned())
    } else if path == "/" {
        ("200 OK", "text/html; charset=utf-8", crate::dashboard::PAGE.to_owned())
    } else if path == "/snapshot" {
        match serde_json::to_string(&crate::dashboard::snapshot(shared, sampler).await) {
            Ok(rendered) => ("200 OK", "application/json; charset=utf-8", rendered),
            Err(_cause) => ("500 Internal Server Error", "text/plain; charset=utf-8",
                            "the snapshot would not render\n".to_owned()),
        }
    } else if path == "/plain" {
        ("200 OK", "text/html; charset=utf-8", dashboard(shared).await)
    } else if path == "/find" {
        let asked = target.split_once('?').map_or("", |(_head, tail)| tail);
        let mut table = String::new();
        let mut key = String::new();
        for pair in asked.split('&') {
            match pair.split_once('=') {
                Some(("table", value)) => table = decoded(value),
                Some(("key", value)) => key = decoded(value),
                _ => {}
            }
        }
        if table.is_empty() || key.is_empty() {
            ("400 Bad Request", "text/plain; charset=utf-8",
             "ask for /find?table=<table>&key=<key>\n".to_owned())
        } else {
            ("200 OK", "text/html; charset=utf-8", key_page(shared, &table, &key).await)
        }
    } else if path == "/metrics" {
        ("200 OK", "text/plain; version=0.0.4; charset=utf-8", render(shared))
    } else if let Some(rest) = path.strip_prefix("/key/") {
        let mut parts = rest.splitn(2, '/');
        match (parts.next(), parts.next()) {
            (Some(table), Some(literal)) if !table.is_empty() && !literal.is_empty() => (
                "200 OK",
                "text/html; charset=utf-8",
                key_page(shared, table, literal).await,
            ),
            _ => ("404 Not Found", "text/plain; charset=utf-8",
                  "ask for /key/<table>/<key>\n".to_owned()),
        }
    } else {
        ("404 Not Found", "text/plain; charset=utf-8",
         "shahrah serves /, /live, /snapshot, /plain, /metrics and \
          /key/<table>/<key>\n".to_owned())
    };
    let sent = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = reader.into_inner();
    stream.write_all(sent.as_bytes()).await?;
    if wants_body {
        stream.write_all(body.as_bytes()).await?;
    }
    stream.flush().await
}

pub async fn start(shared: Shared) {
    let Ok(address) = std::env::var(LISTEN_ENV) else {
        return;
    };
    let acceptor = match crate::tls::load_metrics_acceptor() {
        Ok(acceptor) => acceptor,
        Err(cause) => {
            tracing::error!(%cause, "the dashboard's TLS certificate would not load");
            return;
        }
    };
    let gate = std::sync::Arc::new(crate::guard::Gate::from_env());
    if !gate.guarded() {
        let insisted = match crate::settings::flag(crate::guard::OPEN_ENV) {
            Ok(insisted) => insisted,
            Err(cause) => {
                tracing::error!(%cause, "the dashboard will not be served");
                return;
            }
        };
        if crate::address::reaches_the_world(&address) && !insisted {
            tracing::error!(
                %address,
                "refusing to serve the dashboard on an address other machines can reach with \
                 no password. It publishes the topology and where every user's data lives. Set \
                 {} to a secret, or bind it to loopback, or set {}=yes if you have put your own \
                 authentication in front of it",
                crate::guard::PASSWORD_ENV,
                crate::guard::OPEN_ENV
            );
            return;
        }
        warn!(
            %address,
            "the dashboard has no password; anything that can reach this address can read \
             the topology and look up where a user's data lives"
        );
    }
    if acceptor.is_none() && gate.guarded() && crate::address::reaches_the_world(&address) {
        warn!(
            %address,
            "the dashboard asks for a password over a connection that is not encrypted, so \
             the password and the session cookie cross the network in the clear. Set {} and \
             {}, or bind this to loopback behind a terminator",
            crate::tls::METRICS_CERT_ENV,
            crate::tls::METRICS_KEY_ENV
        );
    }
    let sampler = crate::dashboard::Sampler::new();
    crate::dashboard::sample_forever(shared.clone(), std::sync::Arc::clone(&sampler));
    let shared = std::sync::Arc::new(shared);
    match TcpListener::bind(&address).await {
        Ok(listener) => {
            tracing::info!(
                %address,
                tls = acceptor.is_some(),
                guarded = gate.guarded(),
                "shahrah is serving the dashboard at / and metrics at /metrics"
            );
            tokio::spawn(async move { serve(listener, shared, sampler, gate, acceptor).await });
        }
        Err(cause) => warn!(%address, %cause, "the metrics listener could not bind"),
    }
}
