use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tracing::{info, warn};

use crate::error::SessionError;
use crate::session::Shared;

pub const HOLD_LIMIT: Duration = Duration::from_secs(30);
const SETTLE: std::time::Duration = crate::cluster::WATCH_INTERVAL.saturating_mul(3);
const ANNOUNCE_LIMIT: Duration = Duration::from_secs(5);
pub const WINDOW: Duration = Duration::from_secs(60);
pub const FOREIGN_SHARE: f64 = 0.6;
pub const MIN_SAMPLES: u64 = 20;

#[derive(Default)]
struct Seen {
    from: HashMap<String, u64>,
    first: Option<Instant>,
}

pub struct Relocations {
    moving: Mutex<HashSet<Vec<u8>>>,
    moving_logical: Mutex<HashSet<u16>>,
    woken: Notify,
    traffic: Mutex<HashMap<Vec<u8>, Seen>>,
}

impl Default for Relocations {
    fn default() -> Self {
        Self {
            moving: Mutex::new(HashSet::new()),
            moving_logical: Mutex::new(HashSet::new()),
            woken: Notify::new(),
            traffic: Mutex::new(HashMap::new()),
        }
    }
}

impl Relocations {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn begin(&self, key: &[u8]) -> bool {
        self.moving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.to_vec())
    }

    fn finish(&self, key: &[u8]) {
        self.moving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
        self.woken.notify_waiters();
    }

    #[must_use]
    pub fn is_moving_key(&self, key: &[u8]) -> bool {
        self.is_moving(key)
    }

    fn is_moving(&self, key: &[u8]) -> bool {
        self.moving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(key)
    }

    pub fn begin_logical(&self, logical: u16) -> bool {
        self.moving_logical
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(logical)
    }

    pub fn finish_logical(&self, logical: u16) {
        self.moving_logical
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&logical);
        self.woken.notify_waiters();
    }

    fn logical_is_moving(&self, logical: u16) -> bool {
        self.moving_logical
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&logical)
    }

    pub async fn wait_if_logical_moving(&self, logical: u16) {
        let since = Instant::now();
        while self.logical_is_moving(logical) {
            if since.elapsed() > HOLD_LIMIT {
                warn!("a statement waited past the limit for a range that is being rebalanced");
                return;
            }
            let woken = self.woken.notified();
            if !self.logical_is_moving(logical) {
                return;
            }
            let _timed = tokio::time::timeout(Duration::from_millis(250), woken).await;
        }
    }

    pub async fn wait_if_moving(&self, key: &[u8]) {
        let until = Instant::now();
        while self.is_moving(key) {
            if until.elapsed() > HOLD_LIMIT {
                warn!("a statement waited past the limit for a key that is being relocated");
                return;
            }
            let woken = self.woken.notified();
            if !self.is_moving(key) {
                return;
            }
            let _timed = tokio::time::timeout(Duration::from_millis(250), woken).await;
        }
    }

    pub fn saw(&self, key: &[u8], region: &str) {
        let mut traffic = self.traffic.lock().unwrap_or_else(PoisonError::into_inner);
        let seen = traffic.entry(key.to_vec()).or_default();
        if seen.first.is_none_or(|first| first.elapsed() > WINDOW) {
            seen.from.clear();
            seen.first = Some(Instant::now());
        }
        let counted = seen.from.entry(region.to_owned()).or_insert(0);
        *counted = counted.saturating_add(1);
    }

    #[must_use]
    pub fn candidates(&self, home_of: &dyn Fn(&[u8]) -> Option<String>) -> Vec<Candidate> {
        let traffic = self.traffic.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = Vec::new();
        for (key, seen) in traffic.iter() {
            let total: u64 = seen.from.values().sum();
            if total < MIN_SAMPLES {
                continue;
            }
            let Some(home) = home_of(key) else { continue };
            let Some((region, count)) = seen
                .from
                .iter()
                .filter(|(region, _count)| *region != &home)
                .max_by_key(|(_region, count)| **count)
            else {
                continue;
            };
            #[allow(clippy::cast_precision_loss)]
            let share = *count as f64 / total as f64;
            if share < FOREIGN_SHARE {
                continue;
            }
            out.push(Candidate {
                key: key.clone(),
                home,
                pulling: region.clone(),
                share,
                samples: total,
            });
        }
        out.sort_by(|left, right| right.share.total_cmp(&left.share));
        out
    }
}

pub struct Candidate {
    pub key: Vec<u8>,
    pub home: String,
    pub pulling: String,
    pub share: f64,
    pub samples: u64,
}

fn quote(text: &str) -> String {
    text.replace('\'', "''")
}

async fn affected_by(
    shared: &Shared,
    address: &str,
    database: &str,
    sql: &str,
) -> Result<u64, SessionError> {
    let mut lease = shared.pool.acquire(address, database, None).await?;
    let answered = match lease.connection() {
        Ok(backend) => backend.collect_query(sql).await,
        Err(cause) => Err(cause),
    };
    lease.release().await;
    let collected = answered?;
    if let Some(failure) = collected.failure {
        return Err(failure);
    }
    Ok(collected.affected)
}

async fn one_query(
    shared: &Shared,
    address: &str,
    database: &str,
    sql: &str,
) -> Result<Option<String>, SessionError> {
    let mut lease = shared.pool.acquire(address, database, None).await?;
    let answered = match lease.connection() {
        Ok(backend) => backend.collect_query(sql).await,
        Err(cause) => Err(cause),
    };
    lease.release().await;
    let collected = answered?;
    if let Some(failure) = collected.failure {
        return Err(failure);
    }
    Ok(collected.rows.first().and_then(|row| {
        shahrah_protocol::messages::data_row_fields(row.get(5..).unwrap_or(&[]))
            .ok()
            .and_then(|fields| fields.first().and_then(Clone::clone))
            .map(|value| String::from_utf8_lossy(&value).into_owned())
    }))
}

pub struct Moved {
    pub table_rows: Vec<(String, usize)>,
    pub from: String,
    pub to: String,
    pub held: Duration,
}

pub async fn relocate(
    shared: &Shared,
    table: &str,
    literal: &str,
    key: &[u8],
    to: &str,
    database: &str,
) -> Result<Moved, SessionError> {
    let loaded = shared.routing.load();
    let routing = loaded
        .as_deref()
        .ok_or_else(|| SessionError::Relocate("no topology is loaded".to_owned()))?;

    let key_type = routing
        .policy
        .key_type(table)
        .ok_or_else(|| SessionError::Relocate(format!("\"{table}\" is not geo-partitioned")))?;
    let regions = routing.topology.placed_regions();
    if !regions.contains(&to) {
        return Err(SessionError::Relocate(format!(
            "this topology places no shard in region \"{to}\""
        )));
    }


    let owned = shahrah_sql::analysis::canonical(
        Some(literal.as_bytes()),
        shahrah_sql::analysis::FORMAT_TEXT,
        key_type,
    )
    .map_err(|cause| SessionError::Relocate(cause.to_string()))?;
    let logical = shahrah_hash::shard::LogicalShard::of(
        match &owned {
            shahrah_sql::analysis::OwnedKey::Int(value) => {
                shahrah_hash::key::ShardKey::Int(*value)
            }
            shahrah_sql::analysis::OwnedKey::Uuid(value) => {
                shahrah_hash::key::ShardKey::Uuid(*value)
            }
            shahrah_sql::analysis::OwnedKey::Bytes(value) => {
                shahrah_hash::key::ShardKey::Bytes(value)
            }
            shahrah_sql::analysis::OwnedKey::Text(value) => {
                shahrah_hash::key::ShardKey::Text(value)
            }
        },
        shahrah_hash::shard::HashVersion::V1,
    );

    let here = shahrah_routing::router::route_in(
        &routing.topology,
        routing.topology.region(),
        logical,
        shahrah_routing::router::Intent::Write,
    )
    .map_err(|cause| SessionError::Relocate(cause.to_string()))?;
    let from = one_query(
        shared,
        &here.address,
        database,
        &shared.directory.statement_for(key),
    )
    .await?
    .ok_or_else(|| {
        SessionError::Relocate(format!(
            "the directory has no home region for \"{literal}\", so shahrah does not know where \
             its rows are and will not guess"
        ))
    })?;
    if from == to {
        return Err(SessionError::Relocate(format!(
            "\"{literal}\" already lives in \"{to}\""
        )));
    }
    let moving: Vec<String> = routing
        .policy
        .geo_tables_with(key_type)
        .into_iter()
        .collect();

    if let Some(node) = shared.cluster.get() {
        match tokio::time::timeout(ANNOUNCE_LIMIT, node.announce_move(key.to_vec())).await {
            Ok(Ok(())) => {}
            Ok(Err(cause)) => {
                return Err(SessionError::Relocate(format!(
                    "the group would not record this move, so other proxies could not learn of \
                     it and would keep sending this key to the region it left: {cause}"
                )))
            }
            Err(_elapsed) => {
                return Err(SessionError::Relocate(format!(
                    "the group did not record this move within {ANNOUNCE_LIMIT:?}, which usually \
                     means it has no leader. shahrah will not move a key the rest of the cluster \
                     cannot be told about"
                )))
            }
        }
    }

    if !shared.relocations.begin(key) {
        return Err(SessionError::Relocate(format!(
            "\"{literal}\" is already being relocated"
        )));
    }
    shared.directory.forget(key);
    let started = Instant::now();

    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    let intent = format!(
        "update {} set moving_to = '{}' where shard_key = '\\x{hex}'::bytea \
         and moving_to is null",
        shared.directory.table(),
        quote(to)
    );
    let mut announced: Vec<String> = Vec::new();
    for region in &regions {
        let Ok(decision) = shahrah_routing::router::route_in(
            &routing.topology,
            Some(region),
            logical,
            shahrah_routing::router::Intent::Write,
        ) else {
            continue;
        };
        match affected_by(shared, &decision.address, database, &intent).await {
            Ok(1..) => announced.push((*region).to_owned()),
            Ok(_none) => {
                for done in &announced {
                    let _rolled = clear_intent(shared, routing, done, logical, key, database, to).await;
                }
                shared.relocations.finish(key);
                return Err(SessionError::Relocate(format!(
                    "another proxy is already moving \"{literal}\"; only one move of a key runs \
                     at a time, and the directory row is what decides which"
                )));
            }
            Err(cause) => {
                for done in &announced {
                    let _rolled = clear_intent(shared, routing, done, logical, key, database, to).await;
                }
                shared.relocations.finish(key);
                return Err(SessionError::Relocate(format!(
                    "the move was not started because region \"{region}\" would not record it: \
                     {cause}"
                )));
            }
        }
    }

    let settled = one_query(
        shared,
        &here.address,
        database,
        &shared.directory.statement_for(key),
    )
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| from.clone());
    if settled == to {
        for done in &announced {
            let _rolled = clear_intent(shared, routing, done, logical, key, database, to).await;
        }
        shared.relocations.finish(key);
        return Err(SessionError::Relocate(format!(
            "\"{literal}\" already lives in \"{to}\""
        )));
    }
    let from = settled;

    let outcome = move_rows(
        shared, routing, &moving, literal, logical, &from, to, database,
    )
    .await;

    let written = match outcome {
        Ok(written) => written,
        Err(cause) => {
            shared.relocations.finish(key);
            return Err(cause);
        }
    };

    let update = format!(
        "update {} set home_region = '{}', moving_to = null \
         where shard_key = '\\x{hex}'::bytea and moving_to = '{}'",
        shared.directory.table(),
        quote(to),
        quote(to)
    );
    let mut took = 0usize;
    for region in &regions {
        let Ok(decision) = shahrah_routing::router::route_in(
            &routing.topology,
            Some(region),
            logical,
            shahrah_routing::router::Intent::Write,
        ) else {
            continue;
        };
        match affected_by(shared, &decision.address, database, &update).await {
            Ok(1..) => took = took.saturating_add(1),
            Ok(_none) => warn!(
                region,
                "another proxy took this move over: this region's directory kept its own answer"
            ),
            Err(cause) => {
                warn!(region, %cause, "a region's copy of the directory did not take the new home");
            }
        }
    }
    if took == 0 {
        shared.relocations.finish(key);
        return Err(SessionError::Relocate(format!(
            "another proxy took the move of \"{literal}\" over before this one could finish, so \
             this proxy wrote no directory row and left the rows where they were"
        )));
    }

    shared.directory.forget(key);
    if let Some(node) = shared.cluster.get() {
        let told = tokio::time::timeout(ANNOUNCE_LIMIT, node.announce_move(key.to_vec())).await;
        if !matches!(told, Ok(Ok(()))) {
            warn!(
                "this key moved but the second announcement did not land, so other proxies may \
                 keep routing it to its old region until their cache expires"
            );
        }
    }
    shared.relocations.finish(key);
    let held = started.elapsed();

    if shared.cluster.get().is_some() {
        tokio::time::sleep(SETTLE).await;
    }

    for (name, _rows) in &written {
        let Ok(source) = shahrah_routing::router::route_in(
            &routing.topology,
            Some(&from),
            logical,
            shahrah_routing::router::Intent::Write,
        ) else {
            continue;
        };
        let column = routing.policy.key_column(name).unwrap_or("id");
        let sql = format!("delete from {name} where {column} = '{}'", quote(literal));
        if let Err(cause) = one_query(shared, &source.address, database, &sql).await {
            warn!(table = name, %cause, "the rows left behind in the old region were not removed");
        }
    }

    crate::metrics::Counters::bump(&shared.counters.relocations);
    info!(
        key = literal,
        from,
        to,
        held_ms = held.as_millis(),
        "relocated a key"
    );
    Ok(Moved {
        table_rows: written,
        from,
        to: to.to_owned(),
        held,
    })
}

#[allow(clippy::too_many_arguments)]
async fn move_rows(
    shared: &Shared,
    routing: &crate::config::Loaded,
    tables: &[String],
    literal: &str,
    logical: shahrah_hash::shard::LogicalShard,
    from: &str,
    to: &str,
    database: &str,
) -> Result<Vec<(String, usize)>, SessionError> {
    let source = shahrah_routing::router::route_in(
        &routing.topology,
        Some(from),
        logical,
        shahrah_routing::router::Intent::Write,
    )
    .map_err(|cause| SessionError::Relocate(cause.to_string()))?;
    let destination = shahrah_routing::router::route_in(
        &routing.topology,
        Some(to),
        logical,
        shahrah_routing::router::Intent::Write,
    )
    .map_err(|cause| SessionError::Relocate(cause.to_string()))?;

    let mut written = Vec::new();
    for table in tables {
        let column = routing.policy.key_column(table).unwrap_or("id");
        let read = format!(
            "select coalesce(json_agg(t)::text, '[]') from {table} t where t.{column} = '{}'",
            quote(literal)
        );
        let payload = one_query(shared, &source.address, database, &read)
            .await?
            .unwrap_or_else(|| "[]".to_owned());
        if payload == "[]" {
            written.push((table.clone(), 0));
            continue;
        }
        let insert = format!(
            "insert into {table} select * from json_populate_recordset(null::{table}, '{}')",
            quote(&payload)
        );
        one_query(shared, &destination.address, database, &insert).await?;
        let counted = format!(
            "select count(*) from {table} where {column} = '{}'",
            quote(literal)
        );
        let rows = one_query(shared, &destination.address, database, &counted)
            .await?
            .and_then(|text| text.parse::<usize>().ok())
            .unwrap_or(0);
        written.push((table.clone(), rows));
    }
    Ok(written)
}

async fn clear_intent(
    shared: &Shared,
    routing: &crate::config::Loaded,
    region: &str,
    logical: shahrah_hash::shard::LogicalShard,
    key: &[u8],
    database: &str,
    mine: &str,
) -> Result<(), SessionError> {
    let decision = shahrah_routing::router::route_in(
        &routing.topology,
        Some(region),
        logical,
        shahrah_routing::router::Intent::Write,
    )
    .map_err(|cause| SessionError::Relocate(cause.to_string()))?;
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    let sql = format!(
        "update {} set moving_to = null where shard_key = '\\x{hex}'::bytea \
         and moving_to = '{}'",
        shared.directory.table(),
        quote(mine)
    );
    one_query(shared, &decision.address, database, &sql).await.map(|_none| ())
}

pub struct Rebalanced {
    pub table: String,
    pub from: String,
    pub to: String,
    pub rows: usize,
}

fn logical_of(
    literal: &str,
    key_type: shahrah_sql::analysis::KeyType,
) -> Option<shahrah_hash::shard::LogicalShard> {
    let owned = shahrah_sql::analysis::canonical(
        Some(literal.as_bytes()),
        shahrah_sql::analysis::FORMAT_TEXT,
        key_type,
    )
    .ok()?;
    Some(shahrah_hash::shard::LogicalShard::of(
        match &owned {
            shahrah_sql::analysis::OwnedKey::Int(value) => shahrah_hash::key::ShardKey::Int(*value),
            shahrah_sql::analysis::OwnedKey::Uuid(value) => {
                shahrah_hash::key::ShardKey::Uuid(*value)
            }
            shahrah_sql::analysis::OwnedKey::Bytes(value) => {
                shahrah_hash::key::ShardKey::Bytes(value)
            }
            shahrah_sql::analysis::OwnedKey::Text(value) => shahrah_hash::key::ShardKey::Text(value),
        },
        shahrah_hash::shard::HashVersion::V1,
    ))
}

pub async fn rebalance(
    shared: &Shared,
    region: &str,
    database: &str,
) -> Result<Vec<Rebalanced>, SessionError> {
    let loaded = shared.routing.load();
    let routing = loaded
        .as_deref()
        .ok_or_else(|| SessionError::Relocate("no topology is loaded".to_owned()))?;
    let map = routing
        .topology
        .map_for(Some(region))
        .ok_or_else(|| SessionError::Relocate(format!("no shards are placed in \"{region}\"")))?;

    let here: Vec<&shahrah_routing::topology::Shard> = routing
        .topology
        .shards()
        .iter()
        .filter(|shard| shard.region.as_deref() == Some(region))
        .collect();

    let directory = shared.directory.table().to_owned();
    let mut tables = routing.policy.geo_tables();
    tables.push(directory.clone());

    let mut moved: Vec<Rebalanced> = Vec::new();
    for shard in &here {
        for table in &tables {
            let is_directory = table == &directory;
            let key_type = if is_directory {
                shahrah_sql::analysis::KeyType::Bytea
            } else {
                match routing.policy.key_type(table) {
                    Some(found) => found,
                    None => continue,
                }
            };
            let column = if is_directory {
                "shard_key"
            } else {
                routing.policy.key_column(table).unwrap_or("id")
            };
            let read = format!("select coalesce(json_agg(t)::text, '[]') from {table} t");
            let payload = one_query(shared, &shard.primary.address, database, &read)
                .await?
                .unwrap_or_else(|| "[]".to_owned());
            let Ok(serde_json::Value::Array(rows)) =
                serde_json::from_str::<serde_json::Value>(&payload)
            else {
                continue;
            };

            let mut strays: HashMap<u16, Vec<serde_json::Value>> = HashMap::new();
            for row in rows {
                let Some(value) = row.get(column) else { continue };
                let literal = match value {
                    serde_json::Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                let logical = if is_directory {
                    match hex_bytes(&literal) {
                        Some(raw) => shahrah_hash::shard::LogicalShard::of(
                            shahrah_hash::key::ShardKey::Bytes(&raw),
                            shahrah_hash::shard::HashVersion::V1,
                        ),
                        None => continue,
                    }
                } else {
                    match logical_of(&literal, key_type) {
                        Some(found) => found,
                        None => continue,
                    }
                };
                let owner = map.get(logical);
                if owner.number() == shard.id.number() {
                    continue;
                }
                strays.entry(logical.get()).or_default().push(row);
            }
            if strays.is_empty() {
                continue;
            }

            let mut by_owner: HashMap<u16, (Vec<serde_json::Value>, Vec<u16>)> = HashMap::new();
            for (logical, rows) in strays {
                let owner = map
                    .get(shahrah_hash::shard::LogicalShard::from_index(logical))
                    .number();
                let slot = by_owner.entry(owner).or_default();
                slot.0.extend(rows);
                slot.1.push(logical);
            }

            for (owner, (rows, logicals)) in by_owner {
                let Some(destination) = here.iter().find(|other| other.id.number() == owner) else {
                    continue;
                };
                for logical in &logicals {
                    shared.relocations.begin_logical(*logical);
                }
                let outcome = carry(
                    shared,
                    database,
                    table,
                    column,
                    &shard.primary.address,
                    &destination.primary.address,
                    &rows,
                    is_directory,
                )
                .await;
                for logical in &logicals {
                    shared.relocations.finish_logical(*logical);
                }
                let carried = outcome?;
                info!(
                    table = %table,
                    from = %shard.primary.address,
                    to = %destination.primary.address,
                    rows = carried,
                    "carried rows to the shard that now owns them"
                );
                moved.push(Rebalanced {
                    table: table.clone(),
                    from: shard.primary.address.clone(),
                    to: destination.primary.address.clone(),
                    rows: carried,
                });
            }
        }
    }
    Ok(moved)
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let body = text.strip_prefix("\\x")?;
    let mut out = Vec::with_capacity(body.len().checked_div(2)?);
    let raw = body.as_bytes();
    let mut at = 0usize;
    while at.saturating_add(1) < raw.len() {
        let pair = core::str::from_utf8(raw.get(at..at.saturating_add(2))?).ok()?;
        out.push(u8::from_str_radix(pair, 16).ok()?);
        at = at.saturating_add(2);
    }
    Some(out)
}

#[allow(clippy::too_many_arguments)]
async fn carry(
    shared: &Shared,
    database: &str,
    table: &str,
    column: &str,
    from: &str,
    to: &str,
    rows: &[serde_json::Value],
    is_directory: bool,
) -> Result<usize, SessionError> {
    let payload = serde_json::Value::Array(rows.to_vec()).to_string();
    let insert = format!(
        "insert into {table} select * from json_populate_recordset(null::{table}, '{}') \
         on conflict do nothing",
        quote(&payload)
    );
    one_query(shared, to, database, &insert).await?;

    let mut keys = String::new();
    for row in rows {
        let Some(value) = row.get(column) else { continue };
        let literal = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        if !keys.is_empty() {
            keys.push(',');
        }
        keys.push('\'');
        keys.push_str(&quote(&literal));
        keys.push('\'');
        if is_directory {
            keys.push_str("::bytea");
        }
    }
    if !keys.is_empty() {
        let delete = format!("delete from {table} where {column} in ({keys})");
        one_query(shared, from, database, &delete).await?;
    }
    Ok(rows.len())
}

pub struct Repaired {
    pub key: String,
    pub outcome: &'static str,
    pub home: String,
}

pub async fn repair(shared: &Shared, database: &str) -> Result<Vec<Repaired>, SessionError> {
    let loaded = shared.routing.load();
    let routing = loaded
        .as_deref()
        .ok_or_else(|| SessionError::Relocate("no topology is loaded".to_owned()))?;
    let regions: Vec<String> = routing
        .topology
        .placed_regions()
        .into_iter()
        .map(str::to_owned)
        .collect();

    let mut interrupted: HashMap<Vec<u8>, (String, String)> = HashMap::new();
    for region in &regions {
        for shard in routing.topology.shards() {
            if shard.region.as_deref() != Some(region.as_str()) {
                continue;
            }
            let sql = format!(
                "select encode(shard_key,'hex'), home_region, coalesce(moving_to,'') from {} \
                 where moving_to is not null",
                shared.directory.table()
            );
            let mut lease = shared
                .pool
                .acquire(&shard.primary.address, database, None)
                .await?;
            let answered = match lease.connection() {
                Ok(backend) => backend.collect_query(&sql).await,
                Err(cause) => Err(cause),
            };
            lease.release().await;
            let collected = answered?;
            if let Some(failure) = collected.failure {
                return Err(failure);
            }
            for row in &collected.rows {
                let Ok(fields) =
                    shahrah_protocol::messages::data_row_fields(row.get(5..).unwrap_or(&[]))
                else {
                    continue;
                };
                let text = |index: usize| {
                    fields
                        .get(index)
                        .and_then(Option::as_ref)
                        .map(|v| String::from_utf8_lossy(v).into_owned())
                        .unwrap_or_default()
                };
                let Some(raw) = hex_bytes(&format!("\\x{}", text(0))) else {
                    continue;
                };
                interrupted.insert(raw, (text(1), text(2)));
            }
        }
    }

    let mut out = Vec::new();
    for (key, (from, to)) in interrupted {
        let logical = shahrah_hash::shard::LogicalShard::of(
            shahrah_hash::key::ShardKey::Bytes(&key),
            shahrah_hash::shard::HashVersion::V1,
        );
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        let source_has = rows_for(shared, routing, &from, logical, &key, database).await?;
        let dest_has = rows_for(shared, routing, &to, logical, &key, database).await?;
        let (settled, outcome) = if source_has && !dest_has {
            (from.clone(), "rolled back: the rows never left")
        } else if !source_has && dest_has {
            (to.clone(), "completed: the rows had already arrived")
        } else if source_has && dest_has {
            for table in routing.policy.geo_tables() {
                let column = routing.policy.key_column(&table).unwrap_or("id");
                let Ok(decision) = shahrah_routing::router::route_in(
                    &routing.topology,
                    Some(&to),
                    logical,
                    shahrah_routing::router::Intent::Write,
                ) else {
                    continue;
                };
                let precise = delete_for(&table, column, &key, routing);
                let _dropped = one_query(shared, &decision.address, database, &precise).await;
            }
            (from.clone(), "rolled back: the copy left behind was removed")
        } else {
            (from.clone(), "left alone: no rows on either side")
        };

        let settle = format!(
            "update {} set home_region = '{}', moving_to = null where shard_key = '\\x{hex}'::bytea",
            shared.directory.table(),
            quote(&settled)
        );
        for region in &regions {
            let Ok(decision) = shahrah_routing::router::route_in(
                &routing.topology,
                Some(region),
                logical,
                shahrah_routing::router::Intent::Write,
            ) else {
                continue;
            };
            if let Err(cause) = one_query(shared, &decision.address, database, &settle).await {
                warn!(region, %cause, "a region would not take the repaired home");
            }
        }
        shared.directory.forget(&key);
        if let Some(node) = shared.cluster.get() {
            let _told = node.announce_move(key.clone()).await;
        }
        info!(key = %hex, from = %from, to = %to, settled = %settled, outcome, "repaired an interrupted move");
        out.push(Repaired {
            key: hex,
            outcome,
            home: settled,
        });
    }
    Ok(out)
}

fn delete_for(
    table: &str,
    column: &str,
    key: &[u8],
    routing: &crate::config::Loaded,
) -> String {
    let key_type = routing
        .policy
        .key_type(table)
        .unwrap_or(shahrah_sql::analysis::KeyType::Int);
    let literal = match key_type {
        shahrah_sql::analysis::KeyType::Int => {
            let mut bytes = [0u8; 8];
            for (slot, byte) in bytes.iter_mut().zip(key.iter()) {
                *slot = *byte;
            }
            i64::from_le_bytes(bytes).to_string()
        }
        _ => String::from_utf8_lossy(key).into_owned(),
    };
    format!("delete from {table} where {column} = '{}'", quote(&literal))
}

async fn rows_for(
    shared: &Shared,
    routing: &crate::config::Loaded,
    region: &str,
    logical: shahrah_hash::shard::LogicalShard,
    key: &[u8],
    database: &str,
) -> Result<bool, SessionError> {
    let decision = shahrah_routing::router::route_in(
        &routing.topology,
        Some(region),
        logical,
        shahrah_routing::router::Intent::Write,
    )
    .map_err(|cause| SessionError::Relocate(cause.to_string()))?;
    for table in routing.policy.geo_tables() {
        let column = routing.policy.key_column(&table).unwrap_or("id");
        let key_type = routing
            .policy
            .key_type(&table)
            .unwrap_or(shahrah_sql::analysis::KeyType::Int);
        let literal = match key_type {
            shahrah_sql::analysis::KeyType::Int => {
                let mut bytes = [0u8; 8];
                for (slot, byte) in bytes.iter_mut().zip(key.iter()) {
                    *slot = *byte;
                }
                i64::from_le_bytes(bytes).to_string()
            }
            _ => String::from_utf8_lossy(key).into_owned(),
        };
        let sql = format!(
            "select count(*) from {table} where {column} = '{}'",
            quote(&literal)
        );
        let counted = one_query(shared, &decision.address, database, &sql)
            .await?
            .and_then(|text| text.parse::<i64>().ok())
            .unwrap_or(0);
        if counted > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}
