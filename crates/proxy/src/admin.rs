use shahrah_protocol::messages::{
    command_complete, data_row, ready_for_query, row_description, TRANSACTION_IDLE,
};
use shahrah_protocol::writer::Writer;

use crate::error::SessionError;
use crate::session::Shared;
use shahrah_hash::shard::LogicalShard;
use shahrah_routing::shard::PhysicalShard;
use shahrah_routing::topology::Topology;

fn placement(shard: &shahrah_routing::topology::Shard) -> &str {
    shard
        .region
        .as_deref()
        .or(shard.primary.region.as_deref())
        .unwrap_or("-")
}

fn owned_logical(topology: &Topology, region: &str, id: PhysicalShard) -> u32 {
    let wanted = if region == "-" { None } else { Some(region) };
    let Some(map) = topology.map_for(wanted) else {
        return 0;
    };
    let mut count = 0u32;
    for index in 0..=u16::MAX {
        if map.get(LogicalShard::from_index(index)).number() == id.number() {
            count = count.saturating_add(1);
        }
    }
    count
}

pub const ADMIN_DATABASE: &str = "shahrah";

#[must_use]
pub fn subject_columns(subject: &str) -> &'static [&'static str] {
    match subject {
        "POOLS" => &["endpoint", "idle", "opened"],
        "TRAFFIC" => &["endpoint", "region", "statements", "errors"],
        "HEALTH" => &["endpoint", "state", "kind", "role_ok", "failures", "behind_primary", "probes", "latency", "last_error"],
        "DRAIN" => &["endpoint", "state"],
        "DIRECTORY" => &["measure", "value"],
        _ => &["measure", "value"],
    }
}

#[must_use]
pub fn subject_rows(shared: &Shared, subject: &str) -> Vec<Vec<String>> {
    match subject {
        "TRAFFIC" => {
            let loaded = shared.routing.load();
            shared
                .traffic
                .snapshot()
                .into_iter()
                .map(|(address, statements, errors)| {
                    let region = loaded.as_deref().map_or_else(String::new, |routing| {
                        routing
                            .topology
                            .shards()
                            .iter()
                            .find_map(|shard| {
                                (shard.primary.address == address
                                    || shard.replicas.iter().any(|r| r.address == address))
                                .then(|| {
                                    shard
                                        .region
                                        .clone()
                                        .or_else(|| shard.primary.region.clone())
                                        .unwrap_or_default()
                                })
                            })
                            .unwrap_or_default()
                    });
                    vec![address, region, statements.to_string(), errors.to_string()]
                })
                .collect()
        }
        "POOLS" => shared
            .pool
            .stats()
            .into_iter()
            .map(|(key, idle, opened)| vec![key, idle.to_string(), opened.to_string()])
            .collect(),
        "HEALTH" => shared
            .health
            .snapshot()
            .into_iter()
            .map(|(address, endpoint)| {
                let behind = behind_primary(shared, &address)
                    .map_or_else(|| "-".to_owned(), |value| value.to_string());
                vec![
                    address,
                    if endpoint.drained {
                        "draining".to_owned()
                    } else {
                        endpoint.state.as_str().to_owned()
                    },
                    if endpoint.is_replica { "replica" } else { "primary" }.to_owned(),
                    if endpoint.role_matches_config { "yes" } else { "NO" }.to_owned(),
                    endpoint.consecutive_failures.to_string(),
                    behind,
                    endpoint.probes.to_string(),
                    endpoint
                        .typical_micros()
                        .map_or_else(|| "-".to_owned(), |micros| format!("{micros} us")),
                    endpoint.last_error.clone().unwrap_or_default(),
                ]
            })
            .collect(),
        "DIRECTORY" => {
            let counts = shared.directory.counts();
            vec![
                vec!["cached_home_regions".to_owned(), counts.entries.to_string()],
                vec!["hits".to_owned(), counts.hits.to_string()],
                vec!["hits_on_an_unplaced_key".to_owned(), counts.negative_hits.to_string()],
                vec!["misses".to_owned(), counts.misses.to_string()],
                vec!["lookups_sent_to_a_shard".to_owned(), counts.lookups.to_string()],
                vec!["lookups_that_failed".to_owned(), counts.failures.to_string()],
                vec!["evictions".to_owned(), counts.evictions.to_string()],
            ]
        }
        _ => Vec::new(),
    }
}

pub struct Alert {
    pub name: &'static str,
    pub subject: String,
    pub detail: String,
}

#[must_use]
pub fn behind_primary(shared: &Shared, address: &str) -> Option<i64> {
    let loaded = shared.routing.load();
    let routing = loaded.as_deref()?;
    let primary = routing.topology.shards().iter().find_map(|shard| {
        shard
            .replicas
            .iter()
            .any(|replica| replica.address == address)
            .then(|| shard.primary.address.clone())
    })?;
    let (ahead, _seen) = shared.health.position(&primary)?;
    let (here, _also) = shared.health.position(address)?;
    Some(i64::try_from(ahead.saturating_sub(here)).unwrap_or(i64::MAX))
}

#[must_use]
pub fn alerts(shared: &Shared) -> Vec<Alert> {
    let mut out = Vec::new();
    for (address, endpoint) in shared.health.snapshot() {
        if endpoint.drained {
            out.push(Alert {
                name: "endpoint_draining",
                subject: address.clone(),
                detail: "taking no new work by an operator's instruction".to_owned(),
            });
            continue;
        }
        if !endpoint.state.usable() {
            out.push(Alert {
                name: "endpoint_down",
                subject: address.clone(),
                detail: endpoint
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "shahrah will not send work here".to_owned()),
            });
        }
        if endpoint.in_recovery.is_some() && !endpoint.role_matches_config {
            out.push(Alert {
                name: "endpoint_role_wrong",
                subject: address.clone(),
                detail: "this endpoint no longer plays the role the topology gives it".to_owned(),
            });
        }
        if let Some(behind) = behind_primary(shared, &address)
            && behind > LAG_ALERT_BYTES
        {
            out.push(Alert {
                name: "replica_behind",
                subject: address.clone(),
                detail: format!(
                    "{behind} bytes behind its primary, past the {LAG_ALERT_BYTES} the alert is \
                     set at. A replica that has stopped replicating shows here; its own apply \
                     lag would not"
                ),
            });
        }
        if let Some(limit) = shared.health.read_lag_limit()
            && let Some(behind) = behind_primary(shared, &address)
            && behind > limit
        {
            out.push(Alert {
                name: "replica_not_reading",
                subject: address.clone(),
                detail: format!(
                    "{behind} bytes behind its primary, past the {limit} the read bound is set \
                     at, so reads for its shard are going to the primary instead. Every read \
                     this replica was carrying is now load the primary is carrying"
                ),
            });
        }
    }

    let loaded = shared.routing.load();
    if let Some(routing) = loaded.as_deref() {
        for region in routing.topology.placed_regions() {
            let mut any = false;
            let mut all_down = true;
            for shard in routing.topology.shards() {
                if shard.region.as_deref() != Some(region) {
                    continue;
                }
                any = true;
                if shared.health.usable(&shard.primary.address) {
                    all_down = false;
                }
            }
            if any && all_down {
                out.push(Alert {
                    name: "region_unreachable",
                    subject: region.to_owned(),
                    detail: "no shard in this region will take work".to_owned(),
                });
            }
        }
    }

    let counts = shared.directory.counts();
    if counts.failures > 0 {
        out.push(Alert {
            name: "directory_unreadable",
            subject: "the home-region directory".to_owned(),
            detail: format!("{} lookups have failed", counts.failures),
        });
    }
    out
}

pub const LAG_ALERT_BYTES: i64 = 64 * 1024 * 1024;

#[must_use]
pub fn report(shared: &Shared, subject: &str) -> String {
    let rows = subject_rows(shared, subject);
    serde_json::to_string(&rows).unwrap_or_else(|_cause| "[]".to_owned())
}

pub async fn fleet_rows(shared: &Shared, subject: &str) -> Vec<(String, Vec<Vec<String>>)> {
    let me = shared
        .routing
        .load()
        .as_deref()
        .and_then(|routing| routing.topology.region().map(str::to_owned))
        .unwrap_or_else(|| "this proxy".to_owned());

    let Some(node) = shared.cluster.get() else {
        return vec![(
            format!("{me} (alone, no raft group)"),
            subject_rows(shared, subject),
        )];
    };

    let mut gathered = Vec::new();
    for (id, address) in node.peers().await {
        if id == node.id {
            gathered.push((format!("{id} {me} (this one)"), subject_rows(shared, subject)));
            continue;
        }
        match shahrah_topology::network::ask_peer(&address, subject).await {
            Ok(payload) => {
                let parsed: Vec<Vec<String>> = serde_json::from_str(&payload).unwrap_or_default();
                if parsed.is_empty() {
                    gathered.push((
                        format!("{id} {address}"),
                        vec![vec!["nothing to report".to_owned()]],
                    ));
                } else {
                    gathered.push((format!("{id} {address}"), parsed));
                }
            }
            Err(cause) => gathered.push((
                format!("{id} {address}"),
                vec![vec![format!("unreachable: {cause}")]],
            )),
        }
    }
    gathered
}

async fn fleet(scratch: &mut Writer, shared: &Shared, subject: &str) -> Result<(), SessionError> {
    if !matches!(subject, "POOLS" | "HEALTH" | "DIRECTORY" | "TRAFFIC") {
        row_description(scratch, &["subject", "trouble"])?;
        data_row(scratch, &[
            Some(subject.as_bytes()),
            Some(b"SHOW FLEET answers for POOLS, HEALTH, DIRECTORY or TRAFFIC"),
        ])?;
        command_complete(scratch, "SELECT 1")?;
        return Ok(());
    }
    let mut names: Vec<&str> = vec!["proxy"];
    names.extend_from_slice(subject_columns(subject));
    row_description(scratch, &names)?;

    let width = subject_columns(subject).len();
    let mut rows = 0u32;
    for (who, answered) in fleet_rows(shared, subject).await {
        for row in answered {
            let mut padded: Vec<String> = row.clone();
            padded.resize(width, "-".to_owned());
            padded.truncate(width);
            let mut fields: Vec<Option<&[u8]>> = vec![Some(who.as_bytes())];
            for value in &padded {
                fields.push(Some(value.as_bytes()));
            }
            data_row(scratch, &fields)?;
            rows = rows.saturating_add(1);
        }
    }
    command_complete(scratch, &format!("SELECT {rows}"))?;
    Ok(())
}

pub(crate) async fn ask_the_directory(
    shared: &Shared,
    routing: &crate::config::Loaded,
    key: &[u8],
    logical: LogicalShard,
) -> Result<Option<String>, SessionError> {
    let decision = shahrah_routing::router::route_in(
        &routing.topology,
        routing.topology.region(),
        logical,
        shahrah_routing::router::Intent::Write,
    )
    .map_err(|cause| SessionError::Relocate(cause.to_string()))?;
    let mut lease = shared
        .pool
        .acquire(&decision.address, "postgres", None)
        .await?;
    let answered = match lease.connection() {
        Ok(backend) => {
            backend
                .collect_query(&shared.directory.statement_for(key))
                .await
        }
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

async fn where_is(scratch: &mut Writer, shared: &Shared, sql: &str) -> Result<(), SessionError> {
    row_description(
        scratch,
        &["answer", "learned_from", "logical", "shard", "endpoint", "local"],
    )?;
    let words: Vec<&str> = sql.split_whitespace().collect();
    let (Some(table), Some(literal)) = (words.get(2).copied(), words.get(3).copied()) else {
        data_row(
            scratch,
            &[
                Some(b"say it as: WHERE IS <table> <key>"),
                Some(b"-"), Some(b"-"), Some(b"-"), Some(b"-"), Some(b"-"),
            ],
        )?;
        command_complete(scratch, "SELECT 1")?;
        return Ok(());
    };
    let literal = literal.trim_matches('\'');

    let loaded = shared.routing.load();
    let Some(routing) = loaded.as_deref() else {
        data_row(scratch, &[Some(b"no topology is loaded"), Some(b"-"), Some(b"-"), Some(b"-"), Some(b"-"), Some(b"-")])?;
        command_complete(scratch, "SELECT 1")?;
        return Ok(());
    };
    let Some(key_type) = routing.policy.key_type(table) else {
        let message = format!("\"{table}\" is not geo-partitioned, so no key of it has a home");
        data_row(scratch, &[Some(message.as_bytes()), Some(b"-"), Some(b"-"), Some(b"-"), Some(b"-"), Some(b"-")])?;
        command_complete(scratch, "SELECT 1")?;
        return Ok(());
    };
    let Ok(owned) = shahrah_sql::analysis::canonical(
        Some(literal.as_bytes()),
        shahrah_sql::analysis::FORMAT_TEXT,
        key_type,
    ) else {
        let message = format!("\"{literal}\" is not a usable key for \"{table}\"");
        data_row(scratch, &[Some(message.as_bytes()), Some(b"-"), Some(b"-"), Some(b"-"), Some(b"-"), Some(b"-")])?;
        command_complete(scratch, "SELECT 1")?;
        return Ok(());
    };
    let key = owned.bytes();
    let logical = LogicalShard::of(
        match &owned {
            shahrah_sql::analysis::OwnedKey::Int(value) => shahrah_hash::key::ShardKey::Int(*value),
            shahrah_sql::analysis::OwnedKey::Uuid(value) => shahrah_hash::key::ShardKey::Uuid(*value),
            shahrah_sql::analysis::OwnedKey::Bytes(value) => shahrah_hash::key::ShardKey::Bytes(value),
            shahrah_sql::analysis::OwnedKey::Text(value) => shahrah_hash::key::ShardKey::Text(value),
        },
        shahrah_hash::shard::HashVersion::V1,
    );

    let (home, learned) = match shared.directory.cached(&key) {
        Some(shahrah_routing::directory::Known::Home(region)) => {
            (Some(region.to_string()), "the in-proxy cache".to_owned())
        }
        Some(shahrah_routing::directory::Known::Unplaced) => {
            (None, "the cache, which holds it as unplaced".to_owned())
        }
        None => match ask_the_directory(shared, routing, &key, logical).await {
            Ok(Some(region)) => (Some(region), "the directory, read just now".to_owned()),
            Ok(None) => (None, "the directory, which has no row for it".to_owned()),
            Err(cause) => (None, format!("the directory could not be read: {cause}")),
        },
    };

    let region = home.clone().or_else(|| routing.topology.region().map(str::to_owned));
    let decision = region.as_deref().and_then(|region| {
        shahrah_routing::router::route_in(
            &routing.topology,
            Some(region),
            logical,
            shahrah_routing::router::Intent::Write,
        )
        .ok()
    });

    let answer = home.clone().unwrap_or_else(|| "unknown".to_owned());
    let logical_text = logical.get().to_string();
    let shard_text = decision
        .as_ref()
        .map_or_else(|| "-".to_owned(), |found| found.physical.number().to_string());
    let endpoint = decision
        .as_ref()
        .map_or_else(|| "-".to_owned(), |found| found.address.clone());
    let local = match (routing.topology.region(), home.as_deref()) {
        (Some(here), Some(there)) => {
            if here == there { "yes" } else { "no, this proxy is elsewhere" }
        }
        _ => "-",
    };
    data_row(
        scratch,
        &[
            Some(answer.as_bytes()),
            Some(learned.as_bytes()),
            Some(logical_text.as_bytes()),
            Some(shard_text.as_bytes()),
            Some(endpoint.as_bytes()),
            Some(local.as_bytes()),
        ],
    )?;
    command_complete(scratch, "SELECT 1")?;
    Ok(())
}

async fn relocate_command(
    scratch: &mut Writer,
    shared: &Shared,
    sql: &str,
) -> Result<(), SessionError> {
    let words: Vec<&str> = sql.split_whitespace().collect();
    let (Some(table), Some(literal), Some(to)) = (
        words.get(1).copied(),
        words.get(2).copied(),
        words
            .iter()
            .position(|word| word.eq_ignore_ascii_case("to"))
            .and_then(|at| words.get(at.saturating_add(1)).copied()),
    ) else {
        row_description(scratch, &["error"])?;
        data_row(
            scratch,
            &[Some(b"say it as: RELOCATE <table> <key> TO <region>")],
        )?;
        command_complete(scratch, "SELECT 1")?;
        return Ok(());
    };
    let literal = literal.trim_matches('\'');

    let loaded = shared.routing.load();
    let key_type = loaded
        .as_deref()
        .and_then(|routing| routing.policy.key_type(table));
    let Some(key_type) = key_type else {
        row_description(scratch, &["error"])?;
        let message = format!("\"{table}\" is not a geo-partitioned table");
        data_row(scratch, &[Some(message.as_bytes())])?;
        command_complete(scratch, "SELECT 1")?;
        return Ok(());
    };
    let key = match shahrah_sql::analysis::canonical(
        Some(literal.as_bytes()),
        shahrah_sql::analysis::FORMAT_TEXT,
        key_type,
    ) {
        Ok(owned) => owned.bytes(),
        Err(cause) => {
            row_description(scratch, &["error"])?;
            let message = format!("\"{literal}\" is not a usable key for \"{table}\": {cause}");
            data_row(scratch, &[Some(message.as_bytes())])?;
            command_complete(scratch, "SELECT 1")?;
            return Ok(());
        }
    };

    row_description(scratch, &["moved", "rows", "from", "to", "held_ms"])?;
    match crate::relocate::relocate(shared, table, literal, &key, to, "postgres").await {
        Ok(moved) => {
            let mut rows = 0u32;
            for (name, count) in &moved.table_rows {
                let count = count.to_string();
                let held = moved.held.as_millis().to_string();
                data_row(
                    scratch,
                    &[
                        Some(name.as_bytes()),
                        Some(count.as_bytes()),
                        Some(moved.from.as_bytes()),
                        Some(moved.to.as_bytes()),
                        Some(held.as_bytes()),
                    ],
                )?;
                rows = rows.saturating_add(1);
            }
            command_complete(scratch, &format!("SELECT {rows}"))?;
        }
        Err(cause) => {
            let message = cause.to_string();
            data_row(
                scratch,
                &[
                    Some(b"none"),
                    Some(b"0"),
                    Some(b"-"),
                    Some(b"-"),
                    Some(message.as_bytes()),
                ],
            )?;
            command_complete(scratch, "SELECT 1")?;
        }
    }
    Ok(())
}

const LAG_QUERY: &str = "select subname, coalesce(received_lsn::text,'-'), \
     coalesce(round(extract(epoch from (now() - latest_end_time)))::text,'-') \
     from pg_stat_subscription order by subname";

async fn replication_lag(shared: &Shared) -> Vec<(String, String, String, String, String)> {
    let loaded = shared.routing.load();
    let Some(routing) = loaded.as_deref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for shard in routing.topology.shards() {
        let region = shard
            .region
            .as_deref()
            .or(shard.primary.region.as_deref())
            .unwrap_or("-")
            .to_owned();
        let endpoint = shard.primary.address.clone();
        if !shared.health.usable(&endpoint) {
            out.push((region, endpoint, "-".to_owned(), "-".to_owned(), "down".to_owned()));
            continue;
        }
        let mut lease = match shared.pool.acquire(&endpoint, "postgres", None).await {
            Ok(lease) => lease,
            Err(_cause) => {
                out.push((region, endpoint, "-".to_owned(), "-".to_owned(), "unreachable".to_owned()));
                continue;
            }
        };
        let answered = match lease.connection() {
            Ok(backend) => backend.collect_query(LAG_QUERY).await,
            Err(cause) => Err(cause),
        };
        lease.release().await;
        let Ok(collected) = answered else {
            out.push((region, endpoint, "-".to_owned(), "-".to_owned(), "unreadable".to_owned()));
            continue;
        };
        if collected.rows.is_empty() {
            out.push((
                region,
                endpoint,
                "none".to_owned(),
                "-".to_owned(),
                "this copy is an origin, not a subscriber".to_owned(),
            ));
            continue;
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
                    .map_or_else(|| "-".to_owned(), |v| String::from_utf8_lossy(v).into_owned())
            };
            out.push((region.clone(), endpoint.clone(), text(0), text(1), text(2)));
        }
    }
    out
}

pub async fn respond(
    scratch: &mut Writer,
    shared: &Shared,
    sql: &str,
) -> Result<(), SessionError> {
    let normalised = sql
        .trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
        .to_uppercase();
    scratch.clear();

    if normalised.starts_with("WHERE IS ") {
        where_is(scratch, shared, sql.trim().trim_end_matches(';')).await?;
        ready_for_query(scratch, TRANSACTION_IDLE)?;
        return Ok(());
    }

    if let Some(subject) = normalised.strip_prefix("SHOW FLEET ") {
        fleet(scratch, shared, subject.trim()).await?;
        ready_for_query(scratch, TRANSACTION_IDLE)?;
        return Ok(());
    }

    if normalised.starts_with("DRAIN ") || normalised.starts_with("UNDRAIN ") {
        let draining = normalised.starts_with("DRAIN ");
        let words: Vec<&str> = sql.trim().trim_end_matches(';').split_whitespace().collect();
        row_description(scratch, &["endpoint", "state"])?;
        match words.get(1).copied() {
            Some(endpoint) => {
                let known = shared.routing.load().as_deref().is_some_and(|routing| {
                    routing.topology.shards().iter().any(|shard| {
                        shard.primary.address == endpoint
                            || shard.replicas.iter().any(|r| r.address == endpoint)
                    })
                });
                if known {
                    shared.health.set_drained(endpoint, draining);
                    let state = if draining {
                        "draining: no new work, transactions already there finish"
                    } else {
                        "taking work again"
                    };
                    data_row(scratch, &[Some(endpoint.as_bytes()), Some(state.as_bytes())])?;
                } else {
                    data_row(
                        scratch,
                        &[
                            Some(endpoint.as_bytes()),
                            Some(b"this topology holds no such endpoint"),
                        ],
                    )?;
                }
            }
            None => {
                data_row(scratch, &[Some(b"-"), Some(b"say it as: DRAIN <endpoint>")])?;
            }
        }
        command_complete(scratch, "SELECT 1")?;
        ready_for_query(scratch, TRANSACTION_IDLE)?;
        return Ok(());
    }

    if normalised == "TRACE" || normalised.starts_with("TRACE ") {
        let words: Vec<&str> = sql.trim().trim_end_matches(';').split_whitespace().collect();
        row_description(scratch, &["setting", "value"])?;
        let rows: u32;
        let say = |scratch: &mut Writer, name: &str, value: &str| -> Result<(), SessionError> {
            data_row(scratch, &[Some(name.as_bytes()), Some(value.as_bytes())])?;
            Ok(())
        };
        let verb = words.get(1).copied().unwrap_or_default().to_ascii_uppercase();
        match (verb.as_str(), words.get(2).copied(), words.get(3).copied()) {
            ("EVERY", Some(count), _) => match count.parse::<u64>() {
                Ok(asked) => {
                    let every = asked.max(1);
                    shared.tracing.sample_every(every);
                    say(scratch, "sampling one statement in", &every.to_string())?;
                    rows = 1;
                }
                Err(_cause) => {
                    say(scratch, "TRACE EVERY wants a number", count)?;
                    rows = 1;
                }
            },
            ("OFF", _, _) => {
                let cleared = shared.tracing.unwatch_all();
                say(scratch, "keys no longer watched", &cleared.to_string())?;
                rows = 1;
            }
            ("KEY", Some(table), Some(literal)) => {
                let table = table.trim_matches('"').trim_matches('\'');
                let loaded = shared.routing.load();
                let key_type = loaded
                    .as_deref()
                    .and_then(|routing| routing.policy.key_type(table));
                match key_type.and_then(|kind| {
                    shahrah_sql::analysis::canonical(
                        Some(literal.trim_matches('\'').as_bytes()),
                        shahrah_sql::analysis::FORMAT_TEXT,
                        kind,
                    )
                    .ok()
                }) {
                    Some(owned) => {
                        shared.tracing.watch(owned.bytes());
                        say(scratch, "now tracing every statement for", literal)?;
                        rows = 1;
                    }
                    None => {
                        say(scratch, "not a usable key for that table", literal)?;
                        rows = 1;
                    }
                }
            }
            (unknown, _, _) if !unknown.is_empty() => {
                say(scratch, "TRACE does not understand", &words.get(1..).unwrap_or_default().join(" "))?;
                rows = 1;
            }
            _ => {
                let (every, watched, seen, traced) = shared.tracing.state();
                say(scratch, "one statement in", &every.to_string())?;
                say(scratch, "keys watched in full", &watched.to_string())?;
                say(scratch, "statements considered", &seen.to_string())?;
                say(scratch, "statements traced", &traced.to_string())?;
                rows = 4;
            }
        }
        command_complete(scratch, &format!("SELECT {rows}"))?;
        ready_for_query(scratch, TRANSACTION_IDLE)?;
        return Ok(());
    }

    if normalised.starts_with("REPAIR") {
        row_description(scratch, &["key", "outcome", "home"])?;
        let mut rows = 0u32;
        match crate::relocate::repair(shared, "postgres").await {
            Ok(fixed) => {
                for one in &fixed {
                    data_row(
                        scratch,
                        &[
                            Some(one.key.as_bytes()),
                            Some(one.outcome.as_bytes()),
                            Some(one.home.as_bytes()),
                        ],
                    )?;
                    rows = rows.saturating_add(1);
                }
                if fixed.is_empty() {
                    data_row(
                        scratch,
                        &[Some(b"-"), Some(b"no move was left half done"), Some(b"-")],
                    )?;
                    rows = 1;
                }
            }
            Err(cause) => {
                let message = cause.to_string();
                data_row(scratch, &[Some(b"-"), Some(message.as_bytes()), Some(b"-")])?;
                rows = 1;
            }
        }
        command_complete(scratch, &format!("SELECT {rows}"))?;
        ready_for_query(scratch, TRANSACTION_IDLE)?;
        return Ok(());
    }

    if normalised.starts_with("REBALANCE") {
        let words: Vec<&str> = sql.split_whitespace().collect();
        let loaded = shared.routing.load();
        let region = words.get(1).map(|word| (*word).to_owned()).or_else(|| {
            loaded
                .as_deref()
                .and_then(|routing| routing.topology.region().map(str::to_owned))
        });
        row_description(scratch, &["table", "from", "to", "rows"])?;
        let mut rows = 0u32;
        match region {
            Some(region) => match crate::relocate::rebalance(shared, &region, "postgres").await {
                Ok(moved) => {
                    for one in &moved {
                        let count = one.rows.to_string();
                        data_row(
                            scratch,
                            &[
                                Some(one.table.as_bytes()),
                                Some(one.from.as_bytes()),
                                Some(one.to.as_bytes()),
                                Some(count.as_bytes()),
                            ],
                        )?;
                        rows = rows.saturating_add(1);
                    }
                    if moved.is_empty() {
                        data_row(
                            scratch,
                            &[Some(b"-"), Some(b"-"), Some(b"-"), Some(b"every row is already on the shard that owns it")],
                        )?;
                        rows = 1;
                    }
                }
                Err(cause) => {
                    let message = cause.to_string();
                    data_row(scratch, &[Some(b"-"), Some(b"-"), Some(b"-"), Some(message.as_bytes())])?;
                    rows = 1;
                }
            },
            None => {
                data_row(scratch, &[Some(b"-"), Some(b"-"), Some(b"-"), Some(b"say which region: REBALANCE <region>")])?;
                rows = 1;
            }
        }
        command_complete(scratch, &format!("SELECT {rows}"))?;
        ready_for_query(scratch, TRANSACTION_IDLE)?;
        return Ok(());
    }

    if normalised.starts_with("RELOCATE ") {
        relocate_command(scratch, shared, sql.trim().trim_end_matches(';')).await?;
        ready_for_query(scratch, TRANSACTION_IDLE)?;
        return Ok(());
    }

    match normalised.as_str() {
        "SHOW POOLS" => {
            row_description(scratch, &["database", "idle", "opened"])?;
            let mut rows = 0u32;
            for (database, idle, opened) in shared.pool.stats() {
                data_row(
                    scratch,
                    &[
                        Some(database.as_bytes()),
                        Some(idle.to_string().as_bytes()),
                        Some(opened.to_string().as_bytes()),
                    ],
                )?;
                rows = rows.saturating_add(1);
            }
            command_complete(scratch, &format!("SELECT {rows}"))?;
        }
        "SHOW CLIENTS" => {
            row_description(scratch, &["metric", "value"])?;
            let tracked = shared.registry.len().to_string();
            data_row(
                scratch,
                &[Some(b"cancel_keys"), Some(tracked.as_bytes())],
            )?;
            command_complete(scratch, "SELECT 1")?;
        }
        "SHOW SERVERS" => {
            row_description(scratch, &["setting", "value"])?;
            let rows: [(&str, String); 3] = [
                ("backend", shared.backend_address.clone()),
                ("backend_tls", format!("{:?}", shared.backend_tls)),
                ("client_tls", shared.acceptor.is_some().to_string()),
            ];
            for (name, value) in &rows {
                data_row(scratch, &[Some(name.as_bytes()), Some(value.as_bytes())])?;
            }
            command_complete(scratch, "SELECT 3")?;
        }
        "SHOW TOPOLOGY" => {
            row_description(scratch, &["shard", "role", "endpoint", "region", "logical"])?;
            let loaded = shared.routing.load();
            let mut rows = 0u32;
            if let Some(routing) = loaded.as_deref() {
                for shard in routing.topology.shards() {
                    let region = placement(shard);
                    let owned = owned_logical(&routing.topology, region, shard.id);
                    let number = shard.id.number().to_string();
                    let owned_text = owned.to_string();
                    data_row(
                        scratch,
                        &[
                            Some(number.as_bytes()),
                            Some(b"primary"),
                            Some(shard.primary.address.as_bytes()),
                            Some(region.as_bytes()),
                            Some(owned_text.as_bytes()),
                        ],
                    )?;
                    rows = rows.saturating_add(1);
                    for replica in &shard.replicas {
                        data_row(
                            scratch,
                            &[
                                Some(number.as_bytes()),
                                Some(b"replica"),
                                Some(replica.address.as_bytes()),
                                Some(replica.region.as_deref().unwrap_or("-").as_bytes()),
                                Some(b"-"),
                            ],
                        )?;
                        rows = rows.saturating_add(1);
                    }
                }
            }
            command_complete(scratch, &format!("SELECT {rows}"))?;
        }
        "SHOW HEALTH" => {
            row_description(scratch, subject_columns("HEALTH"))?;
            let mut rows = 0u32;
            for row in subject_rows(shared, "HEALTH") {
                let fields: Vec<Option<&[u8]>> =
                    row.iter().map(|value| Some(value.as_bytes())).collect();
                data_row(scratch, &fields)?;
                rows = rows.saturating_add(1);
            }
            command_complete(scratch, &format!("SELECT {rows}"))?;
        }
        "SHOW MOVERS" => {
            row_description(scratch, &["key", "home", "pulled_by", "share", "samples"])?;
            let loaded = shared.routing.load();
            let mut rows = 0u32;
            let home_of = |key: &[u8]| match shared.directory.cached(key) {
                Some(shahrah_routing::directory::Known::Home(home)) => Some(home.to_string()),
                _ => loaded
                    .as_deref()
                    .and_then(|l| l.topology.region().map(str::to_owned)),
            };
            for found in shared.relocations.candidates(&home_of) {
                let key = found
                    .key
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let share = format!("{:.0}%", found.share * 100.0);
                let samples = found.samples.to_string();
                data_row(
                    scratch,
                    &[
                        Some(key.as_bytes()),
                        Some(found.home.as_bytes()),
                        Some(found.pulling.as_bytes()),
                        Some(share.as_bytes()),
                        Some(samples.as_bytes()),
                    ],
                )?;
                rows = rows.saturating_add(1);
            }
            command_complete(scratch, &format!("SELECT {rows}"))?;
        }
        "SHOW REPLICATION" => {
            row_description(
                scratch,
                &["region", "endpoint", "subscription", "received_lsn", "behind_seconds"],
            )?;
            let mut rows = 0u32;
            for (region, endpoint, subscription, lsn, behind) in replication_lag(shared).await {
                data_row(
                    scratch,
                    &[
                        Some(region.as_bytes()),
                        Some(endpoint.as_bytes()),
                        Some(subscription.as_bytes()),
                        Some(lsn.as_bytes()),
                        Some(behind.as_bytes()),
                    ],
                )?;
                rows = rows.saturating_add(1);
            }
            command_complete(scratch, &format!("SELECT {rows}"))?;
        }
        "SHOW ALERTS" => {
            row_description(scratch, &["alert", "subject", "detail"])?;
            let raised = alerts(shared);
            for one in &raised {
                data_row(
                    scratch,
                    &[
                        Some(one.name.as_bytes()),
                        Some(one.subject.as_bytes()),
                        Some(one.detail.as_bytes()),
                    ],
                )?;
            }
            let count = raised.len();
            if raised.is_empty() {
                data_row(scratch, &[Some(b"-"), Some(b"-"), Some(b"nothing is raising an alert")])?;
                command_complete(scratch, "SELECT 1")?;
            } else {
                command_complete(scratch, &format!("SELECT {count}"))?;
            }
        }
        "SHOW TRAFFIC" => {
            row_description(scratch, subject_columns("TRAFFIC"))?;
            let mut rows = 0u32;
            for row in subject_rows(shared, "TRAFFIC") {
                let fields: Vec<Option<&[u8]>> =
                    row.iter().map(|value| Some(value.as_bytes())).collect();
                data_row(scratch, &fields)?;
                rows = rows.saturating_add(1);
            }
            command_complete(scratch, &format!("SELECT {rows}"))?;
        }
        "SHOW PLACEMENT" => {
            row_description(
                scratch,
                &["table", "class", "key_column", "key_type", "writer_region"],
            )?;
            let loaded = shared.routing.load();
            let mut rows = 0u32;
            if let Some(routing) = loaded.as_deref() {
                for table in routing.policy.geo_tables() {
                    let column = routing.policy.key_column(&table).unwrap_or("-").to_owned();
                    let kind = routing
                        .policy
                        .key_type(&table)
                        .map_or_else(|| "-".to_owned(), |found| format!("{found:?}").to_lowercase());
                    data_row(
                        scratch,
                        &[
                            Some(table.as_bytes()),
                            Some(b"geo-partitioned"),
                            Some(column.as_bytes()),
                            Some(kind.as_bytes()),
                            Some(b"-"),
                        ],
                    )?;
                    rows = rows.saturating_add(1);
                }
                for table in routing.policy.replicated_tables() {
                    let writer = routing.policy.writer_region(&table).unwrap_or("-").to_owned();
                    data_row(
                        scratch,
                        &[
                            Some(table.as_bytes()),
                            Some(b"replicated"),
                            Some(b"-"),
                            Some(b"-"),
                            Some(writer.as_bytes()),
                        ],
                    )?;
                    rows = rows.saturating_add(1);
                }
            }
            command_complete(scratch, &format!("SELECT {rows}"))?;
        }
        "SHOW DIRECTORY" => {
            row_description(scratch, &["measure", "value"])?;
            let counts = shared.directory.counts();
            let rows: [(&str, String); 7] = [
                ("cached_home_regions", counts.entries.to_string()),
                ("hits", counts.hits.to_string()),
                ("hits_on_an_unplaced_key", counts.negative_hits.to_string()),
                ("misses", counts.misses.to_string()),
                ("lookups_sent_to_a_shard", counts.lookups.to_string()),
                ("lookups_that_failed", counts.failures.to_string()),
                ("evictions", counts.evictions.to_string()),
            ];
            for (measure, value) in &rows {
                data_row(scratch, &[Some(measure.as_bytes()), Some(value.as_bytes())])?;
            }
            command_complete(scratch, "SELECT 7")?;
        }
        "SHOW HELP" => {
            row_description(scratch, &["command"])?;
            for command in [
                "SHOW POOLS",
                "SHOW CLIENTS",
                "SHOW SERVERS",
                "SHOW TOPOLOGY",
                "SHOW HEALTH",
                "SHOW DIRECTORY",
                "SHOW REPLICATION",
                "SHOW PLACEMENT",
                "SHOW MOVERS",
                "WHERE IS <table> <key>",
                "REBALANCE <region>",
                "REPAIR",
                "SHOW TRAFFIC",
                "SHOW ALERTS",
                "DRAIN <endpoint> | UNDRAIN <endpoint>",
                "TRACE | TRACE EVERY <n> | TRACE KEY <table> <key> | TRACE OFF",
                "SHOW FLEET POOLS | HEALTH | DIRECTORY | TRAFFIC",
                "SHOW HELP",
            ] {
                data_row(scratch, &[Some(command.as_bytes())])?;
            }
            command_complete(scratch, "SELECT 18")?;
        }
        _ => {
            row_description(scratch, &["error"])?;
            data_row(scratch, &[Some(b"unknown admin command; try SHOW HELP")])?;
            command_complete(scratch, "SELECT 1")?;
        }
    }

    ready_for_query(scratch, TRANSACTION_IDLE)?;
    Ok(())
}
