use std::collections::HashMap;

use pg_query::protobuf::{a_const, node::Node as NodeEnum, ResTarget, SelectStmt};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SqlError {
    #[error("statement did not parse: {0}")]
    Parse(String),

    #[error("statement is empty")]
    Empty,

    #[error("a request may carry one statement, this carried {count}")]
    Multiple { count: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    TransactionBegin,
    TransactionEnd,
    TransactionOther,
    Utility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    Parameter(u16),
    Int(i64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hint {
    Key(String),
    Shard(u16),
}

pub const HINT_MARKER: &str = "shahrah:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintError {
    Unterminated,
    Empty,
    UnknownDirective,
    BadShard,
    Repeated,
}

impl HintError {
    #[must_use]
    pub const fn why(self) -> &'static str {
        match self {
            Self::Unterminated => {
                "a shahrah hint was opened with /* and never closed, so shahrah cannot tell \
                 what it was asked to do"
            }
            Self::Empty => "a shahrah hint carries no directive",
            Self::UnknownDirective => {
                "a shahrah hint names a directive shahrah does not know; it understands \
                 key=<value> and shard=<number>"
            }
            Self::BadShard => "a shahrah hint names a shard that is not a number in 1..=65535",
            Self::Repeated => "a statement carries more than one shahrah hint",
        }
    }
}

pub fn parse_hint(sql: &str) -> Result<Option<Hint>, HintError> {
    let mut found: Option<Hint> = None;
    let mut rest = sql;
    while let Some(open) = rest.find("/*") {
        let after = rest.get(open.saturating_add(2)..).unwrap_or("");
        let Some(close) = after.find("*/") else {
            return if after.contains(HINT_MARKER) {
                Err(HintError::Unterminated)
            } else {
                Ok(found)
            };
        };
        let body = after.get(..close).unwrap_or("");
        rest = after.get(close.saturating_add(2)..).unwrap_or("");
        let Some(directive) = body.find(HINT_MARKER) else {
            continue;
        };
        let text = body
            .get(directive.saturating_add(HINT_MARKER.len())..)
            .unwrap_or("")
            .trim();
        if found.is_some() {
            return Err(HintError::Repeated);
        }
        found = Some(one_directive(text)?);
    }
    Ok(found)
}

fn one_directive(text: &str) -> Result<Hint, HintError> {
    if text.is_empty() {
        return Err(HintError::Empty);
    }
    let (name, value) = text.split_once('=').ok_or(HintError::UnknownDirective)?;
    let value = value.trim();
    match name.trim().to_ascii_lowercase().as_str() {
        "key" => {
            let unquoted = match value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
                Some(inner) => inner.replace("''", "'"),
                None => value.to_owned(),
            };
            if unquoted.is_empty() && !value.starts_with('\'') {
                return Err(HintError::Empty);
            }
            Ok(Hint::Key(unquoted))
        }
        "shard" => value
            .parse::<u16>()
            .ok()
            .filter(|number| *number > 0)
            .map(Hint::Shard)
            .ok_or(HintError::BadShard),
        _ => Err(HintError::UnknownDirective),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routing {
    Single { source: KeySource, key_type: KeyType },
    Pinned { shard: u16 },
    NoShardedTable,
    KeyMissing { table: String },
    Unsupported(&'static str),
    EveryShard {
        what: &'static str,
        instead: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderKey {
    pub column: String,
    pub descending: bool,
    pub nulls_first: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aggregate {
    CountStar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub access: Access,
    pub tables: Vec<String>,
    pub classes: Vec<(String, Option<TableClass>)>,
    pub routing: Routing,
    pub order_by: Vec<OrderKey>,
    pub limit: Option<i64>,
    pub aggregate: Option<Aggregate>,
    pub mergeable: bool,
    pub by_hint: bool,
    pub key_at: Option<u32>,
}

impl Analysis {
    fn plain(access: Access, tables: Vec<String>, routing: Routing) -> Self {
        Self {
            access,
            classes: Vec::new(),
            tables,
            routing,
            order_by: Vec::new(),
            limit: None,
            aggregate: None,
            mergeable: false,
            by_hint: false,
            key_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Int,
    Text,
    Uuid,
    Bytea,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct KeySpec {
    pub column: String,
    #[serde(rename = "type")]
    pub key_type: KeyType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableClass {
    GeoPartitioned,
    Replicated,
}

impl TableClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GeoPartitioned => "geo-partitioned",
            Self::Replicated => "replicated",
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReplicatedSpec {
    pub writer_region: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error(
        "table \"{table}\" is declared both geo-partitioned and replicated; D2 gives a table \
         one class, and shahrah will not choose between them"
    )]
    TwoClasses { table: String },

    #[error(
        "table \"{table}\" is replicated with writer region \"{region}\", which the topology \
         does not hold"
    )]
    UnknownWriterRegion { table: String, region: String },

    #[error("table \"{table}\" is replicated, so it cannot also opt into broadcast")]
    ReplicatedBroadcast { table: String },
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    #[serde(default)]
    keys: HashMap<String, KeySpec>,
    #[serde(default)]
    replicated: HashMap<String, ReplicatedSpec>,
    #[serde(default)]
    broadcast: Vec<String>,
}

impl Policy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_key(mut self, table: &str, column: &str, key_type: KeyType) -> Self {
        self.keys.insert(
            table.to_lowercase(),
            KeySpec {
                column: column.to_lowercase(),
                key_type,
            },
        );
        self
    }

    #[must_use]
    pub fn with_broadcast(mut self, table: &str) -> Self {
        self.broadcast.push(table.to_lowercase());
        self
    }

    #[must_use]
    pub fn bare(table: &str) -> &str {
        table.rsplit('.').next().unwrap_or(table)
    }

    pub fn key_for(&self, table: &str) -> Option<&KeySpec> {
        self.keys.get(&Self::bare(table).to_lowercase())
    }

    #[must_use]
    pub fn key_column(&self, table: &str) -> Option<&str> {
        self.key_for(table).map(|spec| spec.column.as_str())
    }

    #[must_use]
    pub fn key_type(&self, table: &str) -> Option<KeyType> {
        self.key_for(table).map(|spec| spec.key_type)
    }

    #[must_use]
    pub fn with_replicated(mut self, table: &str, writer_region: &str) -> Self {
        self.replicated.insert(
            table.to_lowercase(),
            ReplicatedSpec {
                writer_region: writer_region.to_owned(),
            },
        );
        self
    }

    #[must_use]
    pub fn class_of(&self, table: &str) -> Option<TableClass> {
        let name = Self::bare(table).to_lowercase();
        if self.keys.contains_key(&name) {
            return Some(TableClass::GeoPartitioned);
        }
        if self.replicated.contains_key(&name) {
            return Some(TableClass::Replicated);
        }
        None
    }

    #[must_use]
    pub fn writer_region(&self, table: &str) -> Option<&str> {
        self.replicated
            .get(&Self::bare(table).to_lowercase())
            .map(|spec| spec.writer_region.as_str())
    }

    #[must_use]
    pub fn is_replicated(&self, table: &str) -> bool {
        self.replicated.contains_key(&Self::bare(table).to_lowercase())
    }

    pub fn check(&self, regions: &[String]) -> Result<(), PolicyError> {
        for table in self.replicated.keys() {
            if self.keys.contains_key(table) {
                return Err(PolicyError::TwoClasses {
                    table: table.clone(),
                });
            }
            if self.broadcast.iter().any(|name| &name.to_lowercase() == table) {
                return Err(PolicyError::ReplicatedBroadcast {
                    table: table.clone(),
                });
            }
        }
        if regions.is_empty() {
            return Ok(());
        }
        for (table, spec) in &self.replicated {
            if !regions.iter().any(|known| known == &spec.writer_region) {
                return Err(PolicyError::UnknownWriterRegion {
                    table: table.clone(),
                    region: spec.writer_region.clone(),
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn replicated_tables(&self) -> Vec<String> {
        let mut names: Vec<String> = self.replicated.keys().cloned().collect();
        names.sort();
        names
    }

    #[must_use]
    pub fn geo_tables(&self) -> Vec<String> {
        let mut names: Vec<String> = self.keys.keys().cloned().collect();
        names.sort();
        names
    }

    #[must_use]
    pub fn geo_tables_with(&self, key_type: KeyType) -> Vec<String> {
        let mut names: Vec<String> = self
            .keys
            .iter()
            .filter(|(_name, spec)| spec.key_type == key_type)
            .map(|(name, _spec)| name.clone())
            .collect();
        names.sort();
        names
    }

    pub fn broadcasts(&self, table: &str) -> bool {
        let bare = Self::bare(table).to_lowercase();
        self.broadcast
            .iter()
            .any(|name| Self::bare(name).to_lowercase() == bare)
    }

    #[must_use]
    pub fn is_sharded(&self, table: &str) -> bool {
        self.keys.contains_key(&Self::bare(table).to_lowercase())
    }
}

const STATEMENT_SEPARATOR: i32 = 59;

#[must_use]
pub fn one_statement(sql: &str) -> bool {
    let Ok(scanned) = pg_query::scan(sql) else {
        return false;
    };
    if scanned.tokens.is_empty() {
        return false;
    }
    let last = scanned.tokens.len().saturating_sub(1);
    !scanned
        .tokens
        .iter()
        .enumerate()
        .any(|(index, token)| token.token == STATEMENT_SEPARATOR && index != last)
}

#[must_use]
pub fn touches_sharded(sql: &str, policy: &Policy) -> bool {
    let Ok(parsed) = pg_query::parse(sql) else {
        return false;
    };
    parsed
        .tables
        .iter()
        .any(|(name, _context)| policy.is_sharded(name))
}

pub fn analyse(sql: &str, policy: &Policy) -> Result<Analysis, SqlError> {
    let hint = match parse_hint(sql) {
        Ok(hint) => hint,
        Err(cause) => {
            return Ok(Analysis::plain(
                Access::Write,
                Vec::new(),
                Routing::Unsupported(cause.why()),
            ))
        }
    };

    let parsed = pg_query::parse(sql).map_err(|error| SqlError::Parse(error.to_string()))?;
    let statements = &parsed.protobuf.stmts;

    if statements.is_empty() {
        return Err(SqlError::Empty);
    }
    if statements.len() > 1 {
        return Err(SqlError::Multiple {
            count: statements.len(),
        });
    }

    let node = statements
        .first()
        .and_then(|raw| raw.stmt.as_ref())
        .and_then(|stmt| stmt.node.as_ref())
        .ok_or(SqlError::Empty)?;

    let mentioned: Vec<String> = parsed
        .tables
        .iter()
        .map(|(name, _context)| name.to_lowercase())
        .collect();

    if let Some(Hint::Shard(shard)) = hint {
        let mut pinned = Analysis::plain(
            match node {
                NodeEnum::SelectStmt(_) => Access::Read,
                _ => Access::Write,
            },
            mentioned,
            Routing::Pinned { shard },
        );
        pinned.by_hint = true;
        return Ok(pinned);
    }

    let mut analysis = match node {
        NodeEnum::SelectStmt(select) => analyse_select(select, policy, &mentioned),
        NodeEnum::InsertStmt(insert) => analyse_insert(insert, policy),
        NodeEnum::UpdateStmt(update) => {
            let table = relation_name(update.relation.as_ref());
            if let Some(reason) = writes_beyond_its_target(table.as_deref(), &mentioned, policy) {
                Analysis::plain(Access::Write, mentioned, Routing::Unsupported(reason))
            } else if assigns_the_key(update, table.as_deref(), policy) {
                Analysis::plain(
                    Access::Write,
                    mentioned,
                    Routing::Unsupported(
                        "this statement assigns to the sharding key, which would move the row \
                         to another shard while writing it in place on this one",
                    ),
                )
            } else {
                single_table(Access::Write, table, update.where_clause.as_deref(), policy)
            }
        }
        NodeEnum::DeleteStmt(delete) => {
            let table = relation_name(delete.relation.as_ref());
            if let Some(reason) = writes_beyond_its_target(table.as_deref(), &mentioned, policy) {
                Analysis::plain(Access::Write, mentioned, Routing::Unsupported(reason))
            } else {
                single_table(Access::Write, table, delete.where_clause.as_deref(), policy)
            }
        }
        NodeEnum::TransactionStmt(statement) => Analysis::plain(match statement.kind {
                1 | 2 => Access::TransactionBegin,
                3 | 4 => Access::TransactionEnd,
                _ => Access::TransactionOther,
            }, Vec::new(), Routing::NoShardedTable),
        NodeEnum::VariableSetStmt(set) => Analysis::plain(
            Access::Utility,
            Vec::new(),
            if changes_identity(&set.name) && !is_utf8_request(set) {
                Routing::Unsupported(
                    "shahrah will not let a statement change this connection's identity or its \
                     encoding: the role was settled at authentication and every backend is \
                     shared, and shahrah speaks UTF-8 to every shard so that results from \
                     different shards can be merged",
                )
            } else {
                Routing::NoShardedTable
            },
        ),
        NodeEnum::VariableShowStmt(_) => {
            Analysis::plain(Access::Utility, Vec::new(), Routing::NoShardedTable)
        }
        NodeEnum::ListenStmt(_) | NodeEnum::UnlistenStmt(_) => Analysis::plain(
            Access::Utility,
            Vec::new(),
            Routing::EveryShard {
                what: "LISTEN would only hear what is announced on the one shard this session \
                       happened to land on, and under transaction pooling not even that for long",
                instead: "Connect directly to the shard whose notifications you want.",
            },
        ),
        _ => {
            let tables: Vec<String> = parsed
                .tables
                .iter()
                .map(|(name, _context)| name.clone())
                .collect();
            let touches_sharded = tables.iter().any(|name| policy.is_sharded(name));
            if touches_sharded {
                Analysis::plain(
                    Access::Write,
                    tables,
                    Routing::Unsupported("statement kind is not routable"),
                )
            } else if stays_in_one_session(node) {
                Analysis::plain(Access::Write, tables, Routing::NoShardedTable)
            } else {
                Analysis::plain(
                    Access::Write,
                    tables,
                    Routing::EveryShard {
                        what: "this statement changes the database itself rather than the rows \
                               in it, and it would reach only the shard it was sent to while \
                               reporting success",
                        instead: "Run it against each shard directly.",
                    },
                )
            }
        }
    };

    analysis.classes = analysis
        .tables
        .iter()
        .map(|table| (table.to_lowercase(), policy.class_of(table)))
        .collect();
    analysis.classes.dedup();

    if let Some(Hint::Key(value)) = hint
        && !matches!(analysis.routing, Routing::Unsupported(_))
    {
        match analysis
            .tables
            .iter()
            .find(|name| policy.is_sharded(name))
            .cloned()
        {
            Some(table) => {
                analysis.routing = Routing::Single {
                    source: KeySource::Text(value),
                    key_type: policy.key_type(&table).unwrap_or(KeyType::Int),
                };
                analysis.key_at = None;
                analysis.by_hint = true;
            }
            None => {
                analysis.routing = Routing::Unsupported(
                    "a shahrah hint gives a sharding key, but the statement names no sharded \
                     table, so there is no key type to read the value as and nothing the key \
                     could route. Use shard=<number> to name a shard directly",
                );
            }
        }
    }

    Ok(analysis)
}

const SETOP_NONE: i32 = 1;
const SORTBY_DESC: i32 = 3;
const SORTBY_NULLS_FIRST: i32 = 2;
const SORTBY_NULLS_LAST: i32 = 3;

fn is_utf8_request(set: &pg_query::protobuf::VariableSetStmt) -> bool {
    if !set.name.eq_ignore_ascii_case("client_encoding") {
        return false;
    }
    let mut values = set.args.iter().filter_map(|node| match node.node.as_ref() {
        Some(NodeEnum::AConst(value)) => match value.val.as_ref() {
            Some(a_const::Val::Sval(text)) => Some(text.sval.clone()),
            _ => None,
        },
        _ => None,
    });
    match (values.next(), values.next()) {
        (Some(only), None) => {
            matches!(only.to_ascii_uppercase().as_str(), "UTF8" | "UTF-8" | "UNICODE")
        }
        _ => false,
    }
}

fn changes_identity(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "role" | "session_authorization" | "client_encoding"
    )
}

fn assigns_the_key(
    update: &pg_query::protobuf::UpdateStmt,
    table: Option<&str>,
    policy: &Policy,
) -> bool {
    let Some(column) = table.and_then(|name| policy.key_column(name)) else {
        return false;
    };
    update.target_list.iter().any(|node| {
        matches!(
            node.node.as_ref(),
            Some(NodeEnum::ResTarget(target)) if target.name.eq_ignore_ascii_case(column)
        )
    })
}

fn writes_beyond_its_target(
    table: Option<&str>,
    mentioned: &[String],
    policy: &Policy,
) -> Option<&'static str> {
    let target = table.map(|name| Policy::bare(name).to_lowercase());
    let stray = mentioned.iter().any(|name| {
        policy.is_sharded(name)
            && Some(Policy::bare(name).to_lowercase()) != target
    });
    stray.then_some(
        "this write reaches a sharded table through a subquery or a CTE, which shahrah cannot \
         route and refuses rather than answering from one shard",
    )
}

fn analyse_select(select: &SelectStmt, policy: &Policy, mentioned: &[String]) -> Analysis {
    let mut tables = Vec::new();
    collect_from(&select.from_clause, &mut tables);
    let visible: Vec<String> = tables.iter().map(|name| name.to_lowercase()).collect();
    let mentions_sharded = mentioned.iter().any(|name| policy.is_sharded(name));

    if select.op != SETOP_NONE && (mentions_sharded || visible.iter().any(|n| policy.is_sharded(n)))
    {
        return Analysis::plain(
            Access::Read,
            tables,
            Routing::Unsupported(
                "a UNION, INTERSECT or EXCEPT over a sharded table cannot be routed as one \
                 statement",
            ),
        );
    }

    if select.with_clause.is_some()
        && (mentions_sharded || visible.iter().any(|name| policy.is_sharded(name)))
    {
        return Analysis::plain(
            Access::Read,
            tables,
            Routing::Unsupported(
                "a WITH clause in a statement that names a sharded table cannot be routed; the \
                 name may also be the CTE's rather than the table's",
            ),
        );
    }

    if mentioned
        .iter()
        .any(|name| policy.is_sharded(name) && !visible.contains(name))
    {
        return Analysis::plain(
            Access::Read,
            tables,
            Routing::Unsupported(
                "a sharded table is read inside a subquery, where shahrah cannot see its key",
            ),
        );
    }

    let sharded: Vec<&String> = tables
        .iter()
        .filter(|name| policy.is_sharded(name))
        .collect();

    let mut key_at = None;
    let routing = match sharded.as_slice() {
        [] => Routing::NoShardedTable,
        [only] => {
            let column = policy.key_column(only).unwrap_or("");
            match select
                .where_clause
                .as_deref()
                .and_then(|clause| find_key(clause, column))
            {
                Some((source, at)) => {
                    key_at = at;
                    Routing::Single {
                        source,
                        key_type: policy.key_type(only).unwrap_or(KeyType::Int),
                    }
                }
                None => Routing::KeyMissing {
                    table: (*only).clone(),
                },
            }
        }
        _ => Routing::Unsupported("more than one sharded table in one statement"),
    };

    let sorted = order_keys(&select.sort_clause);
    let mut analysis = Analysis::plain(Access::Read, tables, routing);
    analysis.key_at = key_at;
    analysis.order_by = sorted.clone().unwrap_or_default();
    analysis.limit = literal_limit(select.limit_count.as_deref());
    analysis.aggregate = count_star(&select.target_list);
    analysis.mergeable = sorted.is_some()
        && select.group_clause.is_empty()
        && select.having_clause.is_none()
        && select.distinct_clause.is_empty()
        && select.limit_offset.is_none()
        && (analysis.aggregate.is_some() || select.target_list.iter().all(is_plain_target));
    analysis
}

fn analyse_insert(
    insert: &pg_query::protobuf::InsertStmt,
    policy: &Policy,
) -> Analysis {
    let table = relation_name(insert.relation.as_ref());
    let tables = table.clone().into_iter().collect::<Vec<String>>();

    let Some(name) = table else {
        return Analysis::plain(Access::Write, tables, Routing::Unsupported("insert without a target relation"));
    };

    if !policy.is_sharded(&name) {
        return Analysis::plain(Access::Write, tables, Routing::NoShardedTable);
    }

    let column = policy.key_column(&name).unwrap_or("").to_owned();
    let position = insert.cols.iter().position(|col| {
        matches!(col.node.as_ref(), Some(NodeEnum::ResTarget(target)) if target_name(target) == column)
    });

    let key_type = policy.key_type(&name).unwrap_or(KeyType::Int);
    let mut key_at = None;
    let routing = match position.and_then(|index| insert_value(insert, index)) {
        Some((source, at)) => {
            key_at = at;
            Routing::Single { source, key_type }
        }
        None => Routing::KeyMissing { table: name },
    };

    let mut analysis = Analysis::plain(Access::Write, tables, routing);
    analysis.key_at = key_at;
    analysis
}

fn insert_value(
    insert: &pg_query::protobuf::InsertStmt,
    index: usize,
) -> Option<(KeySource, Option<u32>)> {
    let select = insert.select_stmt.as_deref()?.node.as_ref()?;
    let NodeEnum::SelectStmt(select) = select else {
        return None;
    };
    if select.values_lists.len() != 1 {
        return None;
    }
    let row = select.values_lists.first()?.node.as_ref()?;
    let NodeEnum::List(list) = row else {
        return None;
    };
    constant(list.items.get(index)?.node.as_ref()?)
}

fn single_table(
    access: Access,
    table: Option<String>,
    where_clause: Option<&pg_query::protobuf::Node>,
    policy: &Policy,
) -> Analysis {
    let tables = table.clone().into_iter().collect::<Vec<String>>();
    let Some(name) = table else {
        return Analysis::plain(access, tables, Routing::Unsupported("statement without a target relation"));
    };

    if !policy.is_sharded(&name) {
        return Analysis::plain(access, tables, Routing::NoShardedTable);
    }

    let column = policy.key_column(&name).unwrap_or("");
    let key_type = policy.key_type(&name).unwrap_or(KeyType::Int);
    let mut key_at = None;
    let routing = match where_clause.and_then(|clause| find_key(clause, column)) {
        Some((source, at)) => {
            key_at = at;
            Routing::Single { source, key_type }
        }
        None => Routing::KeyMissing { table: name },
    };

    let mut analysis = Analysis::plain(access, tables, routing);
    analysis.key_at = key_at;
    analysis
}

fn order_keys(sort: &[pg_query::protobuf::Node]) -> Option<Vec<OrderKey>> {
    let mut keys = Vec::new();
    for item in sort {
        let Some(NodeEnum::SortBy(by)) = item.node.as_ref() else {
            return None;
        };
        let node = by.node.as_deref().and_then(|node| node.node.as_ref())?;
        let NodeEnum::ColumnRef(reference) = node else {
            return None;
        };
        let name = reference
            .fields
            .last()
            .and_then(|field| field.node.as_ref())
            .and_then(|field| match field {
                NodeEnum::String(text) => Some(text.sval.clone()),
                _ => None,
            })?;
        let descending = by.sortby_dir == SORTBY_DESC;
        keys.push(OrderKey {
            column: name,
            descending,
            nulls_first: match by.sortby_nulls {
                SORTBY_NULLS_FIRST => true,
                SORTBY_NULLS_LAST => false,
                _default => descending,
            },
        });
    }
    Some(keys)
}

fn literal_limit(node: Option<&pg_query::protobuf::Node>) -> Option<i64> {
    match constant(node?.node.as_ref()?)? {
        (KeySource::Int(value), _at) => Some(value),
        _ => None,
    }
}

fn count_star(targets: &[pg_query::protobuf::Node]) -> Option<Aggregate> {
    if targets.len() != 1 {
        return None;
    }
    let Some(NodeEnum::ResTarget(target)) = targets.first()?.node.as_ref() else {
        return None;
    };
    let NodeEnum::FuncCall(call) = target.val.as_deref()?.node.as_ref()? else {
        return None;
    };
    let name = call.funcname.last()?.node.as_ref()?;
    let NodeEnum::String(text) = name else {
        return None;
    };
    if text.sval.eq_ignore_ascii_case("count") && call.agg_star {
        Some(Aggregate::CountStar)
    } else {
        None
    }
}

fn is_plain_target(node: &pg_query::protobuf::Node) -> bool {
    let Some(NodeEnum::ResTarget(target)) = node.node.as_ref() else {
        return false;
    };
    matches!(
        target.val.as_deref().and_then(|value| value.node.as_ref()),
        Some(NodeEnum::ColumnRef(_) | NodeEnum::AConst(_))
    )
}

fn collect_from(from: &[pg_query::protobuf::Node], out: &mut Vec<String>) {
    for item in from {
        match item.node.as_ref() {
            Some(NodeEnum::RangeVar(range)) if !range.relname.is_empty() => {
                out.push(if range.schemaname.is_empty() {
                    range.relname.clone()
                } else {
                    format!("{}.{}", range.schemaname, range.relname)
                });
            }
            Some(NodeEnum::JoinExpr(join)) => {
                if let Some(left) = join.larg.as_deref() {
                    collect_from(core::slice::from_ref(left), out);
                }
                if let Some(right) = join.rarg.as_deref() {
                    collect_from(core::slice::from_ref(right), out);
                }
            }
            _ => {}
        }
    }
}

fn stays_in_one_session(node: &NodeEnum) -> bool {
    if let NodeEnum::CreateStmt(create) = node
        && let Some(relation) = create.relation.as_ref()
    {
        return matches!(relation.relpersistence.as_str(), "t");
    }
    matches!(
        node,
        NodeEnum::PrepareStmt(_)
            | NodeEnum::ExecuteStmt(_)
            | NodeEnum::DeallocateStmt(_)
            | NodeEnum::DeclareCursorStmt(_)
            | NodeEnum::FetchStmt(_)
            | NodeEnum::ClosePortalStmt(_)
            | NodeEnum::ExplainStmt(_)
            | NodeEnum::DiscardStmt(_)
            | NodeEnum::LockStmt(_)
            | NodeEnum::ConstraintsSetStmt(_)
            | NodeEnum::NotifyStmt(_)
            | NodeEnum::CopyStmt(_)
    )
}

fn relation_name(relation: Option<&pg_query::protobuf::RangeVar>) -> Option<String> {
    relation
        .map(|range| range.relname.clone())
        .filter(|name| !name.is_empty())
}

fn target_name(target: &ResTarget) -> String {
    target.name.to_lowercase()
}

fn find_key(clause: &pg_query::protobuf::Node, column: &str) -> Option<(KeySource, Option<u32>)> {
    match clause.node.as_ref()? {
        NodeEnum::AExpr(expr) => {
            let operator = expr
                .name
                .first()
                .and_then(|node| node.node.as_ref())
                .and_then(|node| match node {
                    NodeEnum::String(text) => Some(text.sval.as_str()),
                    _ => None,
                })?;
            if operator != "=" {
                return None;
            }
            let left = expr.lexpr.as_deref()?;
            let right = expr.rexpr.as_deref()?;
            if column_matches(left, column) {
                constant(right.node.as_ref()?)
            } else if column_matches(right, column) {
                constant(left.node.as_ref()?)
            } else {
                None
            }
        }
        NodeEnum::BoolExpr(expr) => {
            if expr.boolop != 1 {
                return None;
            }
            expr.args.iter().find_map(|arg| find_key(arg, column))
        }
        _ => None,
    }
}

fn column_matches(node: &pg_query::protobuf::Node, column: &str) -> bool {
    let Some(NodeEnum::ColumnRef(reference)) = node.node.as_ref() else {
        return false;
    };
    reference
        .fields
        .last()
        .and_then(|field| field.node.as_ref())
        .is_some_and(|field| match field {
            NodeEnum::String(text) => text.sval.eq_ignore_ascii_case(column),
            _ => false,
        })
}

fn constant(node: &NodeEnum) -> Option<(KeySource, Option<u32>)> {
    match node {
        NodeEnum::ParamRef(param) => u16::try_from(param.number)
            .ok()
            .map(|number| (KeySource::Parameter(number), None)),
        NodeEnum::AConst(value) => {
            let at = u32::try_from(value.location).ok();
            let source = match value.val.as_ref()? {
                a_const::Val::Ival(number) => KeySource::Int(i64::from(number.ival)),
                a_const::Val::Sval(text) => KeySource::Text(text.sval.clone()),
                a_const::Val::Fval(number) => KeySource::Int(number.fval.parse::<i64>().ok()?),
                _ => return None,
            };
            Some((source, at))
        }
        NodeEnum::TypeCast(cast) => constant(cast.arg.as_deref()?.node.as_ref()?),
        _ => None,
    }
}

pub const FORMAT_TEXT: i16 = 0;
pub const FORMAT_BINARY: i16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedKey {
    Int(i64),
    Text(String),
    Uuid([u8; 16]),
    Bytes(Vec<u8>),
}

impl OwnedKey {
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Int(value) => value.to_le_bytes().to_vec(),
            Self::Text(value) => value.as_bytes().to_vec(),
            Self::Uuid(value) => value.to_vec(),
            Self::Bytes(value) => value.clone(),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeyError {
    #[error("the sharding key was NULL, which cannot address a shard")]
    Null,

    #[error("a {expected} key arrived as {len} bytes in binary format")]
    BinaryWidth { expected: &'static str, len: usize },

    #[error("a {expected} key arrived as text that does not parse")]
    Text { expected: &'static str },

    #[error("the sharding key is not valid UTF-8")]
    NotUtf8,
}

pub fn canonical(
    raw: Option<&[u8]>,
    format: i16,
    key_type: KeyType,
) -> Result<OwnedKey, KeyError> {
    let bytes = raw.ok_or(KeyError::Null)?;
    match key_type {
        KeyType::Int => {
            if format == FORMAT_BINARY {
                widen_integer(bytes)
            } else {
                let text = core::str::from_utf8(bytes).map_err(|_| KeyError::NotUtf8)?;
                text.trim()
                    .parse::<i64>()
                    .map(OwnedKey::Int)
                    .map_err(|_| KeyError::Text { expected: "integer" })
            }
        }
        KeyType::Text => {
            let text = core::str::from_utf8(bytes).map_err(|_| KeyError::NotUtf8)?;
            Ok(OwnedKey::Text(text.to_owned()))
        }
        KeyType::Uuid => {
            if format == FORMAT_BINARY {
                <[u8; 16]>::try_from(bytes)
                    .map(OwnedKey::Uuid)
                    .map_err(|_| KeyError::BinaryWidth {
                        expected: "uuid",
                        len: bytes.len(),
                    })
            } else {
                let text = core::str::from_utf8(bytes).map_err(|_| KeyError::NotUtf8)?;
                parse_uuid(text).map(OwnedKey::Uuid)
            }
        }
        KeyType::Bytea => Ok(OwnedKey::Bytes(bytes.to_vec())),
    }
}

fn widen_integer(bytes: &[u8]) -> Result<OwnedKey, KeyError> {
    match bytes.len() {
        2 => <[u8; 2]>::try_from(bytes)
            .map(|array| OwnedKey::Int(i64::from(i16::from_be_bytes(array))))
            .map_err(|_| KeyError::BinaryWidth {
                expected: "integer",
                len: bytes.len(),
            }),
        4 => <[u8; 4]>::try_from(bytes)
            .map(|array| OwnedKey::Int(i64::from(i32::from_be_bytes(array))))
            .map_err(|_| KeyError::BinaryWidth {
                expected: "integer",
                len: bytes.len(),
            }),
        8 => <[u8; 8]>::try_from(bytes)
            .map(|array| OwnedKey::Int(i64::from_be_bytes(array)))
            .map_err(|_| KeyError::BinaryWidth {
                expected: "integer",
                len: bytes.len(),
            }),
        other => Err(KeyError::BinaryWidth {
            expected: "integer",
            len: other,
        }),
    }
}

fn parse_uuid(text: &str) -> Result<[u8; 16], KeyError> {
    let mut raw = [0u8; 16];
    let mut written = 0usize;
    let mut high: Option<u8> = None;
    for character in text.chars() {
        if character == '-' {
            continue;
        }
        let digit = character
            .to_digit(16)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or(KeyError::Text { expected: "uuid" })?;
        match high.take() {
            None => high = Some(digit),
            Some(first) => {
                let slot = raw
                    .get_mut(written)
                    .ok_or(KeyError::Text { expected: "uuid" })?;
                *slot = first
                    .checked_mul(16)
                    .and_then(|scaled| scaled.checked_add(digit))
                    .ok_or(KeyError::Text { expected: "uuid" })?;
                written = written.saturating_add(1);
            }
        }
    }
    if written != 16 || high.is_some() {
        return Err(KeyError::Text { expected: "uuid" });
    }
    Ok(raw)
}
