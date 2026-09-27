use shahrah_protocol::messages::{
    bind_complete, command_complete, data_row, data_row_fields, parse_complete, ready_for_query,
    row_description, TRANSACTION_IDLE,
};
use shahrah_protocol::reader::Reader;
use shahrah_protocol::writer::Writer;
use shahrah_sql::analysis::{Aggregate, Analysis, OrderKey};
use tracing::debug;

use crate::connection::Collected;
use crate::error::SessionError;

const OID_INT2: i32 = 21;
const OID_INT4: i32 = 23;
const OID_INT8: i32 = 20;
const OID_OID: i32 = 26;
const OID_FLOAT4: i32 = 700;
const OID_FLOAT8: i32 = 701;
const OID_NUMERIC: i32 = 1700;
const OID_BOOL: i32 = 16;
const OID_BYTEA: i32 = 17;
const OID_DATE: i32 = 1082;
const OID_TIME: i32 = 1083;
const OID_TIMESTAMP: i32 = 1114;
const OID_TIMESTAMPTZ: i32 = 1184;
const OID_UUID: i32 = 2950;
const OID_TEXT: i32 = 25;
const OID_VARCHAR: i32 = 1043;
const OID_BPCHAR: i32 = 1042;
const OID_NAME: i32 = 19;

pub const MAX_RANKED_VALUES: usize = 20_000;

#[derive(Debug, Clone)]
pub enum TextOrder {
    Bytes,
    Ranked(std::collections::HashMap<Vec<u8>, i64>),
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ordering {
    Numeric,
    Bytes,
    NeedsCollation,
    Unknown,
}

const fn ordering_of(type_oid: i32) -> Ordering {
    match type_oid {
        OID_INT2 | OID_INT4 | OID_INT8 | OID_OID | OID_FLOAT4 | OID_FLOAT8 | OID_NUMERIC => {
            Ordering::Numeric
        }
        OID_BOOL | OID_BYTEA | OID_DATE | OID_TIME | OID_TIMESTAMP | OID_TIMESTAMPTZ
        | OID_UUID => Ordering::Bytes,
        OID_TEXT | OID_VARCHAR | OID_BPCHAR | OID_NAME => Ordering::NeedsCollation,
        _ => Ordering::Unknown,
    }
}

pub struct Merged {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Simple,
    Extended { describe: bool, parsed: bool },
}

impl Framing {
    #[must_use]
    pub const fn is_extended(self) -> bool {
        matches!(self, Self::Extended { .. })
    }

    const fn wants_description(self) -> bool {
        match self {
            Self::Simple => true,
            Self::Extended { describe, .. } => describe,
        }
    }

    const fn owes_parse_complete(self) -> bool {
        matches!(self, Self::Extended { parsed: true, .. })
    }
}

pub fn merge(
    parts: Vec<Collected>,
    analysis: &Analysis,
    scratch: &mut Writer,
    framing: Framing,
    text_order: &TextOrder,
) -> Result<Merged, SessionError> {
    for part in &parts {
        if let Some(failure) = &part.failure {
            return Err(SessionError::BackendRefused {
                code: match failure {
                    SessionError::BackendRefused { code, .. } => code.clone(),
                    _ => String::new(),
                },
                message: failure.to_string(),
            });
        }
    }

    scratch.clear();
    if framing.owes_parse_complete() {
        parse_complete(scratch)?;
    }
    if framing.is_extended() {
        bind_complete(scratch)?;
    }

    if analysis.aggregate == Some(Aggregate::CountStar) {
        let description = parts.iter().find_map(|part| part.description.clone());
        let binary = description
            .as_deref()
            .map(column_formats)
            .transpose()?
            .and_then(|formats| formats.first().copied())
            .unwrap_or(0)
            == 1;
        let total: i64 = parts
            .iter()
            .map(|part| first_integer(part, binary).unwrap_or(0))
            .sum();
        if framing.wants_description() {
            match description.as_deref() {
                Some(raw) => scratch.bytes(raw),
                None => row_description(scratch, &["count"])?,
            }
        }
        if binary {
            data_row(scratch, &[Some(&total.to_be_bytes())])?;
        } else {
            let text = total.to_string();
            data_row(scratch, &[Some(text.as_bytes())])?;
        }
        command_complete(scratch, "SELECT 1")?;
        if !framing.is_extended() {
            ready_for_query(scratch, TRANSACTION_IDLE)?;
        }
        debug!(shards = parts.len(), total, "merged a count");
        return Ok(Merged {
            bytes: scratch.as_bytes().to_vec(),
        });
    }

    let description = parts.iter().find_map(|part| part.description.clone());
    let columns = description
        .as_deref()
        .map(describe_columns)
        .transpose()?
        .unwrap_or_default();

    if !analysis.order_by.is_empty() {
        let plan = match sort_plan(&analysis.order_by, &columns, text_order) {
            Ok(plan) => plan,
            Err(why) => return Err(SessionError::Unmergeable { why }),
        };
        for part in &parts {
            agrees_with_the_shard(&part.rows, &plan)?;
        }
        let mut rows: Vec<Vec<u8>> = parts.into_iter().flat_map(|part| part.rows).collect();
        sort_rows(&mut rows, &plan)?;
        return finish(rows, description, columns, analysis, scratch, framing);
    }

    let rows: Vec<Vec<u8>> = parts.into_iter().flat_map(|part| part.rows).collect();
    finish(rows, description, columns, analysis, scratch, framing)
}

fn finish(
    mut rows: Vec<Vec<u8>>,
    description: Option<Vec<u8>>,
    columns: Vec<Column>,
    analysis: &Analysis,
    scratch: &mut Writer,
    framing: Framing,
) -> Result<Merged, SessionError> {
    let _seen = columns;

    if let Some(limit) = analysis.limit
        && let Ok(limit) = usize::try_from(limit)
    {
        rows.truncate(limit);
    }

    if let Some(description) = description
        && framing.wants_description()
    {
        scratch.bytes(&description);
    }
    let count = rows.len();
    for row in rows {
        scratch.bytes(&row);
    }
    command_complete(scratch, &format!("SELECT {count}"))?;
    if !framing.is_extended() {
        ready_for_query(scratch, TRANSACTION_IDLE)?;
    }
    debug!(rows = count, "merged a broadcast read");
    Ok(Merged {
        bytes: scratch.as_bytes().to_vec(),
    })
}

struct Column {
    name: String,
    type_oid: i32,
}

fn describe_columns(raw: &[u8]) -> Result<Vec<Column>, SessionError> {
    let body = raw.get(5..).unwrap_or(&[]);
    let mut reader = Reader::new(body);
    let count = reader.i16()?.max(0);
    let mut columns = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for _index in 0..count {
        let name = String::from_utf8_lossy(reader.cstring()?).into_owned();
        reader.i32()?;
        reader.i16()?;
        let type_oid = reader.i32()?;
        reader.i16()?;
        reader.i32()?;
        reader.i16()?;
        columns.push(Column { name, type_oid });
    }
    Ok(columns)
}

#[derive(Clone)]
enum Compare {
    Numeric,
    Bytes,
    Ranked(std::sync::Arc<std::collections::HashMap<Vec<u8>, i64>>),
}

#[derive(Clone)]
struct SortStep {
    index: usize,
    how: Compare,
    descending: bool,
    nulls_first: bool,
}

fn sort_plan(
    keys: &[OrderKey],
    columns: &[Column],
    text_order: &TextOrder,
) -> Result<Vec<SortStep>, &'static str> {
    let mut plan = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(index) = columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(&key.column))
        else {
            return Err("the ORDER BY names a column that is not in the result");
        };
        let type_oid = columns.get(index).map_or(0, |column| column.type_oid);
        let how = match ordering_of(type_oid) {
            Ordering::Numeric => Compare::Numeric,
            Ordering::Bytes => Compare::Bytes,
            Ordering::NeedsCollation => match text_order {
                TextOrder::Bytes => Compare::Bytes,
                TextOrder::Ranked(ranks) => {
                    Compare::Ranked(std::sync::Arc::new(ranks.clone()))
                }
                TextOrder::Unavailable => {
                    return Err(
                        "ordering by a text column across shards needs the shards' own \
                         collation, and there were more distinct values than shahrah will \
                         send to a shard to be ordered; narrow the query or add a LIMIT",
                    )
                }
            },
            Ordering::Unknown => {
                return Err(
                    "shahrah does not know how to order this column type across shards",
                )
            }
        };
        plan.push(SortStep {
            index,
            how,
            descending: key.descending,
            nulls_first: key.nulls_first,
        });
    }
    Ok(plan)
}

#[must_use]
pub fn text_columns_in_order(keys: &[OrderKey], description: Option<&[u8]>) -> Vec<usize> {
    let Some(columns) = description.map(describe_columns).transpose().ok().flatten() else {
        return Vec::new();
    };
    keys.iter()
        .filter_map(|key| {
            let index = columns
                .iter()
                .position(|column| column.name.eq_ignore_ascii_case(&key.column))?;
            let type_oid = columns.get(index).map_or(0, |column| column.type_oid);
            matches!(ordering_of(type_oid), Ordering::NeedsCollation).then_some(index)
        })
        .collect()
}

#[must_use]
pub fn values_at(rows: &[Vec<u8>], index: usize) -> Vec<Vec<u8>> {
    rows.iter()
        .filter_map(|row| {
            data_row_fields(row.get(5..).unwrap_or(&[]))
                .ok()
                .and_then(|fields| fields.get(index).cloned().flatten())
        })
        .collect()
}

fn agrees_with_the_shard(rows: &[Vec<u8>], plan: &[SortStep]) -> Result<(), SessionError> {
    let mut previous: Option<Vec<Option<Vec<u8>>>> = None;
    for row in rows {
        let fields = data_row_fields(row.get(5..).unwrap_or(&[]))?;
        if let Some(earlier) = &previous
            && compare_rows(earlier, &fields, plan) == core::cmp::Ordering::Greater
        {
            return Err(SessionError::Unmergeable {
                why: "shahrah's ordering disagrees with the order a shard returned its own \
                      rows in, so merging them would not reproduce what PostgreSQL would \
                      have answered",
            });
        }
        previous = Some(fields);
    }
    Ok(())
}

fn compare_rows(
    left: &[Option<Vec<u8>>],
    right: &[Option<Vec<u8>>],
    plan: &[SortStep],
) -> core::cmp::Ordering {
    for step in plan {
        let a = left.get(step.index).and_then(Option::as_ref);
        let b = right.get(step.index).and_then(Option::as_ref);
        let ordering = match (a, b) {
            (None, None) => core::cmp::Ordering::Equal,
            (None, Some(_)) => {
                if step.nulls_first {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Greater
                }
            }
            (Some(_), None) => {
                if step.nulls_first {
                    core::cmp::Ordering::Greater
                } else {
                    core::cmp::Ordering::Less
                }
            }
            (Some(one), Some(other)) => {
                let value = compare(one, other, &step.how);
                if step.descending {
                    value.reverse()
                } else {
                    value
                }
            }
        };
        if ordering != core::cmp::Ordering::Equal {
            return ordering;
        }
    }
    core::cmp::Ordering::Equal
}

fn sort_rows(rows: &mut [Vec<u8>], plan: &[SortStep]) -> Result<(), SessionError> {
    let mut decoded: Vec<Vec<Option<Vec<u8>>>> = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        decoded.push(data_row_fields(row.get(5..).unwrap_or(&[]))?);
    }

    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|left, right| {
        match (decoded.get(*left), decoded.get(*right)) {
            (Some(one), Some(other)) => compare_rows(one, other, plan),
            _ => core::cmp::Ordering::Equal,
        }
    });

    let sorted: Vec<Vec<u8>> = order
        .into_iter()
        .filter_map(|index| rows.get(index).cloned())
        .collect();
    for (slot, value) in rows.iter_mut().zip(sorted) {
        *slot = value;
    }
    Ok(())
}

fn compare(a: &[u8], b: &[u8], how: &Compare) -> core::cmp::Ordering {
    match how {
        Compare::Numeric => {
            let left = core::str::from_utf8(a)
                .ok()
                .and_then(|text| text.parse::<f64>().ok());
            let right = core::str::from_utf8(b)
                .ok()
                .and_then(|text| text.parse::<f64>().ok());
            match (left, right) {
                (Some(left), Some(right)) => {
                    left.partial_cmp(&right).unwrap_or(core::cmp::Ordering::Equal)
                }
                _ => a.cmp(b),
            }
        }
        Compare::Bytes => a.cmp(b),
        Compare::Ranked(ranks) => match (ranks.get(a), ranks.get(b)) {
            (Some(left), Some(right)) => left.cmp(right),
            _ => a.cmp(b),
        },
    }
}

fn first_integer(part: &Collected, binary: bool) -> Option<i64> {
    let row = part.rows.first()?;
    let fields = data_row_fields(row.get(5..)?).ok()?;
    let value = fields.first()?.as_ref()?;
    if binary {
        return match value.len() {
            2 => Some(i64::from(i16::from_be_bytes([*value.first()?, *value.get(1)?]))),
            4 => Some(i64::from(i32::from_be_bytes([
                *value.first()?,
                *value.get(1)?,
                *value.get(2)?,
                *value.get(3)?,
            ]))),
            8 => {
                let mut wide = [0u8; 8];
                wide.copy_from_slice(value.get(..8)?);
                Some(i64::from_be_bytes(wide))
            }
            _ => None,
        };
    }
    core::str::from_utf8(value).ok()?.parse().ok()
}

fn column_formats(raw: &[u8]) -> Result<Vec<i16>, SessionError> {
    let body = raw.get(5..).unwrap_or(&[]);
    let mut reader = Reader::new(body);
    let count = reader.i16()?.max(0);
    let mut formats = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for _index in 0..count {
        reader.cstring()?;
        reader.i32()?;
        reader.i16()?;
        reader.i32()?;
        reader.i16()?;
        reader.i32()?;
        formats.push(reader.i16()?);
    }
    Ok(formats)
}
