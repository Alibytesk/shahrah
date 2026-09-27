use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::analysis::{analyse, Analysis, KeySource, Policy, Routing, SqlError};

pub const DEFAULT_CAPACITY: usize = 4096;

#[derive(Debug, Default, Clone, Copy)]
pub struct Counts {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub entries: usize,
}

pub struct Cache {
    exact: Mutex<HashMap<String, Arc<Analysis>>>,
    entries: Mutex<HashMap<String, Shaped>>,
    unshapeable: Mutex<HashSet<u64>>,
    capacity: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl Cache {
    #[must_use]
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            exact: Mutex::new(HashMap::with_capacity(capacity.min(1024))),
            entries: Mutex::new(HashMap::with_capacity(capacity.min(1024))),
            unshapeable: Mutex::new(HashSet::with_capacity(capacity.min(1024))),
            capacity: capacity.max(1),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        })
    }

    pub fn analyse(&self, sql: &str, policy: &Policy) -> Result<Arc<Analysis>, SqlError> {
        if let Some(found) = self
            .exact
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(sql)
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(found));
        }
        let print = fingerprint(sql);
        if self
            .unshapeable
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&print)
        {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::new(analyse(sql, policy)?));
        }

        let Some((shape, literals)) = shape_of(sql) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::new(analyse(sql, policy)?));
        };

        let known = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&shape)
            .cloned();
        match known {
            Some(Shaped::Fixed(held)) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(held);
            }
            Some(Shaped::KeyedLiteral(held, at)) => {
                if let Some(span) = literals.get(at)
                    && let Some(rebuilt) = with_key(&held, sql, *span)
                {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(Arc::new(rebuilt));
                }
            }
            None => {}
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        let analysis = Arc::new(analyse(sql, policy)?);
        let Some(verdict) = classify(&analysis, &literals, sql, policy, &shape) else {
            self.remember_unshapeable(print);
            return Ok(analysis);
        };

        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.capacity {
            let victim = entries.keys().next().cloned();
            if let Some(victim) = victim {
                entries.remove(&victim);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        entries.insert(shape, verdict);
        drop(entries);
        if literals.is_empty() {
            let mut exact = self.exact.lock().unwrap_or_else(PoisonError::into_inner);
            if exact.len() >= self.capacity {
                let victim = exact.keys().next().cloned();
                if let Some(victim) = victim {
                    exact.remove(&victim);
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
            exact.insert(sql.to_owned(), Arc::clone(&analysis));
        }
        Ok(analysis)
    }

    fn remember_unshapeable(&self, print: u64) {
        let mut known = self
            .unshapeable
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if known.len() >= self.capacity {
            known.clear();
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        known.insert(print);
    }

    #[must_use]
    pub fn counts(&self) -> Counts {
        Counts {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            entries: self
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len()
                .saturating_add(
                    self.exact
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .len(),
                ),
        }
    }
}

#[derive(Clone)]
enum Shaped {
    Fixed(Arc<Analysis>),
    KeyedLiteral(Arc<Analysis>, usize),
}

fn classify(
    analysis: &Arc<Analysis>,
    literals: &[(usize, usize)],
    sql: &str,
    policy: &Policy,
    shape: &str,
) -> Option<Shaped> {
    if analysis.limit.is_some() {
        return None;
    }
    let from_a_literal = matches!(
        analysis.routing,
        Routing::Single {
            source: KeySource::Int(_) | KeySource::Text(_),
            ..
        }
    );
    let keyed = match (from_a_literal, analysis.key_at) {
        (true, Some(at)) => match literals
            .iter()
            .position(|(start, _end)| u32::try_from(*start).is_ok_and(|start| start == at))
        {
            Some(found) => Some(found),
            None => return None,
        },
        (true, None) => return None,
        (false, _) => None,
    };
    let holds = |span: (usize, usize)| -> bool {
        for swap in swaps(sql, span) {
            let Some(probe) = rewritten(sql, span, &swap) else {
                return false;
            };
            let Some((probe_shape, probe_literals)) = shape_of(&probe) else {
                return false;
            };
            if probe_shape != shape {
                return false;
            }
            let Ok(honest) = analyse(&probe, policy) else {
                return false;
            };
            let answered = match keyed {
                Some(at) => {
                    match probe_literals
                        .get(at)
                        .and_then(|only| with_key(analysis, &probe, *only))
                    {
                        Some(answered) => answered,
                        None => return false,
                    }
                }
                None => Analysis::clone(analysis),
            };
            if answered != honest {
                return false;
            }
        }
        true
    };
    for span in literals {
        if !holds(*span) {
            return None;
        }
    }
    match keyed {
        Some(at) => Some(Shaped::KeyedLiteral(Arc::clone(analysis), at)),
        None => Some(Shaped::Fixed(Arc::clone(analysis))),
    }
}

fn rewritten(sql: &str, span: (usize, usize), swap: &str) -> Option<String> {
    let (start, end) = span;
    let before = sql.get(..start)?;
    let after = sql.get(end..)?;
    Some(format!("{before}{swap}{after}"))
}

fn swaps(sql: &str, span: (usize, usize)) -> Vec<String> {
    let (start, end) = span;
    let text = sql.get(start..end).unwrap_or("");
    let opener = text.chars().next().unwrap_or(' ');
    if opener == '\'' {
        return vec!["'zq'".to_owned(), "'7'".to_owned()];
    }
    if matches!(opener, 'b' | 'B') {
        return vec!["B'101'".to_owned()];
    }
    if matches!(opener, 'x' | 'X') {
        return vec!["X'1f'".to_owned()];
    }
    if text.contains(['.', 'e', 'E']) || text.len() > 9 {
        return vec!["7.5".to_owned(), "9223372036854775807".to_owned()];
    }
    vec!["7".to_owned(), "123456".to_owned()]
}

fn fingerprint(sql: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    let mut quoted = false;
    let mut numeric = false;
    let mut wordish = false;
    for byte in sql.bytes() {
        if quoted {
            if byte == b'\'' {
                quoted = false;
                hasher.write_u8(b'\'');
            }
            continue;
        }
        if byte == b'\'' {
            quoted = true;
            numeric = false;
            wordish = false;
            hasher.write_u8(b'\'');
            continue;
        }
        let inside_number = numeric && matches!(byte, b'.' | b'e' | b'E');
        if (byte.is_ascii_digit() || inside_number) && !wordish {
            if !numeric {
                numeric = true;
                hasher.write_u8(b'#');
            }
            continue;
        }
        numeric = false;
        wordish = byte.is_ascii_alphanumeric() || byte == b'_';
        hasher.write_u8(byte.to_ascii_lowercase());
    }
    hasher.finish()
}

fn shape_of(sql: &str) -> Option<(String, Vec<(usize, usize)>)> {
    let scanned = pg_query::scan(sql).ok()?;
    let mut shape = String::with_capacity(sql.len().saturating_add(8));
    let mut literals: Vec<(usize, usize)> = Vec::new();
    for token in &scanned.tokens {
        let start = usize::try_from(token.start).ok()?;
        let end = usize::try_from(token.end).ok()?;
        let text = sql.get(start..end)?;
        shape.push('\u{1}');
        match token.token {
            LITERAL_INT | LITERAL_FLOAT | LITERAL_STRING | LITERAL_BIT | LITERAL_HEX => {
                literals.push((start, end));
                shape.push('?');
                shape.push_str(&token.token.to_string());
            }
            _ => shape.push_str(text),
        }
    }
    Some((shape, literals))
}

const LITERAL_FLOAT: i32 = 260;
const LITERAL_STRING: i32 = 261;
const LITERAL_BIT: i32 = 263;
const LITERAL_HEX: i32 = 264;
const LITERAL_INT: i32 = 266;

fn with_key(held: &Arc<Analysis>, sql: &str, span: (usize, usize)) -> Option<Analysis> {
    let (start, end) = span;
    let text = sql.get(start..end)?;
    let Routing::Single { source, key_type } = &held.routing else {
        return None;
    };
    let source = match source {
        KeySource::Int(_) => KeySource::Int(text.parse::<i64>().ok()?),
        KeySource::Text(_) => KeySource::Text(unquote(text)?),
        KeySource::Parameter(_) => return None,
    };
    let mut fresh = Analysis::clone(held);
    fresh.routing = Routing::Single {
        source,
        key_type: *key_type,
    };
    fresh.key_at = u32::try_from(start).ok();
    Some(fresh)
}

fn unquote(text: &str) -> Option<String> {
    let inner = text.strip_prefix('\'')?.strip_suffix('\'')?;
    if inner.contains('\\') {
        return None;
    }
    Some(inner.replace("''", "'"))
}
