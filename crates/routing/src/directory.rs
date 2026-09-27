use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};


pub const DEFAULT_CAPACITY: usize = 1 << 20;
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);
pub const DEFAULT_TABLE: &str = "shahrah_directory";
pub const TABLE_ENV: &str = "SHAHRAH_DIRECTORY_TABLE";
pub const CAPACITY_ENV: &str = "SHAHRAH_DIRECTORY_CACHE";
pub const TTL_ENV: &str = "SHAHRAH_DIRECTORY_TTL";

#[derive(Debug, Clone, Copy, Default)]
pub struct Counts {
    pub hits: u64,
    pub misses: u64,
    pub negative_hits: u64,
    pub evictions: u64,
    pub lookups: u64,
    pub failures: u64,
    pub entries: usize,
}

#[derive(Clone)]
struct Entry {
    home: Option<Arc<str>>,
    at: Instant,
}

pub struct Directory {
    entries: Mutex<HashMap<Vec<u8>, Entry>>,
    capacity: usize,
    ttl: Duration,
    table: String,
    hits: AtomicU64,
    misses: AtomicU64,
    negative_hits: AtomicU64,
    evictions: AtomicU64,
    lookups: AtomicU64,
    failures: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Known {
    Home(Arc<str>),
    Unplaced,
}

impl Directory {
    #[must_use]
    pub fn from_env() -> Arc<Self> {
        let capacity = std::env::var(CAPACITY_ENV)
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(DEFAULT_CAPACITY);
        let ttl = std::env::var(TTL_ENV)
            .ok()
            .and_then(|text| text.parse().ok())
            .map_or(DEFAULT_TTL, Duration::from_secs);
        let table = std::env::var(TABLE_ENV).unwrap_or_else(|_| DEFAULT_TABLE.to_owned());
        Arc::new(Self {
            entries: Mutex::new(HashMap::with_capacity(capacity.min(4096))),
            capacity: capacity.max(1),
            ttl,
            table,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            negative_hits: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            lookups: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn cached(&self, key: &[u8]) -> Option<Known> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let found = entries.get(key)?;
        if found.at.elapsed() >= self.ttl {
            return None;
        }
        let answer = match &found.home {
            Some(region) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Known::Home(Arc::clone(region))
            }
            None => {
                self.negative_hits.fetch_add(1, Ordering::Relaxed);
                Known::Unplaced
            }
        };
        Some(answer)
    }

    pub fn remember(&self, key: &[u8], home: Option<&str>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.capacity && !entries.contains_key(key) {
            let victim = entries.keys().next().cloned();
            if let Some(victim) = victim {
                entries.remove(&victim);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        entries.insert(
            key.to_vec(),
            Entry {
                home: home.map(Arc::from),
                at: Instant::now(),
            },
        );
    }

    pub fn forget(&self, key: &[u8]) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }

    #[must_use]
    pub fn statement_for(&self, key: &[u8]) -> String {
        let mut hex = String::with_capacity(key.len().saturating_mul(2));
        for byte in key {
            hex.push_str(&format!("{byte:02x}"));
        }
        format!(
            "select home_region from {} where shard_key = '\\x{hex}'::bytea",
            self.table
        )
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_lookup(&self, failed: bool) {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        if failed {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn counts(&self) -> Counts {
        Counts {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            negative_hits: self.negative_hits.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            lookups: self.lookups.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            entries: self
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
        }
    }
}
