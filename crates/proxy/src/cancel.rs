use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use rand::RngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CancelKey {
    pub process_id: i32,
    pub secret_key: i32,
}

#[derive(Debug, Clone)]
pub struct BackendRoute {
    pub key: CancelKey,
    pub address: String,
}

impl BackendRoute {
    #[must_use]
    pub fn nowhere() -> Self {
        Self {
            key: CancelKey {
                process_id: 0,
                secret_key: 0,
            },
            address: String::new(),
        }
    }

    #[must_use]
    pub fn is_real(&self) -> bool {
        !self.address.is_empty() && self.key.process_id != 0
    }
}

#[derive(Debug, Default)]
pub struct CancelRegistry {
    entries: Mutex<HashMap<CancelKey, BackendRoute>>,
}

impl CancelRegistry {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[must_use]
    pub fn register(self: &Arc<Self>, route: BackendRoute) -> CancelGuard {
        let issued = loop {
            let candidate = random_key();
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(candidate) {
                slot.insert(route.clone());
                break candidate;
            }
        };

        CancelGuard {
            registry: Arc::clone(self),
            issued,
        }
    }

    pub fn retarget(&self, issued: CancelKey, route: BackendRoute) {
        if let Some(slot) = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&issued)
        {
            *slot = route;
        }
    }

    #[must_use]
    pub fn lookup(&self, key: CancelKey) -> Option<BackendRoute> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .cloned()
    }

    fn forget(&self, key: CancelKey) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[derive(Debug)]
pub struct CancelGuard {
    registry: Arc<CancelRegistry>,
    issued: CancelKey,
}

impl CancelGuard {
    #[must_use]
    pub const fn issued(&self) -> CancelKey {
        self.issued
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.registry.forget(self.issued);
    }
}

fn random_key() -> CancelKey {
    let mut rng = rand::rng();
    CancelKey {
        process_id: rng.next_u32() as i32,
        secret_key: rng.next_u32() as i32,
    }
}
