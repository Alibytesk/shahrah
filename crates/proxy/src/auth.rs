use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use rand::RngCore;
use shahrah_protocol::scram::Verifier;
use tokio::sync::Mutex;
use tracing::debug;

use crate::error::SessionError;
use crate::pool::Pool;

pub const DEFAULT_AUTH_QUERY: &str = "SELECT username, verifier FROM shahrah_get_auth($1)";
pub const AUTH_QUERY_ENV: &str = "SHAHRAH_AUTH_QUERY";
const VERIFIER_TTL: Duration = Duration::from_secs(300);

struct Cached {
    verifier: Verifier,
    at: Instant,
}

pub struct Verifiers {
    pool: Arc<Pool>,
    address: String,
    database: String,
    template: String,
    cache: Mutex<HashMap<String, Cached>>,
}

impl Verifiers {
    #[must_use]
    pub fn new(
        pool: Arc<Pool>,
        address: String,
        database: String,
        template: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            pool,
            address,
            database,
            template,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub async fn lookup(&self, user: &str) -> Result<Option<Verifier>, SessionError> {
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get(user)
            && entry.at.elapsed() < VERIFIER_TTL
        {
            return Ok(Some(entry.verifier.clone()));
        }

        let sql = self.template.replace("$1", &quote_literal(user));
        let mut lease = self
            .pool
            .acquire(&self.address, &self.database, None)
            .await?;
        let rows = lease.connection()?.simple_query(&sql).await;
        lease.release().await;

        let rows = rows?;
        let Some(first) = rows.first() else {
            debug!(user, "auth query returned no row");
            return Ok(None);
        };
        let Some(Some(raw)) = first.get(1) else {
            return Ok(None);
        };

        let text = String::from_utf8_lossy(raw);
        let verifier = Verifier::parse(&text)?;
        cache.insert(
            user.to_owned(),
            Cached {
                verifier: verifier.clone(),
                at: Instant::now(),
            },
        );
        Ok(Some(verifier))
    }
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[must_use]
pub fn nonce() -> String {
    let mut raw = [0u8; 18];
    rand::rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::STANDARD.encode(raw)
}
