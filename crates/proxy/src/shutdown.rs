use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Default)]
pub struct Sessions(AtomicUsize);

impl Sessions {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[must_use]
    pub fn enter(self: &Arc<Self>) -> SessionGuard {
        self.0.fetch_add(1, Ordering::AcqRel);
        SessionGuard(Arc::clone(self))
    }

    #[must_use]
    pub fn active(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct SessionGuard(Arc<Sessions>);

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub async fn signalled() {
    let mut terminate = match tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    ) {
        Ok(terminate) => terminate,
        Err(cause) => {
            warn!(%cause, "SIGTERM cannot be observed; only Ctrl-C will stop shahrah");
            let _unused = tokio::signal::ctrl_c().await;
            return;
        }
    };

    tokio::select! {
        _unused = terminate.recv() => info!("SIGTERM received"),
        _unused = tokio::signal::ctrl_c() => info!("interrupt received"),
    }
}

pub async fn drain(sessions: &Arc<Sessions>, notify: &watch::Sender<bool>) {
    let _ignored = notify.send(true);
    let deadline = tokio::time::Instant::now().checked_add(DRAIN_TIMEOUT);

    loop {
        let active = sessions.active();
        if active == 0 {
            info!("all sessions drained");
            return;
        }
        match deadline {
            Some(deadline) if tokio::time::Instant::now() >= deadline => {
                warn!(active, "drain timed out, closing anyway");
                return;
            }
            _ => {}
        }
        info!(active, "waiting for sessions to reach a transaction boundary");
        tokio::time::sleep(POLL).await;
    }
}
