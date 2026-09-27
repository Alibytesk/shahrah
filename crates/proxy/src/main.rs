mod address;
mod admin;
mod auth;
mod broadcast;
mod cancel;
mod cluster;
mod config;
mod connection;
mod dashboard;
mod error;
mod guard;
mod health;
mod metrics;
mod pool;
mod relocate;
mod session;
mod settings;
mod statements;
mod shutdown;
mod tls;
mod transport;

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::cancel::CancelRegistry;
use crate::session::{Session, Shared};
use crate::auth::Verifiers;
use crate::config::CONFIG_ENV;
use crate::pool::{Pool, PoolConfig};
use crate::health::{Health, Prober};
use crate::shutdown::Sessions;
use crate::tls::BackendTls;
use crate::transport::Transport;

const DEFAULT_LISTEN: &str = "127.0.0.1:6432";
const LISTEN_ENV: &str = "SHAHRAH_LISTEN";
const DEFAULT_BACKEND: &str = "127.0.0.1:5432";
const BACKEND_ENV: &str = "SHAHRAH_BACKEND";
const BACKEND_USER_ENV: &str = "SHAHRAH_BACKEND_USER";
const BACKEND_PASSWORD_ENV: &str = "SHAHRAH_BACKEND_PASSWORD";
const AUTH_DATABASE_ENV: &str = "SHAHRAH_AUTH_DATABASE";
const MAX_POOL_ENV: &str = "SHAHRAH_MAX_POOL";
const WARM_ENV: &str = "SHAHRAH_WARM_PER_SHARD";
const DEFAULT_MAX_POOL: usize = 20;
const MAX_CLIENTS_ENV: &str = "SHAHRAH_MAX_CLIENTS";
const DEFAULT_MAX_CLIENTS: usize = 10_000;
const ACCEPT_BACKOFF_MILLIS: [u64; 6] = [5, 20, 50, 100, 250, 500];
const TURN_AWAY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
const TURN_AWAY_SWALLOW: usize = 10_240;
const DEFAULT_WARM_PER_SHARD: usize = 1;
const WORKERS_ENV: &str = "SHAHRAH_WORKERS";
#[cfg(feature = "pprof")]
const PROFILE_ENV: &str = "SHAHRAH_PROFILE";

#[cfg(feature = "pprof")]
fn profile_to(path: String) {
    std::thread::spawn(move || {
        let built = pprof::ProfilerGuardBuilder::default()
            .frequency(999)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build();
        let Ok(guard) = built else {
            warn!("the profiler would not start");
            return;
        };
        std::thread::sleep(std::time::Duration::from_secs(30));
        match guard.report().build() {
            Ok(report) => match std::fs::File::create(&path) {
                Ok(file) => match report.flamegraph(file) {
                    Ok(()) => info!(path, "wrote a flamegraph"),
                    Err(cause) => warn!(%cause, "the flamegraph would not render"),
                },
                Err(cause) => warn!(%cause, "the flamegraph file would not open"),
            },
            Err(cause) => warn!(%cause, "the profile would not build"),
        }
    });
}

async fn watch_config(
    path: String,
    slot: std::sync::Arc<arc_swap::ArcSwapOption<config::Loaded>>,
) {
    let Ok(mut hangup) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    else {
        warn!("SIGHUP cannot be observed; the topology will not reload");
        return;
    };

    while hangup.recv().await.is_some() {
        match config::load(std::path::Path::new(&path)) {
            Ok(loaded) => {
                info!(
                    shards = loaded.topology.len(),
                    region = loaded.topology.region().unwrap_or("none"),
                    "topology reloaded"
                );
                slot.store(Some(std::sync::Arc::new(loaded)));
            }
            Err(cause) => {
                error!(%cause, "topology reload refused, keeping the previous one");
            }
        }
    }
}

fn main() -> std::process::ExitCode {
    let workers = worker_threads();
    let built = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build();
    let runtime = match built {
        Ok(runtime) => runtime,
        Err(cause) => {
            let _told = std::io::Write::write_all(
                &mut std::io::stderr(),
                format!("shahrah could not build its runtime: {cause}\n").as_bytes(),
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        info!(workers, "shahrah sized its runtime to the processors it may actually use");
        match run().await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(cause) => {
                error!(%cause, "shahrah cannot start");
                std::process::ExitCode::FAILURE
            }
        }
    })
}

fn worker_threads() -> usize {
    if let Ok(asked) = std::env::var(WORKERS_ENV)
        && let Ok(count) = asked.parse::<usize>()
        && count > 0
    {
        return count;
    }
    let seen = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let Ok(quota) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") else {
        return seen;
    };
    let mut fields = quota.split_whitespace();
    let (Some(allowed), Some(period)) = (fields.next(), fields.next()) else {
        return seen;
    };
    let (Ok(allowed), Ok(period)) = (allowed.parse::<u64>(), period.parse::<u64>()) else {
        return seen;
    };
    if period == 0 {
        return seen;
    }
    let capped = allowed.div_euclid(period).max(1);
    usize::try_from(capped).unwrap_or(seen).min(seen)
}

async fn warm_every_region(
    pool: &std::sync::Arc<Pool>,
    routing: &std::sync::Arc<arc_swap::ArcSwapOption<config::Loaded>>,
    database: &str,
    wanted: usize,
) {
    let loaded = routing.load();
    let Some(topology) = loaded.as_deref().map(|loaded| &loaded.topology) else {
        return;
    };
    let mut opened = 0usize;
    let mut reached = 0usize;
    for shard in topology.shards() {
        match pool.warm(&shard.primary.address, database, None, wanted).await {
            Ok(count) => {
                opened = opened.saturating_add(count);
                reached = reached.saturating_add(1);
            }
            Err(cause) => warn!(
                endpoint = %shard.primary.address,
                %cause,
                "could not open a connection to keep this shard warm; the first session to \
                 reach it will pay the cost instead"
            ),
        }
    }
    info!(
        connections = opened,
        shards = reached,
        of = topology.shards().len(),
        "opened connections so no session pays the first crossing to a region"
    );
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tls::install_crypto_provider();

    #[cfg(feature = "pprof")]
    if let Ok(path) = std::env::var(PROFILE_ENV) {
        info!(path, "sampling this process for 30 seconds");
        profile_to(path);
    }

    let listen = std::env::var(LISTEN_ENV).unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let address: SocketAddr = listen.parse()?;
    let backend_address = std::env::var(BACKEND_ENV).unwrap_or_else(|_| DEFAULT_BACKEND.to_owned());

    let config_path = std::env::var(CONFIG_ENV).ok();
    let routing = std::sync::Arc::new(arc_swap::ArcSwapOption::from(None));
    if let Some(path) = config_path.as_deref() {
        let loaded = config::load(std::path::Path::new(path))?;
        info!(
            path,
            shards = loaded.topology.len(),
            region = loaded.topology.region().unwrap_or("none"),
            "topology loaded"
        );
        routing.store(Some(std::sync::Arc::new(loaded)));
    } else {
        info!("no topology configured, forwarding every statement to the single backend");
    }

    let acceptor = tls::load_acceptor()?;
    let connector = tls::load_connector()?;
    let backend_tls = BackendTls::from_env()?;

    let (notify, shutdown) = tokio::sync::watch::channel(false);
    let sessions = Sessions::new();

    let pool = Pool::new(
        PoolConfig {
            user: std::env::var(BACKEND_USER_ENV).unwrap_or_else(|_| "shahrah".to_owned()),
            password: std::env::var(BACKEND_PASSWORD_ENV).unwrap_or_default(),
            max_per_database: settings::count(MAX_POOL_ENV, DEFAULT_MAX_POOL)
                .map_err(crate::error::SessionError::Setting)?,
            idle_timeout: std::time::Duration::from_secs(300),
            wait: settings::seconds(pool::WAIT_ENV, Some(pool::DEFAULT_WAIT))
                .map_err(crate::error::SessionError::Setting)?,
            backend_tls,
        },
        connector.clone(),
    );
    let auth_database = std::env::var(AUTH_DATABASE_ENV).unwrap_or_else(|_| "postgres".to_owned());
    let warm_database = auth_database.clone();
    let verifiers = Verifiers::new(
        std::sync::Arc::clone(&pool),
        backend_address.clone(),
        auth_database,
        std::env::var(auth::AUTH_QUERY_ENV)
            .unwrap_or_else(|_| auth::DEFAULT_AUTH_QUERY.to_owned()),
    );

    let shared_directory = shahrah_routing::directory::Directory::from_env();
    let reporting: std::sync::Arc<std::sync::OnceLock<Shared>> =
        std::sync::Arc::new(std::sync::OnceLock::new());
    let (cluster_lost, mut cluster_gone) = tokio::sync::watch::channel(false);
    let raft_node = match cluster::settings_from_env().map_err(crate::error::SessionError::Setting)? {
        Some(settings) => Some(
            cluster::start(
                settings,
                std::sync::Arc::clone(&routing),
                cluster_lost,
                std::sync::Arc::clone(&shared_directory),
                std::sync::Arc::clone(&reporting),
            )
            .await?,
        ),
        None => {
            info!("no raft configuration, the topology comes from the config file alone");
            None
        }
    };
    let _raft = raft_node.clone();

    let warm_per_shard: usize = settings::count(WARM_ENV, DEFAULT_WARM_PER_SHARD)
        .map_err(crate::error::SessionError::Setting)?;
    let max_clients: usize = settings::count(MAX_CLIENTS_ENV, DEFAULT_MAX_CLIENTS)
        .map_err(crate::error::SessionError::Setting)?;
    let backend_settings =
        connection::backend_settings().map_err(crate::error::SessionError::Setting)?;
    info!(settings = backend_settings, "every backend connection is opened with these");

    let read_lag_limit = {
        let mib = settings::count(health::READ_LAG_LIMIT_ENV, health::DEFAULT_READ_LAG_LIMIT_MIB)
            .map_err(crate::error::SessionError::Setting)?;
        let bytes = mib.saturating_mul(health::BYTES_PER_MIB);
        i64::try_from(bytes).ok().filter(|bytes| *bytes > 0)
    };
    match read_lag_limit {
        Some(bytes) => info!(bytes, "a replica further behind its primary than this stops taking reads"),
        None => warn!(
            "{} is 0, so a replica takes reads however far behind its primary it is",
            health::READ_LAG_LIMIT_ENV
        ),
    }
    let health = Health::new(read_lag_limit);
    health.attach_pool(std::sync::Arc::clone(&pool));

    let shared = Shared {
        backend_address: backend_address.clone(),
        registry: CancelRegistry::new(),
        acceptor: acceptor.clone(),
        connector: connector.clone(),
        backend_tls,
        shutdown,
        pool,
        verifiers,
        routing: std::sync::Arc::clone(&routing),
        health: std::sync::Arc::clone(&health),
        cache: shahrah_sql::cache::Cache::new(shahrah_sql::cache::DEFAULT_CAPACITY),
        text_sorts_by_bytes: std::sync::Arc::new(std::sync::OnceLock::new()),
        directory: std::sync::Arc::clone(&shared_directory),
        warmed: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        warm_per_shard,
        relocations: relocate::Relocations::new(),
        counters: std::sync::Arc::new(metrics::Counters::default()),
        traffic: std::sync::Arc::new(metrics::Traffic::default()),
        tracing: std::sync::Arc::new(metrics::Tracing::default()),
        cluster: {
            let slot = std::sync::Arc::new(std::sync::OnceLock::new());
            if let Some(node) = raft_node.clone() {
                let _held = slot.set(node);
            }
            slot
        },
    };

    if let Some(path) = config_path.clone() {
        let slot = std::sync::Arc::clone(&routing);
        tokio::spawn(async move { watch_config(path, slot).await });
    }

    tokio::spawn(
        Prober {
            health: std::sync::Arc::clone(&health),
            routing: std::sync::Arc::clone(&routing),
            connector: connector.clone(),
            backend_tls,
            user: std::env::var(BACKEND_USER_ENV).unwrap_or_else(|_| "shahrah".to_owned()),
            password: std::env::var(BACKEND_PASSWORD_ENV).unwrap_or_default(),
            database: std::env::var(AUTH_DATABASE_ENV).unwrap_or_else(|_| "postgres".to_owned()),
        }
        .run(),
    );

    let listener = TcpListener::bind(address).await?;
    info!(
        %address,
        backend = %backend_address,
        client_tls = acceptor.is_some(),
        backend_tls = ?backend_tls,
        "shahrah is listening"
    );

    if let Some(loaded) = routing.load().as_deref() {
        let endpoints: Vec<String> = loaded
            .topology
            .shards()
            .iter()
            .flat_map(|shard| {
                core::iter::once(shard.primary.address.clone())
                    .chain(shard.replicas.iter().map(|replica| replica.address.clone()))
            })
            .collect();
        shared.traffic.learn(&endpoints);
    }
    let _reported = reporting.set(shared.clone());
    metrics::start(shared.clone()).await;

    let mut accept_trouble: u32 = 0;

    if warm_per_shard > 0 {
        let pool = std::sync::Arc::clone(&shared.pool);
        let routing = std::sync::Arc::clone(&routing);
        let database = warm_database.clone();
        tokio::spawn(async move {
            warm_every_region(&pool, &routing, &database, warm_per_shard).await;
        });
    }

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = shutdown::signalled() => break,
            Ok(()) = cluster_gone.changed() => break,
        };

        let (stream, peer) = match accepted {
            Ok(accepted) => {
                accept_trouble = 0;
                accepted
            }
            Err(cause) => {
                accept_trouble = accept_trouble.saturating_add(1);
                if accept_trouble == 1 || accept_trouble.is_multiple_of(1000) {
                    error!(%cause, running = accept_trouble, "accept failed");
                }
                tokio::time::sleep(accept_backoff(accept_trouble)).await;
                continue;
            }
        };

        if max_clients > 0 && sessions.active() >= max_clients {
            crate::metrics::Counters::bump(&shared.counters.clients_refused);
            tokio::spawn(async move { turn_away(stream, peer, max_clients).await });
            continue;
        }

        if let Err(cause) = stream.set_nodelay(true) {
            warn!(%peer, %cause, "could not disable Nagle");
        }

        let shared = shared.clone();
        let guard = sessions.enter();
        tokio::spawn(async move {
            let _held = guard;
            match Session::new(Transport::Plain(stream), shared).run().await {
                Ok(()) => info!(%peer, "session closed"),
                Err(cause) => warn!(%peer, %cause, "session ended"),
            }
        });
    }

    info!("no longer accepting connections");
    shutdown::drain(&sessions, &notify).await;
    info!("shahrah has stopped");
    Ok(())
}

fn accept_backoff(tries: u32) -> std::time::Duration {
    let at = usize::try_from(tries).unwrap_or(usize::MAX).saturating_sub(1);
    let millis = ACCEPT_BACKOFF_MILLIS
        .get(at)
        .copied()
        .unwrap_or_else(|| ACCEPT_BACKOFF_MILLIS.last().copied().unwrap_or(500));
    std::time::Duration::from_millis(millis)
}

async fn turn_away(mut stream: tokio::net::TcpStream, peer: SocketAddr, cap: usize) {
    use tokio::io::AsyncWriteExt;

    if tokio::time::timeout(TURN_AWAY_DEADLINE, hear_the_client_out(&mut stream))
        .await
        .is_err()
    {
        return;
    }

    warn!(
        %peer,
        cap,
        "refusing a client because shahrah is already holding {MAX_CLIENTS_ENV} connections"
    );
    let message = format!(
        "shahrah is already holding {cap} client connections, which is {MAX_CLIENTS_ENV}. \
         The connection was refused rather than accepted and left waiting"
    );
    let mut writer = shahrah_protocol::writer::Writer::new();
    if shahrah_protocol::messages::error_response(
        &mut writer,
        shahrah_protocol::messages::SEVERITY_FATAL,
        shahrah_protocol::messages::SQLSTATE_TOO_MANY_CONNECTIONS,
        message.as_bytes(),
    )
    .is_err()
    {
        return;
    }
    let _written = stream.write_all(writer.as_bytes()).await;
    let _flushed = stream.flush().await;
    let _closed = stream.shutdown().await;
}

async fn hear_the_client_out(stream: &mut tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut opening = [0u8; 8];
    if stream.read_exact(&mut opening).await.is_err() {
        return;
    }
    let Some(declared) = declared_length(opening.get(..4)) else {
        return;
    };
    let asks_for_tls = opening
        .get(4..8)
        .and_then(|four| <[u8; 4]>::try_from(four).ok())
        .is_some_and(|code| {
            i32::from_be_bytes(code) == shahrah_protocol::startup::SSL_REQUEST_CODE
        });
    if !asks_for_tls {
        swallow(stream, declared.saturating_sub(8)).await;
        return;
    }
    if stream.write_all(b"N").await.is_err() {
        return;
    }
    let mut length = [0u8; 4];
    if stream.read_exact(&mut length).await.is_err() {
        return;
    }
    let Some(declared) = declared_length(Some(&length)) else {
        return;
    };
    swallow(stream, declared.saturating_sub(4)).await;
}

fn declared_length(head: Option<&[u8]>) -> Option<usize> {
    let four = head.and_then(|head| <[u8; 4]>::try_from(head).ok())?;
    usize::try_from(i32::from_be_bytes(four)).ok()
}

async fn swallow(stream: &mut tokio::net::TcpStream, mut left: usize) {
    use tokio::io::AsyncReadExt;

    let mut bin = [0u8; 1024];
    left = left.min(TURN_AWAY_SWALLOW);
    while left > 0 {
        let want = left.min(bin.len());
        let Some(room) = bin.get_mut(..want) else {
            return;
        };
        match stream.read(room).await {
            Ok(0) | Err(_) => return,
            Ok(read) => left = left.saturating_sub(read),
        }
    }
}
