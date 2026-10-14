use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
    time::Duration,
};

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{self, JoinHandle},
    time,
};

use crate::{
    config::DbConfig,
    enums::{blocking_error::BlockingError, db_error::DbError},
};

/// Everything a user's requests share: their database pool, their stored
/// files, and the limits on how much of the server they may occupy. All of a
/// user's sessions use one, and it lives on while any work it started is
/// still running, so its limits apply to the user as a whole.
///
/// Blocking threads are shared by every user, so all blocking work done for a
/// user goes through here: database work ([`with_db`](Self::with_db)), file
/// access (see `user_storage`), and anything else
/// ([`run_blocking`](Self::run_blocking),
/// [`start_blocking`](Self::start_blocking)). Waiting for a connection or for
/// a turn holds no thread.
#[derive(Clone)]
pub struct UserContext(Arc<Shared>);

/// Work that needs both a connection and a thread always takes the
/// connection first, so two tasks can never each hold what the other waits
/// for.
struct Shared {
    pool: Pool<SqliteConnectionManager>,
    /// The directory holding the user's database and encrypted files.
    user_path: PathBuf,
    /// One permit per connection in the pool. Database work takes one before
    /// it starts a thread, so `pool.get()` finds a connection free and a
    /// thread never sits waiting for one.
    connections: Arc<Semaphore>,
    /// The most blocking threads the user may occupy at once; none means no
    /// limit.
    blocking: Option<Arc<Semaphore>>,
    /// Folder downloads hold a connection for as long as they run, so they
    /// may only take half of them; the rest stay free for the user's other
    /// requests.
    folder_downloads: Arc<Semaphore>,
    /// How long a task waits for a connection or a turn before giving up.
    max_wait: Duration,
    /// Whether a scan for the user's orphaned files is running.
    orphan_scan_running: AtomicBool,
}

/// One of a user's permits: a connection, or a folder download slot. It keeps
/// the user's [`UserContext`] alive while held, so work that outlives the
/// user's sessions, such as a download, still counts against their limits
/// when they log in again.
pub struct UserPermit {
    _permit: OwnedSemaphorePermit,
    _context: UserContext,
}

/// One of the user's blocking threads, reserved but not yet in use. Reserving
/// first lets a caller wait for other limits, such as a server-wide one,
/// without holding any of those while it waits for the user's turn.
pub struct BlockingSlot {
    /// The user's turn, when their blocking threads are limited.
    _permit: Option<OwnedSemaphorePermit>,
    _context: UserContext,
}

/// Proof that the holder is running the user's only orphan scan. The next scan
/// may start once it is dropped.
pub struct OrphanScanClaim(UserContext);

/// A reference to a [`UserContext`] that doesn't keep it alive.
pub struct WeakUserContext(Weak<Shared>);

impl UserContext {
    /// A context for the user whose database is `pool` and whose files are
    /// in `user_path`. `blocking_limit` is the most blocking threads the user
    /// may occupy at once; with none, they may use every one.
    pub fn new(
        pool: Pool<SqliteConnectionManager>,
        user_path: PathBuf,
        config: &DbConfig,
        blocking_limit: Option<NonZeroUsize>,
    ) -> Self {
        let connections = config.max_connections.get() as usize;

        Self(Arc::new(Shared {
            pool,
            user_path,
            connections: Arc::new(Semaphore::new(connections)),
            blocking: blocking_limit.map(|limit| Arc::new(Semaphore::new(limit.get()))),
            folder_downloads: Arc::new(Semaphore::new((connections / 2).max(1))),
            max_wait: Duration::from_secs(config.connection_timeout_seconds.get()),
            orphan_scan_running: AtomicBool::new(false),
        }))
    }

    /// The directory holding the user's database and encrypted files.
    pub fn user_path(&self) -> &Path {
        &self.0.user_path
    }

    /// The pool itself, for work already holding one of the user's
    /// connections (see [`reserve_connection`](Self::reserve_connection)).
    pub fn pool(&self) -> &Pool<SqliteConnectionManager> {
        &self.0.pool
    }

    /// Runs `f` with one of the user's database connections, on one of their
    /// blocking threads, and returns its result.
    pub async fn with_db<F, R>(&self, f: F) -> Result<R, DbError>
    where
        F: FnOnce(PooledConnection<SqliteConnectionManager>) -> Result<R, DbError> + Send + 'static,
        R: Send + 'static,
    {
        let connection = self.reserve_connection().await?;
        let pool = self.0.pool.clone();

        self.run_blocking(move || {
            let _connection = connection;

            f(pool.get()?)
        })
        .await?
    }

    /// Waits until one of the user's connections is free, for at most the
    /// connection timeout, and reserves it. While the permit is held,
    /// `pool().get()` finds a connection free. Take it before any of the
    /// user's blocking threads.
    pub async fn reserve_connection(&self) -> Result<UserPermit, BlockingError> {
        self.acquire(&self.0.connections)
            .await
            .ok_or(BlockingError::Busy)
    }

    /// Runs `f` on one of the user's blocking threads and returns its result.
    pub async fn run_blocking<F, R>(&self, f: F) -> Result<R, BlockingError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.reserve_blocking().await?.run(f).await
    }

    /// Starts `f` on one of the user's blocking threads and returns without
    /// waiting for it to finish. The thread counts against the user's limit
    /// until `f` returns.
    pub async fn start_blocking<F, R>(&self, f: F) -> Result<JoinHandle<R>, BlockingError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        Ok(self.reserve_blocking().await?.start(f))
    }

    /// Reserves one of the user's blocking threads, waiting, for at most the
    /// connection timeout, if the user is at their limit.
    pub async fn reserve_blocking(&self) -> Result<BlockingSlot, BlockingError> {
        let permit = match &self.0.blocking {
            Some(limit) => Some(
                self.acquire_permit(limit)
                    .await
                    .ok_or(BlockingError::Busy)?,
            ),
            None => None,
        };

        Ok(BlockingSlot {
            _permit: permit,
            _context: self.clone(),
        })
    }

    /// Waits until the user may start another folder download, for at most
    /// the connection timeout. `None` if they may not.
    pub async fn folder_download_permit(&self) -> Option<UserPermit> {
        self.acquire(&self.0.folder_downloads).await
    }

    /// Claims the user's orphan scan, unless one is already running. A scan
    /// walks all of the user's storage, so running several at once (one per
    /// login) would only repeat the same work.
    pub fn try_claim_orphan_scan(&self) -> Option<OrphanScanClaim> {
        self.0
            .orphan_scan_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| OrphanScanClaim(self.clone()))
    }

    /// A reference that lets the session store find this context while
    /// anything else still holds it, without keeping it alive itself.
    pub fn downgrade(&self) -> WeakUserContext {
        WeakUserContext(Arc::downgrade(&self.0))
    }

    /// Waits for a permit from `semaphore`, as a permit that keeps this context
    /// alive.
    async fn acquire(&self, semaphore: &Arc<Semaphore>) -> Option<UserPermit> {
        Some(UserPermit {
            _permit: self.acquire_permit(semaphore).await?,
            _context: self.clone(),
        })
    }

    /// Waits for a permit from `semaphore`, for at most the connection
    /// timeout.
    async fn acquire_permit(&self, semaphore: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
        time::timeout(self.0.max_wait, semaphore.clone().acquire_owned())
            .await
            .ok()?
            .ok()
    }
}

impl BlockingSlot {
    /// Runs `f` on the reserved thread and returns its result.
    pub async fn run<F, R>(self, f: F) -> Result<R, BlockingError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.start(f)
            .await
            .map_err(|e| BlockingError::Failed(e.to_string()))
    }

    /// Starts `f` on the reserved thread, which is released when `f` returns.
    pub fn start<F, R>(self, f: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        task::spawn_blocking(move || {
            let _slot = self;

            f()
        })
    }
}

impl Drop for OrphanScanClaim {
    fn drop(&mut self) {
        self.0
             .0
            .orphan_scan_running
            .store(false, Ordering::Release);
    }
}

impl WeakUserContext {
    /// The context, if anything still holds it.
    pub fn upgrade(&self) -> Option<UserContext> {
        self.0.upgrade().map(UserContext)
    }
}
