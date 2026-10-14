//! The application itself, independent of how it is served: its configuration
//! and the state every operation shares. The web layer holds one and passes
//! it to the service functions.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::{
    config::AppConfig,
    session::{orphans::OrphanScanner, policy::SessionPolicy, store::SessionStore},
};

/// State every operation shares.
pub struct App {
    pub config: Arc<AppConfig>,
    pub sessions: Arc<SessionStore>,
    pub orphan_scanner: OrphanScanner,
    pub thumbnail_semaphore: Arc<Semaphore>,
    /// One permit for each folder download in progress; none when folder
    /// downloads are unlimited.
    pub download_semaphore: Option<Arc<Semaphore>>,
}

impl App {
    /// Sets up the shared state as `config` asks, and logs the limits it
    /// applies.
    pub fn new(config: Arc<AppConfig>) -> Self {
        let semaphore_tickets = config.thumbnail_concurrency();

        info!(
            "Thumbnails: at most {} generated at once, each decode limited to {}.",
            semaphore_tickets, config.thumbnail.max_decode_memory
        );

        info!(
            "Blocking threads: at most {} in all, {}.",
            config.runtime.max_blocking_threads,
            match config.max_blocking_threads_per_user {
                Some(limit) => format!("at most {} per user", limit),
                None => "no limit per user (JUSTENCRYPT_MAX_BLOCKING_THREADS_PER_USER)".to_string(),
            }
        );

        match config.max_active_downloads {
            Some(limit) => info!("Folder downloads: at most {} at once.", limit),
            None => info!("Folder downloads: no limit (JUSTENCRYPT_MAX_ACTIVE_DOWNLOADS)."),
        }

        let session_policy = SessionPolicy::from(&config.session);

        info!(
            "Session policy: idle timeout {}s, max lifetime {}s, max {} session(s) per user.",
            session_policy.idle_timeout.as_secs(),
            session_policy.max_lifetime.as_secs(),
            session_policy.max_per_user
        );

        let orphan_scanner = OrphanScanner::new(config.orphan_scan_enabled);

        info!(
            "Orphan file scan at login is {} (JUSTENCRYPT_ORPHAN_SCAN_ENABLED).",
            if orphan_scanner.is_enabled() {
                "enabled"
            } else {
                "disabled"
            }
        );

        Self {
            sessions: Arc::new(SessionStore::new(session_policy)),
            orphan_scanner,
            thumbnail_semaphore: Arc::new(Semaphore::new(semaphore_tickets)),
            download_semaphore: config
                .max_active_downloads
                .map(|limit| Arc::new(Semaphore::new(limit.get()))),
            config,
        }
    }

    /// Cleans up the uploads every live session has in progress. Called once
    /// the server has stopped taking requests.
    pub async fn shutdown(&self) {
        info!("Shutting down. Cleaning up active uploads for all sessions.");

        for session in self.sessions.snapshot().await {
            if let Err(e) = session.cleanup_own_uploads().await {
                error!(
                    "Error during shutdown cleanup for user {}: {}",
                    session.username, e
                );
            }
        }
    }
}
