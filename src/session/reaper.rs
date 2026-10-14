use std::{sync::Arc, time::Duration};

use tokio::time::interval;

use crate::{
    session::{store::SessionStore, user_session::UserSession},
    util::time::unix_now_secs,
};

/// Cleans up the uploads of sessions that have been removed from the store:
/// their partial files and upload tracking rows.
pub async fn discard_sessions(sessions: Vec<Arc<UserSession>>) {
    for session in sessions {
        trace!("Discarding session {}", session.session_id);

        if let Err(e) = session.cleanup_own_uploads().await {
            error!(
                "Failed to clean up uploads of discarded session for user {}: {}",
                session.username, e
            );
        }
    }
}

/// One reaper pass: removes expired sessions and cleans up after them, then
/// removes uploads idle for longer than `upload_ttl` from the sessions that
/// are still live.
pub async fn reap_once(store: &SessionStore, upload_ttl: Duration) {
    let expired = store.remove_expired(unix_now_secs()).await;

    if !expired.is_empty() {
        info!("Reaping {} expired session(s)", expired.len());
    }

    discard_sessions(expired).await;

    for session in store.snapshot().await {
        session.sweep_stale_uploads(upload_ttl).await;
    }
}

/// Periodically runs [`reap_once`] in the background.
///
/// Expired sessions are already rejected on their next request (see
/// [`authenticate`](crate::service::auth::authenticate)), and swept out on
/// every login, so the reaper
/// is only needed to reclaim sessions that are never used again. It runs only
/// when `JUSTENCRYPT_SESSION_REAPER_INTERVAL_SECONDS` is set above 0.
pub struct SessionReaper {
    interval: Duration,
}

impl SessionReaper {
    /// `None` when `seconds` is 0, which disables the reaper.
    pub fn every(seconds: u64) -> Option<Self> {
        (seconds > 0).then(|| Self {
            interval: Duration::from_secs(seconds),
        })
    }

    /// Starts the reaper on `store`, removing uploads idle for longer than
    /// `upload_ttl`. It runs until the runtime shuts down.
    pub fn spawn(&self, store: Arc<SessionStore>, upload_ttl: Duration) {
        let period = self.interval;

        info!(
            "Session reaper running every {} second(s).",
            period.as_secs()
        );

        tokio::spawn(async move {
            let mut ticker = interval(period);

            // The first tick completes immediately; skip it so the first pass
            // happens one full interval after launch.
            ticker.tick().await;

            loop {
                ticker.tick().await;
                reap_once(&store, upload_ttl).await;
            }
        });
    }
}
