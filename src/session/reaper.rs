use std::{env, sync::Arc, time::Duration};

use rocket::{
    async_trait,
    fairing::{Fairing, Info, Kind},
    tokio::{self, time::interval},
    Orbit, Rocket,
};

use crate::{
    session::{store::SessionStore, user_session::UserSession},
    util::{time::unix_now_secs, upload_limits::upload_ttl},
    AppState,
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
/// removes stale uploads from the sessions that are still live.
pub async fn reap_once(store: &SessionStore) {
    let expired = store.remove_expired(unix_now_secs()).await;

    if !expired.is_empty() {
        info!("Reaping {} expired session(s)", expired.len());
    }

    discard_sessions(expired).await;

    let ttl = upload_ttl();

    for session in store.snapshot().await {
        session.sweep_stale_uploads(ttl).await;
    }
}

/// Periodically runs [`reap_once`] in the background.
///
/// Expired sessions are already rejected on their next request by the
/// `AuthenticatedSession` guard, and swept out on every login, so the reaper
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

    /// Reads `JUSTENCRYPT_SESSION_REAPER_INTERVAL_SECONDS`. Missing, unparsable
    /// or 0 disables the reaper.
    pub fn from_env() -> Option<Self> {
        let seconds = env::var("JUSTENCRYPT_SESSION_REAPER_INTERVAL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        Self::every(seconds)
    }
}

#[async_trait]
impl Fairing for SessionReaper {
    fn info(&self) -> Info {
        Info {
            name: "Session Reaper",
            kind: Kind::Liftoff,
        }
    }

    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        let Some(state) = rocket.state::<AppState>() else {
            error!("Session reaper not started: AppState is not managed.");

            return;
        };

        let store = state.sessions.clone();
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
                reap_once(&store).await;
            }
        });
    }
}
