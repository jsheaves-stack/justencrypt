//! Logging in and out, and finding the live session a session token belongs
//! to.

use std::{collections::HashSet, sync::Arc, time::Duration};

use secrecy::{ExposeSecret, SecretString};

use crate::{
    app::App,
    enums::service_error::ServiceError,
    service::credentials::validate_credentials,
    session::{
        reaper::discard_sessions,
        user_session::{new_session_token, UserSession},
    },
    util::time::unix_now_secs,
};

/// What a successful login hands back: the new session's token, which only
/// the client keeps, and how long the session may live.
pub struct LoginGrant {
    pub token: SecretString,
    pub max_age: Duration,
}

/// Logs in: opens the user's encrypted database with their password and
/// starts a session. Every failure to open the account is the same
/// `InvalidCredentials`, so the result never reveals whether the account
/// exists.
pub async fn login(
    app: &App,
    username: &str,
    password: &SecretString,
) -> Result<LoginGrant, ServiceError> {
    validate_credentials(username, password.expose_secret())?;

    trace!("Attempting to open user session for user: {}", username);

    // Clear out expired sessions first, so they don't count against this user's
    // session limit and don't linger when the background reaper is disabled.
    discard_sessions(app.sessions.remove_expired(unix_now_secs()).await).await;

    // Held until the new session is in the store, so concurrent logins for
    // this user don't each create a pool and migrate the database at once.
    let login_guard = app.sessions.lock_login(username).await;
    let existing_context = app.sessions.context_for_user(username).await;

    let session = Arc::new(
        match UserSession::open(username, password, existing_context, &app.config).await {
            Ok(a) => {
                trace!("User session opened successfully.");

                a
            },
            Err(e) => {
                warn!("Failed to open user session: {}", e);

                return Err(ServiceError::InvalidCredentials);
            },
        },
    );

    // The token only lives with the client; the store keeps its digest.
    let token = new_session_token();

    trace!("Generated new session ID: {}", session.session_id);

    let evicted = app
        .sessions
        .insert(token.expose_secret(), session.clone())
        .await;

    drop(login_guard);

    trace!("Session added to active session map.");

    if !evicted.is_empty() {
        info!(
            "User {} is over the session limit; ending {} older session(s).",
            username,
            evicted.len()
        );

        discard_sessions(evicted).await;
    }

    let active_session_ids = app
        .sessions
        .snapshot()
        .await
        .iter()
        .map(|s| s.session_id.clone())
        .collect::<HashSet<_>>();

    if let Err(e) = session.cleanup_orphaned_uploads(active_session_ids).await {
        error!(
            "Failed to clean up orphaned uploads on session creation: {}",
            e
        );
    }

    app.orphan_scanner.scan_in_background(session);

    Ok(LoginGrant {
        token,
        max_age: app.sessions.policy().max_lifetime,
    })
}

/// Logs out: ends the session `token` belongs to and cleans up its uploads in
/// progress. Fails with `MissingActiveSession` if there is no such session.
pub async fn logout(app: &App, token: &str) -> Result<(), ServiceError> {
    match app.sessions.remove_by_token(token).await {
        Some(session) => {
            trace!("Removed active session with ID: {}", session.session_id);

            discard_sessions(vec![session]).await;

            Ok(())
        },
        None => {
            trace!("User token not found in active session list.");

            Err(ServiceError::MissingActiveSession)
        },
    }
}

/// The live session `token` belongs to, which is refreshed as active. Fails
/// with `MissingActiveSession` if there is none, or if it has expired.
pub async fn authenticate(app: &App, token: &str) -> Result<Arc<UserSession>, ServiceError> {
    let session = match app.sessions.get(token).await {
        Some(s) => {
            trace!("Found active session for token.");

            s
        },
        None => {
            trace!("No active session found for token.");

            return Err(ServiceError::MissingActiveSession);
        },
    };

    // Enforced here on every request, so an expired session is rejected on
    // time whether or not the background reaper is running.

    if session.is_expired(unix_now_secs(), app.sessions.policy()) {
        trace!("Session has expired.");

        if let Some(expired) = app.sessions.remove_by_id(&session.session_id).await {
            tokio::spawn(discard_sessions(vec![expired]));
        }

        return Err(ServiceError::MissingActiveSession);
    }

    session.touch();

    Ok(session)
}
