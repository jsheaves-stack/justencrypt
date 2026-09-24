use std::{collections::HashSet, env, str::FromStr, sync::Arc};

use rocket::{
    http::{Cookie, CookieJar, SameSite},
    options, post,
    serde::json::Json,
    time, State,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    session::{
        credentials::validate_credentials, reaper::discard_sessions, user_session::UserSession,
    },
    util::time::unix_now_secs,
    AppState,
};

#[derive(Deserialize)]
pub struct CreateSession {
    username: String,
    password: String,
}

#[options("/")]
pub fn session_options() -> Result<RequestSuccess, RequestError> {
    trace!("Entering route::session::session_options");

    Ok(RequestSuccess::NoContent)
}

#[post("/", format = "json", data = "<reqbody>")]
pub async fn create_session(
    reqbody: Json<CreateSession>,
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [POST /session]");

    validate_credentials(&reqbody.username, &reqbody.password)?;

    let passphrase = SecretString::from_str(reqbody.password.as_str()).unwrap();
    let user_name = reqbody.username.clone();

    trace!("Attempting to open user session for user: {}", user_name);

    // Clear out expired sessions first, so they don't count against this user's
    // session limit and don't linger when the background reaper is disabled.
    discard_sessions(state.sessions.remove_expired(unix_now_secs()).await).await;

    let existing_pool = state.sessions.pool_for_user(&user_name).await;

    let session = Arc::new(
        match UserSession::open(&user_name, &passphrase, existing_pool).await {
            Ok(a) => {
                trace!("User session opened successfully.");

                a
            },
            Err(e) => {
                // Every failure is the same 401, so the response never reveals
                // whether the account exists.
                warn!("Failed to open user session: {}", e);

                return Err(RequestError::Unauthorized);
            },
        },
    );

    let (user_token, session_id) = {
        let session_read = session.clone();
        (
            session_read.user_token.expose_secret().clone(),
            session_read.session_id.clone(),
        )
    };

    trace!("Generated new session ID: {}", session_id);

    let secure_cookies = env::var("JUSTENCRYPT_SECURE_COOKIES")
        .unwrap_or_else(|_| "true".to_string())
        .parse::<bool>()
        .unwrap_or(true);

    let max_lifetime_secs = state.sessions.policy().max_lifetime.as_secs();

    let mut cookie = Cookie::new("sid", user_token.clone());
    cookie.set_same_site(Some(SameSite::Strict));
    cookie.set_secure(secure_cookies);
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::seconds(
        i64::try_from(max_lifetime_secs).unwrap_or(i64::MAX),
    ));
    cookies.add_private(cookie);

    trace!("Session cookie added to jar.");

    let evicted = state.sessions.insert(user_token, session.clone()).await;

    trace!("Session added to active session map.");

    if !evicted.is_empty() {
        info!(
            "User {} is over the session limit; ending {} older session(s).",
            user_name,
            evicted.len()
        );

        discard_sessions(evicted).await;
    }

    let active_session_ids = state
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

    state.orphan_scanner.scan_in_background(session.clone());

    trace!("Exiting route [POST /session] successfully.");

    Ok(RequestSuccess::Created)
}

#[delete("/")]
pub async fn destroy_session(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [DELETE /session]");

    let cookie = match cookies.get_private("sid") {
        Some(c) => {
            trace!("Found sid cookie.");

            c
        },
        None => {
            trace!("sid cookie not found.");

            return Err(RequestError::MissingSessionId);
        },
    };

    let user_token = cookie.value().to_string();

    // The browser should forget the cookie whether or not the server still
    // knew the session.
    cookies.remove_private("sid");

    let result = match state.sessions.remove_by_token(&user_token).await {
        Some(session) => {
            trace!("Removed active session with ID: {}", session.session_id);

            discard_sessions(vec![session]).await;

            Ok(RequestSuccess::NoContent)
        },
        None => {
            trace!("User token not found in active session list.");

            Err(RequestError::MissingActiveSession)
        },
    };

    trace!("Exiting route [DELETE /session] successfully.");

    result
}
