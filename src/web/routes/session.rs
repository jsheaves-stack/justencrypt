use axum::{extract::State, http::StatusCode};
use axum_extra::extract::PrivateCookieJar;
use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    enums::service_error::ServiceError,
    service::auth,
    web::{
        cookies::{session_cookie, session_cookie_removal, SESSION_COOKIE},
        extractors::JsonBody,
        state::WebState,
    },
};

/// The body of `POST /session`: the credentials to log in with.
#[derive(Deserialize)]
pub struct CreateSession {
    username: String,
    password: SecretString,
}

/// Answers the CORS preflight for `/session`.
pub async fn session_options() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Logs in: opens the user's encrypted database with their password and
/// sets the session cookie. Every failure is the same `401`, so the response
/// never reveals whether the account exists.
pub async fn create_session(
    State(state): State<WebState>,
    jar: PrivateCookieJar,
    JsonBody(reqbody): JsonBody<CreateSession>,
) -> Result<(PrivateCookieJar, StatusCode), ServiceError> {
    let CreateSession { username, password } = reqbody;

    let grant = auth::login(&state.app, &username, &password).await?;
    let cookie = session_cookie(
        grant.token,
        grant.max_age,
        state.app.config.http.secure_cookies,
    );

    trace!("Session cookie added to jar.");

    Ok((jar.add(cookie), StatusCode::CREATED))
}

/// Logs out: ends the session in the cookie, cleans up its uploads in
/// progress and clears the cookie.
pub async fn destroy_session(
    State(state): State<WebState>,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Result<StatusCode, ServiceError>), ServiceError> {
    let token = match jar.get(SESSION_COOKIE) {
        Some(cookie) => {
            trace!("Found sid cookie.");

            cookie.value().to_string()
        },
        None => {
            trace!("sid cookie not found.");

            return Err(ServiceError::MissingSessionId);
        },
    };

    // The browser should forget the cookie whether or not the server still
    // knew the session.
    let jar = jar.remove(session_cookie_removal());
    let result = auth::logout(&state.app, &token)
        .await
        .map(|()| StatusCode::NO_CONTENT);

    Ok((jar, result))
}
