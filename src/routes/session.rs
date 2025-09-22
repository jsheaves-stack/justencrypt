use std::{str::FromStr, sync::Arc};

use rocket::{
    http::{Cookie, CookieJar, SameSite},
    options, post,
    serde::json::Json,
    tokio::sync::RwLock,
    State,
};
use secrecy::SecretString;
use serde::Deserialize;
use std::env;
use uuid::Uuid;
use zxcvbn::{zxcvbn, Score};

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    AppState, UserSession,
};

#[derive(Deserialize)]
pub struct CreateSession {
    username: String,
    password: String,
}

#[options("/create")]
pub fn create_session_options() -> Result<RequestSuccess, RequestError> {
    trace!("Entering route::session::create_session_options");
    Ok(RequestSuccess::NoContent)
}

#[post("/create", format = "json", data = "<reqbody>")]
pub async fn create_session(
    reqbody: Json<CreateSession>,
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [POST /session/create]");

    let score_str =
        env::var("JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE").unwrap_or_else(|_| "4".to_string());

    let score_num = score_str.parse::<u8>().unwrap_or(4);

    let minimum_password_security_score = match score_num {
        0 => Score::Zero,
        1 => Score::One,
        2 => Score::Two,
        3 => Score::Three,
        4 => Score::Four,
        _ => Score::Three,
    };

    let password_security_estimate = zxcvbn(reqbody.password.as_str(), &[]).score();

    trace!("Validating password security score.");

    if password_security_estimate < minimum_password_security_score {
        trace!(
            "Password score {} does not meet minimum required score {}.",
            password_security_estimate,
            minimum_password_security_score
        );

        return Err(RequestError::PasswordDoesNotMeetRequirements);
    }

    trace!("Password meets requirements.");

    let passphrase = SecretString::from_str(reqbody.password.as_str()).unwrap();
    let user_name = reqbody.username.clone();

    trace!("Attempting to open user session for user: {}", user_name);
    let session = Arc::new(RwLock::new(
        match UserSession::open(&user_name, &passphrase).await {
            Ok(a) => {
                trace!("User session opened successfully.");
                a
            }
            Err(e) => {
                error!("Failed to create user session: {}", e);
                return Err(RequestError::FailedToCreateUserSession);
            }
        },
    ));

    let uuid = Uuid::new_v4().hyphenated().to_string();
    trace!("Generated new session UUID: {}", uuid);

    let mut cookie = Cookie::new("session_id", uuid.clone());
    cookie.set_same_site(Some(SameSite::Strict));
    cookies.add_private(cookie);
    trace!("Session cookie added to jar.");

    state.active_sessions.write().await.insert(uuid, session);
    trace!("Session added to active sessions map.");

    trace!("Exiting route [POST /session/create] successfully.");
    Ok(RequestSuccess::NoContent)
}

#[options("/destroy")]
pub fn destroy_session_options() -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /session/destroy]");
    Ok(RequestSuccess::NoContent)
}

#[post("/destroy")]
pub async fn destroy_session(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [POST /session/destroy]");
    let mut active_sessions = state.active_sessions.write().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => {
            trace!("Found session_id cookie.");
            c
        }
        None => {
            trace!("session_id cookie not found.");
            return Err(RequestError::MissingSessionId);
        }
    };

    let result = match active_sessions.remove(cookie.value()) {
        Some(_) => {
            trace!("Removed active session with ID: {}", cookie.value());
            Ok(RequestSuccess::NoContent)
        }
        None => {
            trace!(
                "Session ID {} not found in active sessions.",
                cookie.value()
            );
            Err(RequestError::MissingActiveSession)
        }
    };

    trace!("Exiting route [POST /session/destroy] successfully.");
    result
}
