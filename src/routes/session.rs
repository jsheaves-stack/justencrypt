use std::str::FromStr;

use rocket::{
    http::{Cookie, CookieJar, SameSite},
    serde::json::Json,
    State,
};
use secrecy::SecretString;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    AppSession, AppState,
};

#[derive(Deserialize)]
pub struct CreateSession {
    username: String,
    password: String,
}

#[options("/create")]
pub fn create_session_options() -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[post("/create", format = "json", data = "<reqbody>")]
pub async fn create_session(
    reqbody: Json<CreateSession>,
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    let passphrase = SecretString::from_str(reqbody.password.as_str()).unwrap();
    let session = AppSession::open(&reqbody.username, &passphrase).await;

    match session {
        Ok(v) => {
            let uuid = Uuid::new_v4().hyphenated().to_string();

            let mut cookie = Cookie::new("session_id", uuid.clone());

            cookie.set_same_site(Some(SameSite::Strict));

            cookies.add_private(cookie);

            let mut active_sessions = state.active_sessions.write().await;

            active_sessions.insert(uuid, v);

            Ok(RequestSuccess::NoContent)
        }
        Err(e) => {
            error!("{}", e);
            Err(RequestError::FailedToCreateUserSession)
        }
    }
}

#[options("/destroy")]
pub fn destroy_session_options() -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[post("/destroy")]
pub async fn destroy_session(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    let mut active_sessions = state.active_sessions.write().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => return Err(RequestError::MissingSessionId),
    };

    match active_sessions.remove(cookie.value()) {
        Some(_) => Ok(RequestSuccess::NoContent),
        None => Err(RequestError::MissingActiveSession),
    }
}

#[options("/")]
pub fn check_session_options() -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[get("/")]
pub async fn check_session(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    // Read access to the active sessions map.
    let active_sessions = state.active_sessions.read().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => return Err(RequestError::MissingSessionId),
    };

    match active_sessions.get(cookie.value()) {
        Some(_) => Ok(RequestSuccess::NoContent),
        None => Err(RequestError::MissingActiveSession),
    }
}
