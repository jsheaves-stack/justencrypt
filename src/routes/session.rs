use std::{str::FromStr, sync::Arc};

use rocket::{
    http::{Cookie, CookieJar, SameSite},
    serde::json::Json,
    tokio::sync::Mutex,
    State,
};
use secrecy::SecretString;
use serde::Deserialize;
use uuid::Uuid;

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
    Ok(RequestSuccess::NoContent)
}

#[post("/create", format = "json", data = "<reqbody>")]
pub async fn create_session(
    reqbody: Json<CreateSession>,
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    let passphrase = SecretString::from_str(reqbody.password.as_str()).unwrap();
    let user_name = reqbody.username.clone();

    let session = Arc::new(Mutex::new(
        match UserSession::open(&user_name, &passphrase).await {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to create user session: {}", e);
                return Err(RequestError::FailedToCreateUserSession);
            }
        },
    ));

    let uuid = Uuid::new_v4().hyphenated().to_string();

    let mut cookie = Cookie::new("session_id", uuid.clone());

    cookie.set_same_site(Some(SameSite::Strict));

    cookies.add_private(cookie);

    state.active_sessions.write().await.insert(uuid, session);

    Ok(RequestSuccess::NoContent)
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
