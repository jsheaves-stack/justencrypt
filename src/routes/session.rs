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
    user_name: String,
    passphrase: String,
}

#[post("/create", format = "json", data = "<reqbody>")]
pub async fn create_session(
    reqbody: Json<CreateSession>,
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    let passphrase = SecretString::from_str(&reqbody.passphrase.as_str()).unwrap();
    let session = AppSession::open(&reqbody.user_name, &passphrase).await;

    match session {
        Ok(v) => {
            let uuid = Uuid::new_v4().hyphenated().to_string();

            let mut cookie = Cookie::new("session_id", uuid.clone());

            cookie.set_same_site(Some(SameSite::Strict));

            cookies.add_private(cookie);

            let mut active_sessions = state.active_sessions.write().await;

            active_sessions.insert(uuid, *v);

            Ok(RequestSuccess::NoContent)
        }
        Err(e) => {
            error!("{}", e);
            return Err(RequestError::FailedToCreateUserSession);
        }
    }
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
        Some(_) => return Ok(RequestSuccess::NoContent),
        None => return Err(RequestError::MissingActiveSession),
    };
}
