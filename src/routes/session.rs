use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    AppState, UserSession,
};
use rocket::{
    http::{Cookie, CookieJar, SameSite},
    options, post,
    serde::json::Json,
    tokio::{sync::RwLock, task},
    State,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::{env, path::PathBuf, str::FromStr, sync::Arc};
use zxcvbn::{zxcvbn, Score};

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

    let user_name = reqbody.username.clone();
    let password = reqbody.password.clone();

    task::spawn_blocking(move || {
        let user_data_path =
            env::var("JUSTENCRYPT_USER_DATA_PATH").unwrap_or_else(|_| String::from("./user_data"));
        let user_db_path = PathBuf::from(&user_data_path)
            .join(&user_name)
            .join(format!("{}.db", user_name));

        if !user_db_path.exists() {
            trace!("User database does not exist, performing security score check.");
            let score_str = env::var("JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE")
                .unwrap_or_else(|_| "4".to_string());
            let score_num = score_str.parse::<u8>().unwrap_or(4);
            let minimum_password_security_score = match score_num {
                0 => Score::Zero,
                1 => Score::One,
                2 => Score::Two,
                3 => Score::Three,
                4 => Score::Four,
                _ => Score::Three,
            };

            let password_security_estimate = zxcvbn(password.as_str(), &[]).score();

            if password_security_estimate < minimum_password_security_score {
                trace!(
                    "Password score {} does not meet minimum required score {}.",
                    password_security_estimate,
                    minimum_password_security_score
                );
                return Err(RequestError::PasswordDoesNotMeetRequirements);
            }
            trace!("Password security score check passed.");
        } else {
            trace!("User database exists, skipping security score check.");
        }
        Ok(())
    })
    .await
    .map_err(|e| {
        error!("Blocking task failed: {}", e);
        RequestError::FailedToCreateUserSession
    })??;

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
                return Err(RequestError::Unauthorized);
            }
        },
    ));

    let (user_token, session_id) = {
        let session_read = session.read().await;
        (
            session_read.user_token.expose_secret().clone(),
            session_read.session_id.clone(),
        )
    };

    trace!("Generated new session ID: {}", session_id);

    let mut cookie = Cookie::new("__Host-id", user_token.clone());
    cookie.set_same_site(Some(SameSite::Strict));
    cookie.set_secure(true);
    cookies.add_private(cookie);

    trace!("Session cookie added to jar.");

    state
        .sessions_by_id
        .write()
        .await
        .insert(session_id.clone(), session);
    state
        .token_to_id
        .write()
        .await
        .insert(user_token, session_id);

    trace!("Session added to active session map.");

    trace!("Exiting route [POST /session] successfully.");

    Ok(RequestSuccess::Created)
}

#[delete("/")]
pub async fn destroy_session(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [DELETE /session]");

    let cookie = match cookies.get_private("__Host-id") {
        Some(c) => {
            trace!("Found __Host-id cookie.");
            c
        }
        None => {
            trace!("__Host-id cookie not found.");
            return Err(RequestError::MissingSessionId);
        }
    };

    let user_token = cookie.value();

    let mut sessions_by_id = state.sessions_by_id.write().await;
    let mut token_to_id = state.token_to_id.write().await;

    let result = match token_to_id.remove(user_token) {
        Some(session_id) => {
            sessions_by_id.remove(&session_id);
            trace!("Removed active session with ID: {}", session_id);
            Ok(RequestSuccess::NoContent)
        }
        None => {
            trace!("User token not found in active session list.");
            Err(RequestError::MissingActiveSession)
        }
    };

    trace!("Exiting route [DELETE /session] successfully.");

    result
}
