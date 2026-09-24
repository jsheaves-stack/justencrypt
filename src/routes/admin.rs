use std::time::{SystemTime, UNIX_EPOCH};

use rocket::{delete, get, options, post, serde::json::Json, State};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    session::accounts::create_account,
    web::forwarding_guards::AdminGuard,
    AppState,
};

#[derive(Deserialize, Serialize)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct ActiveSessionInfo {
    pub session_id: String,
    pub username: String,
    pub created_at: u64,
    pub active_uploads: Vec<ActiveFileUpload>,
}

#[derive(Serialize)]
pub struct ActiveFileUpload {
    upload_id: String,
    file_path: String,
    encoded_file_name: String,
    last_updated: SystemTime,
}

#[get("/session")]
pub async fn get_session(
    _admin_guard: AdminGuard,
    state: &State<AppState>,
) -> Json<Vec<ActiveSessionInfo>> {
    let sessions = state.sessions.snapshot().await;
    let mut session_list = Vec::new();

    for session in sessions {
        let mut active_uploads = Vec::<ActiveFileUpload>::new();

        let session_uploads = session.active_uploads.lock().await;
        for (id, state) in session_uploads.iter() {
            active_uploads.push(ActiveFileUpload {
                upload_id: id.clone(),
                file_path: state.file_path.display().to_string(),
                encoded_file_name: state.encoded_file_name.clone(),
                last_updated: state.last_updated(),
            });
        }

        session_list.push(ActiveSessionInfo {
            session_id: session.session_id.clone(),
            username: session.username.clone(),
            created_at: session
                .created_at
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            active_uploads,
        });
    }

    Json(session_list)
}

#[delete("/session/<session_id>")]
pub async fn delete_session(
    _admin_guard: AdminGuard,
    session_id: String,
    state: &State<AppState>,
) -> Result<RequestSuccess, RequestError> {
    match state.sessions.remove_by_id(&session_id).await {
        Some(_) => Ok(RequestSuccess::NoContent),
        None => Err(RequestError::MissingActiveSession),
    }
}

#[options("/session")]
pub async fn admin_options() {}

#[options("/session/<_session_id>")]
pub async fn delete_session_options(_session_id: String) {}

#[post("/users", format = "json", data = "<reqbody>")]
pub async fn create_user(
    _admin_guard: AdminGuard,
    reqbody: Json<CreateUser>,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [POST /admin/users]");

    let CreateUser { username, password } = reqbody.into_inner();

    create_account(&username, &SecretString::from(password)).await?;

    Ok(RequestSuccess::Created)
}

#[options("/users")]
pub async fn create_user_options() {}
