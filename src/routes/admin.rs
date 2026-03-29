use std::time::SystemTime;

use rocket::{delete, get, options, serde::json::Json, State};
use secrecy::ExposeSecret;
use serde::Serialize;

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    web::forwarding_guards::AdminGuard,
    AppState,
};

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
    let sessions_by_id = state.sessions_by_id.read().await;
    let mut session_list = Vec::new();

    for (session_id, session_lock) in sessions_by_id.iter() {
        let session = session_lock.clone();
        let mut active_uploads = Vec::<ActiveFileUpload>::new();

        let session_uploads = session.active_uploads.lock().await;
        for (id, state) in session_uploads.iter() {
            active_uploads.push(ActiveFileUpload {
                upload_id: id.clone(),
                file_path: state.file_path.display().to_string(),
                encoded_file_name: state.encoded_file_name.clone(),
                last_updated: *state.last_updated.lock().await,
            });
        }

        session_list.push(ActiveSessionInfo {
            session_id: session_id.clone(),
            username: session.username.clone(),
            created_at: session
                .created_at
                .duration_since(std::time::UNIX_EPOCH)
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
    let mut sessions_by_id = state.sessions_by_id.write().await;
    let mut token_to_id = state.token_to_id.write().await;

    if let Some(session_lock) = sessions_by_id.remove(&session_id) {
        let session = session_lock.clone();
        let user_token = session.user_token.expose_secret();
        token_to_id.remove(user_token);
        Ok(RequestSuccess::NoContent)
    } else {
        Err(RequestError::MissingActiveSession)
    }
}

#[options("/session")]
pub async fn admin_options() {}

#[options("/session/<_session_id>")]
pub async fn delete_session_options(_session_id: String) {}
