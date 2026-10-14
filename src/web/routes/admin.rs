use std::time::SystemTime;

use axum::{extract::State, http::StatusCode, Json};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{
    enums::service_error::ServiceError,
    service::{
        accounts::create_account,
        admin::{self, SessionSummary, UploadSummary},
    },
    web::{
        extractors::{AdminGuard, JsonBody, PathParam},
        state::WebState,
    },
};

/// The body of `POST /admin/users`.
#[derive(Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub password: SecretString,
}

/// A live session, as `GET /admin/session` lists it.
#[derive(Serialize)]
pub struct ActiveSessionInfo {
    pub session_id: String,
    pub username: String,
    pub created_at: u64,
    pub active_uploads: Vec<ActiveFileUpload>,
}

/// An upload in progress, as `GET /admin/session` lists it.
#[derive(Serialize)]
pub struct ActiveFileUpload {
    upload_id: String,
    file_path: String,
    encoded_file_name: String,
    last_updated: SystemTime,
}

impl From<SessionSummary> for ActiveSessionInfo {
    fn from(session: SessionSummary) -> Self {
        Self {
            session_id: session.session_id,
            username: session.username,
            created_at: session.created_at,
            active_uploads: session
                .active_uploads
                .into_iter()
                .map(ActiveFileUpload::from)
                .collect(),
        }
    }
}

impl From<UploadSummary> for ActiveFileUpload {
    fn from(upload: UploadSummary) -> Self {
        Self {
            upload_id: upload.upload_id,
            file_path: upload.file_path,
            encoded_file_name: upload.encoded_file_name,
            last_updated: upload.last_updated,
        }
    }
}

/// Answers the CORS preflight for the `/admin` routes.
pub async fn admin_options() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Lists every live session, with its user and the uploads it has in
/// progress.
pub async fn get_session(
    _admin_guard: AdminGuard,
    State(state): State<WebState>,
) -> Json<Vec<ActiveSessionInfo>> {
    let sessions = admin::list_sessions(&state.app).await;

    Json(sessions.into_iter().map(ActiveSessionInfo::from).collect())
}

/// Ends the session `session_id` and cleans up its uploads in progress, as
/// logging out would. Fails with `MissingActiveSession` if there is no such
/// session.
pub async fn delete_session(
    _admin_guard: AdminGuard,
    State(state): State<WebState>,
    PathParam(session_id): PathParam<String>,
) -> Result<StatusCode, ServiceError> {
    admin::end_session(&state.app, &session_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Creates an account, with its encrypted database and storage directory.
/// Fails if the password is too weak or the account already exists.
pub async fn create_user(
    _admin_guard: AdminGuard,
    State(state): State<WebState>,
    JsonBody(reqbody): JsonBody<CreateUser>,
) -> Result<StatusCode, ServiceError> {
    let CreateUser { username, password } = reqbody;

    create_account(&username, &password, &state.app.config).await?;

    Ok(StatusCode::CREATED)
}
