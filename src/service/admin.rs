//! What the holder of the admin API key can do: list and end sessions.
//! Accounts are created through [`accounts`](crate::service::accounts).

use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::ExposeSecret;

use crate::{app::App, enums::service_error::ServiceError, session::reaper::discard_sessions};

/// A live session, with its user and the uploads it has in progress.
pub struct SessionSummary {
    pub session_id: String,
    pub username: String,
    /// Unix seconds when the session was created.
    pub created_at: u64,
    pub active_uploads: Vec<UploadSummary>,
}

/// An upload in progress.
pub struct UploadSummary {
    pub upload_id: String,
    pub file_path: String,
    pub encoded_file_name: String,
    pub last_updated: SystemTime,
}

/// Checks `provided` against the configured admin API key. Fails with
/// `InvalidApiKey` when it is missing or wrong, and with `Internal` when no
/// key is configured.
pub fn verify_api_key(app: &App, provided: Option<&str>) -> Result<(), ServiceError> {
    let Some(api_key) = app.config.admin_api_key.as_ref() else {
        return Err(ServiceError::Internal);
    };

    match provided {
        Some(key) if key == api_key.expose_secret() => Ok(()),
        _ => Err(ServiceError::InvalidApiKey),
    }
}

/// Every live session, with its user and the uploads it has in progress.
pub async fn list_sessions(app: &App) -> Vec<SessionSummary> {
    let mut session_list = Vec::new();

    for session in app.sessions.snapshot().await {
        let mut active_uploads = Vec::new();

        let session_uploads = session.active_uploads.lock().await;
        for (id, state) in session_uploads.iter() {
            active_uploads.push(UploadSummary {
                upload_id: id.clone(),
                file_path: state.file_path.display().to_string(),
                encoded_file_name: state.encoded_file_name.clone(),
                last_updated: state.last_updated(),
            });
        }

        session_list.push(SessionSummary {
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

    session_list
}

/// Ends the session `session_id` and cleans up its uploads in progress, as
/// logging out would. Fails with `MissingActiveSession` if there is no such
/// session.
pub async fn end_session(app: &App, session_id: &str) -> Result<(), ServiceError> {
    match app.sessions.remove_by_id(session_id).await {
        Some(session) => {
            discard_sessions(vec![session]).await;

            Ok(())
        },
        None => Err(ServiceError::MissingActiveSession),
    }
}
