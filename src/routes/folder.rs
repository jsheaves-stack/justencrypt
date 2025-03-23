use rocket::{get, http::CookieJar, State};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    AppState,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GetFolder {
    is_file: bool,
    file_extension: Option<String>,
    file_name: String,
}

#[options("/<_folder_path..>")]
pub fn folder_options(_folder_path: PathBuf) -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[get("/<folder_path..>")]
pub async fn get_folder(
    folder_path: PathBuf, // The name/path of the folder being requested, extracted from the URL.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> Result<(), RequestError> {
    // Read access to the active sessions map.
    let active_sessions = state.active_sessions.read().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => return Err(RequestError::MissingSessionId),
    };

    let session = match active_sessions.get(cookie.value()) {
        Some(s) => s,
        None => return Err(RequestError::MissingActiveSession),
    };

    Ok(())
}

#[put("/<folder_path..>")]
pub async fn create_folder(
    folder_path: PathBuf, // The name/path of the folder being requested, extracted from the URL.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> Result<RequestSuccess, RequestError> {
    // Lock the active sessions map for write access.
    let mut active_sessions = state.active_sessions.write().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => return Err(RequestError::MissingSessionId),
    };

    let session = match active_sessions.get_mut(cookie.value()) {
        Some(s) => s,
        None => return Err(RequestError::MissingActiveSession),
    };

    // Process the file path to separate it into components.
    let components = folder_path
        .iter()
        .filter_map(|s| s.to_str())
        .map(String::from)
        .collect::<Vec<String>>();

    Ok(RequestSuccess::Created)
}
