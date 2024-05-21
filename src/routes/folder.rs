use rocket::{get, http::CookieJar, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{enums::request_error::RequestError, session::session::FileSystemNode, AppState};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GetFolder {
    is_file: bool,
    file_extension: Option<String>,
    file_name: String,
}

impl From<&FileSystemNode> for GetFolder {
    fn from(node: &FileSystemNode) -> Self {
        GetFolder {
            is_file: node.is_file,
            file_extension: node.file_extension.clone(),
            file_name: node.file_name.clone(),
        }
    }
}

#[get("/<folder_path..>")]
pub async fn get_folder(
    folder_path: PathBuf, // The name/path of the folder being requested, extracted from the URL.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> Result<Json<Vec<GetFolder>>, RequestError> {
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

    let nodes = session.manifest.files.find_path_nodes(&folder_path);

    let simplified_nodes = nodes.iter().map(|&node| GetFolder::from(node)).collect();

    Ok(Json(simplified_nodes))
}
