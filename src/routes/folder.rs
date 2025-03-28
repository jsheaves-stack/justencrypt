use rocket::{get, serde::json::Json};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    db::db::File,
    enums::{request_error::RequestError, request_success::RequestSuccess},
    web::forwarding_guards::AuthenticatedSession,
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
    auth: AuthenticatedSession,
) -> Result<Json<Vec<File>>, RequestError> {
    let mut session = auth.session.lock().await;

    let folder_contents = match session.get_folder(folder_path).await {
        Ok(f) => {
            drop(session);
            f
        }
        Err(e) => {
            error!("Failed to get folder contents from db: {}", e);
            return Err(RequestError::FailedToReadFolderContents);
        }
    };

    Ok(Json(folder_contents))
}

#[put("/<folder_path..>")]
pub async fn create_folder(
    folder_path: PathBuf, // The name/path of the folder being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    let mut session = auth.session.lock().await;

    match session.add_folder(folder_path).await {
        Ok(_) => drop(session),
        Err(e) => {
            error!("Failed to create StreamDecryptor: {}", e);
            return Err(RequestError::FailedToCreateFolder);
        }
    }

    Ok(RequestSuccess::Created)
}
