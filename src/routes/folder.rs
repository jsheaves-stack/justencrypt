use rocket::{delete, get, options, put, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    db::sqlite::FolderEntry,
    enums::{request_error::RequestError, request_success::RequestSuccess},
    get_sharded_path, remove_sharded_path,
    web::forwarding_guards::AuthenticatedSession,
    UnrestrictedPath,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GetFolder {
    is_file: bool,
    file_extension: Option<String>,
    file_name: String,
}

#[options("/<folder_path..>")]
pub fn folder_options(folder_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /folder{}]", folder_path);
    Ok(RequestSuccess::NoContent)
}

#[get("/<folder_path..>")]
pub async fn get_folder(
    folder_path: UnrestrictedPath, // The name/path of the folder being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<Json<Vec<FolderEntry>>, RequestError> {
    trace!("Entering route [GET /folder{}]", folder_path);
    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.read().await;

    let folder_contents = match session.get_folder(folder_path_buf).await {
        Ok(f) => {
            trace!("Successfully retrieved folder contents.");
            drop(session);
            f
        }
        Err(e) => {
            error!("Failed to get folder contents from db: {}", e);
            return Err(RequestError::FailedToReadFolderContents);
        }
    };

    trace!("Exiting route [GET /folder{}] successfully.", folder_path);
    Ok(Json(folder_contents))
}

#[put("/<folder_path..>")]
pub async fn create_folder(
    folder_path: UnrestrictedPath, // The name/path of the folder being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PUT /folder{}]", folder_path);
    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.read().await;

    match session.add_folder(folder_path_buf).await {
        Ok(_) => {
            trace!("Successfully added folder to db.");
            drop(session)
        }
        Err(e) => {
            error!("Failed to add folder to db: {}", e);
            return Err(RequestError::FailedToCreateFolder);
        }
    }

    trace!("Exiting route [PUT /folder{}] successfully.", folder_path);
    Ok(RequestSuccess::Created)
}

#[delete("/<folder_path..>")]
pub async fn delete_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [DELETE /folder{}]", folder_path);
    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.write().await;

    let folder_id = match session.get_folder_id(folder_path_buf.clone()).await {
        Ok(Some(id)) => {
            trace!("Found root folder to delete with ID: {}", id);
            id
        }
        Ok(None) => {
            trace!("Folder to delete not found in db.");
            return Err(RequestError::FailedToRemoveFile);
        }
        Err(e) => {
            error!("Failed to get folder id from db: {}", e);
            return Err(RequestError::FailedToCreateFolder);
        }
    };

    let user_path = session.get_user_path().clone();
    let mut folder_stack: Vec<i32> = vec![folder_id];
    trace!("Starting recursive delete from folder ID: {}", folder_id);

    while let Some(current_folder_id) = folder_stack.pop() {
        trace!("Processing folder ID: {}", current_folder_id);
        let files = match session.get_files_in_folder(current_folder_id).await {
            Ok(files) => files,
            Err(e) => {
                error!("Failed to get files in folder: {}", e);
                return Err(RequestError::FailedToReadFolderContents);
            }
        };
        trace!(
            "Found {} files in folder ID {}",
            files.len(),
            current_folder_id
        );

        for file in files {
            trace!(
                "Deleting file with ID: {}, encoded_name: {}",
                file.id,
                file.encoded_name
            );
            let encoded_file_path = get_sharded_path(user_path.clone(), &file.encoded_name);

            // Remove thumbnail if it exists
            if let Ok(Some(encoded_thumbnail_file_name)) = session
                .get_encoded_thumbnail_file_name_by_file_id(file.id)
                .await
            {
                trace!("Found thumbnail to delete: {}", encoded_thumbnail_file_name);
                let encoded_thumbnail_file_path = get_sharded_path(
                    user_path.clone().join(".cache"),
                    &encoded_thumbnail_file_name,
                );

                if encoded_thumbnail_file_path.exists() {
                    if let Err(e) =
                        remove_sharded_path(&user_path, &encoded_thumbnail_file_path).await
                    {
                        error!("Failed to delete thumbnail file: {}", e);
                    }
                } else {
                    info!(
                        "Thumbnail file does not exist: {:?}",
                        encoded_thumbnail_file_path
                    );
                }
            }

            if let Err(e) = remove_sharded_path(&user_path, &encoded_file_path).await {
                error!("Failed to delete file: {}", e);
            }

            if let Err(e) = session.delete_file_by_id(file.id).await {
                error!("Failed to delete file by id: {}", e);
            }
        }

        let child_folder_ids = match session.get_child_folders(current_folder_id).await {
            Ok(child_folders) => child_folders,
            Err(e) => {
                error!("Failed to get child folders: {}", e);
                return Err(RequestError::FailedToReadFolderContents);
            }
        };
        trace!(
            "Found {} child folders in folder ID {}",
            child_folder_ids.len(),
            current_folder_id
        );

        for child_folder_id in child_folder_ids {
            folder_stack.push(child_folder_id);
        }

        if current_folder_id != folder_id {
            trace!("Deleting folder metadata for ID: {}", current_folder_id);
            if let Err(e) = session.delete_folder_by_id(current_folder_id).await {
                error!("Failed to delete folder by id: {}", e);
            }
        }
    }

    trace!(
        "Deleting root folder metadata for path: {:?}",
        folder_path_buf
    );
    if let Err(e) = session.delete_folder(folder_path_buf).await {
        error!("Failed to delete folder: {}", e);
        return Err(RequestError::FailedToRemoveFile);
    }

    drop(session);

    trace!(
        "Exiting route [DELETE /folder{}] successfully.",
        folder_path
    );
    Ok(RequestSuccess::NoContent)
}
