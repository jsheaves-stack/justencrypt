use crate::{
    db::sqlite::FolderEntry,
    enums::{request_error::RequestError, request_success::RequestSuccess},
    util::{
        sharded_path::{get_sharded_path, remove_sharded_path},
        unrestricted_path::UnrestrictedPath,
    },
    web::forwarding_guards::AuthenticatedSession,
};
use rocket::{delete, get, options, put, serde::json::Json};

#[options("/<folder_path..>")]
pub fn folder_options(folder_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /folder/{}]", folder_path);
    Ok(RequestSuccess::NoContent)
}

#[get("/<folder_path..>")]
pub async fn get_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<Json<Vec<FolderEntry>>, RequestError> {
    trace!("Entering route [GET /folder/{}]", folder_path);

    let folder_path_buf = folder_path.to_path_buf();
    let folder_contents = {
        let session = auth.session.clone();
        session.get_folder(folder_path_buf).await?
    };

    Ok(Json(folder_contents))
}

#[put("/<folder_path..>")]
pub async fn create_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PUT /folder/{}]", folder_path);

    let folder_path_buf = folder_path.to_path_buf();
    {
        let session = auth.session.clone();
        session.add_folder(folder_path_buf).await.map_err(|e| {
            error!("Failed to add folder: {}", e);
            RequestError::FailedToCreateFolder
        })?;
    }

    Ok(RequestSuccess::Created)
}

#[delete("/<folder_path..>")]
pub async fn delete_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [DELETE /folder/{}]", folder_path);

    let folder_path_buf = folder_path.to_path_buf();
    let user_path = {
        let session = auth.session.clone();
        session.get_user_path()
    };

    let folder_id = {
        let session = auth.session.clone();
        session
            .get_folder_id(folder_path_buf.clone())
            .await?
            .ok_or(RequestError::NotFound)?
    };

    let mut folder_stack: Vec<i32> = vec![folder_id];
    let mut folders_to_delete: Vec<i32> = Vec::new();

    while let Some(current_folder_id) = folder_stack.pop() {
        folders_to_delete.push(current_folder_id);

        let files = {
            let session = auth.session.clone();
            session
                .get_files_in_folder(current_folder_id)
                .await
                .map_err(|e| {
                    error!("Failed to get files in folder {}: {}", current_folder_id, e);
                    RequestError::FailedToReadFolderContents
                })?
        };

        for file in files {
            let encoded_file_path = get_sharded_path(user_path.clone(), &file.encoded_name).await;

            let encoded_thumbnail_file_name = {
                let session = auth.session.clone();
                session
                    .get_encoded_thumbnail_file_name_by_file_id(file.id)
                    .await
                    .ok()
                    .flatten()
            };

            if let Some(name) = encoded_thumbnail_file_name {
                let encoded_thumbnail_file_path =
                    get_sharded_path(user_path.join(".cache"), &name).await;

                if encoded_thumbnail_file_path.exists() {
                    if let Err(e) =
                        remove_sharded_path(&user_path, &encoded_thumbnail_file_path).await
                    {
                        warn!(
                            "Failed to remove thumbnail file {:?}: {}",
                            encoded_thumbnail_file_path, e
                        );
                    }
                }
            }

            if let Err(e) = remove_sharded_path(&user_path, &encoded_file_path).await {
                warn!(
                    "Failed to remove physical file {:?}: {}",
                    encoded_file_path, e
                );
            }

            {
                let session = auth.session.clone();
                if let Err(e) = session.delete_file_by_id(file.id).await {
                    warn!("Failed to delete file entry {} from db: {}", file.id, e);
                }
            }
        }

        let child_folder_ids = {
            let session = auth.session.clone();
            session
                .get_child_folders(current_folder_id)
                .await
                .map_err(|e| {
                    error!(
                        "Failed to get child folders for {}: {}",
                        current_folder_id, e
                    );
                    RequestError::FailedToReadFolderContents
                })?
        };

        for child_folder_id in child_folder_ids {
            folder_stack.push(child_folder_id);
        }
    }

    for current_folder_id in folders_to_delete.into_iter().rev() {
        if current_folder_id != folder_id {
            let session = auth.session.clone();
            if let Err(e) = session.delete_folder_by_id(current_folder_id).await {
                warn!(
                    "Failed to delete folder entry {} from db: {}",
                    current_folder_id, e
                );
            }
        }
    }

    {
        let session = auth.session.clone();
        session.delete_folder(folder_path_buf).await.map_err(|e| {
            error!("Failed to delete root folder: {}", e);
            RequestError::FailedToRemoveFile
        })?;
    }

    Ok(RequestSuccess::NoContent)
}
