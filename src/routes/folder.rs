use rocket::{
    delete, futures::future::BoxFuture, get, serde::json::Json, tokio::sync::RwLockWriteGuard,
};
use serde::{Deserialize, Serialize};

use crate::{
    db::sqlite::File,
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

#[options("/<_folder_path..>")]
pub fn folder_options(_folder_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[get("/<folder_path..>")]
pub async fn get_folder(
    folder_path: UnrestrictedPath, // The name/path of the folder being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<Json<Vec<File>>, RequestError> {
    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.read().await;

    let folder_contents = match session.get_folder(folder_path_buf).await {
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
    folder_path: UnrestrictedPath, // The name/path of the folder being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.read().await;

    match session.add_folder(folder_path_buf).await {
        Ok(_) => drop(session),
        Err(e) => {
            error!("Failed to add folder to db: {}", e);
            return Err(RequestError::FailedToCreateFolder);
        }
    }

    Ok(RequestSuccess::Created)
}

#[delete("/<folder_path..>")]
pub async fn delete_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.write().await;

    let folder_id = match session.get_folder_id(folder_path_buf.clone()).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to get folder id from db: {}", e);
            return Err(RequestError::FailedToCreateFolder);
        }
    };

    if folder_id.is_none() {
        return Err(RequestError::FailedToRemoveFile);
    }

    let user_path = session.get_user_path().clone();

    delete_folder_recursive(folder_id.unwrap(), &session, user_path)
        .await
        .await?;

    match session.delete_folder(folder_path_buf).await {
        Ok(_) => drop(session),
        Err(e) => {
            error!("Failed to delete folder: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    Ok(RequestSuccess::NoContent)
}

async fn delete_folder_recursive(
    folder_id: i32,
    session: &RwLockWriteGuard<'_, crate::session::user_session::UserSession>,
    user_path: std::path::PathBuf,
) -> BoxFuture<'static, Result<(), RequestError>> {
    let files = session.get_files_in_folder(folder_id).await.unwrap();

    for file in files {
        let encoded_file_name = file.encoded_name;
        let file_path = user_path.clone();
        let encoded_file_path = get_sharded_path(file_path.clone(), &encoded_file_name);

        //remove thumbnail if it exists
        if let Some(encoded_thumbnail_file_name) = session
            .get_encoded_thumbnail_file_name_by_file_id(file.id)
            .await
            .unwrap()
        {
            let encoded_thumbnail_file_path = get_sharded_path(
                user_path.clone().join(".cache"),
                &encoded_thumbnail_file_name,
            );

            if encoded_thumbnail_file_path.exists() {
                remove_sharded_path(&user_path, &encoded_thumbnail_file_path)
                    .await
                    .map_err(|e| {
                        error!("Failed to delete thumbnail file: {}", e);
                        RequestError::FailedToRemoveFile
                    })
                    .unwrap();
            } else {
                info!(
                    "Thumbnail file does not exist: {:?}",
                    encoded_thumbnail_file_path
                );
            }
        }

        remove_sharded_path(&user_path, &encoded_file_path)
            .await
            .map_err(|e| {
                error!("Failed to delete file: {}", e);
                RequestError::FailedToRemoveFile
            })
            .unwrap();

        session.delete_file_by_id(file.id).await.unwrap();
    }

    let child_folders = session.get_child_folders(folder_id).await.unwrap();

    for child_folder in child_folders {
        Box::pin(delete_folder_recursive(
            child_folder.id,
            session,
            user_path.clone(),
        ))
        .await
        .await
        .unwrap();
        Box::pin(session.delete_folder_by_id(child_folder.id))
            .await
            .unwrap();
    }

    Box::pin(async move { Ok(()) })
}
