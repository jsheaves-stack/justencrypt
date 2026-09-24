use rocket::{delete, get, options, patch, put, serde::json::Json};

use crate::{
    db::sqlite::FolderContent,
    enums::{request_error::RequestError, request_success::RequestSuccess},
    util::{sharded_path::remove_blob_and_thumbnail, unrestricted_path::UnrestrictedPath},
    web::forwarding_guards::AuthenticatedSession,
};

#[options("/<folder_path..>")]
pub fn folder_options(folder_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /folder/{}]", folder_path);

    Ok(RequestSuccess::NoContent)
}

#[get("/<folder_path..>")]
pub async fn get_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<Json<Vec<FolderContent>>, RequestError> {
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

    let session = auth.session.clone();
    let user_path = session.get_user_path();

    // All database rows go in one transaction; the blobs are removed only once
    // it has committed, so a failure can never leave rows without their data.
    let blobs = session
        .delete_folder_tree(folder_path.to_path_buf())
        .await?;

    for encoded_name in blobs {
        remove_blob_and_thumbnail(&user_path, &encoded_name).await;
    }

    Ok(RequestSuccess::NoContent)
}

#[patch("/<folder_path..>", data = "<patch_data>")]
pub async fn patch_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    patch_data: Json<PatchFolderData>,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PATCH /folder/{}]", folder_path);

    let mut current_path_buf = folder_path.to_path_buf();

    if let Some(new_name) = &patch_data.folder_name {
        let session = auth.session.clone();
        session
            .rename_folder(current_path_buf.clone(), new_name.clone())
            .await?;

        current_path_buf.set_file_name(new_name);
    }

    if let Some(destination_folder) = &patch_data.parent_folder_path {
        let session = auth.session.clone();
        session
            .move_folder(current_path_buf, destination_folder.clone())
            .await?;
    }

    Ok(RequestSuccess::NoContent)
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PatchFolderData {
    pub folder_name: Option<String>,
    pub parent_folder_path: Option<String>,
}
