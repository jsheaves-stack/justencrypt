use axum::{body::Body, extract::State, http::StatusCode};
use futures_util::TryStreamExt;
use serde::Deserialize;
use tokio_util::io::StreamReader;

use crate::{
    enums::service_error::ServiceError,
    service::{files, folders::EntryChanges},
    web::{
        extractors::{AuthenticatedSession, JsonBody, RangeHeader},
        responses::FileResponse,
        state::WebState,
        unrestricted_path::UnrestrictedPath,
    },
};

/// The body of `PATCH /file`: a new name, a new folder, or both.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFileData {
    pub file_name: Option<String>,
    pub parent_folder_path: Option<String>,
}

/// Answers the CORS preflight for `/file/<file_path..>`.
pub async fn file_options() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Uploads a file in a single request, encrypting the body as it arrives,
/// and stores it at `file_path`, replacing any file already there.
pub async fn put_file(
    State(state): State<WebState>,
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    body: Body,
) -> Result<StatusCode, ServiceError> {
    let body = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));

    files::store(&state.app, &auth.session, file_path.to_path_buf(), body).await?;

    Ok(StatusCode::CREATED)
}

/// Streams the file at `file_path`, decrypting it as it is sent. A single
/// `Range` gets just those bytes.
pub async fn get_file(
    State(state): State<WebState>,
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    range: RangeHeader,
) -> Result<FileResponse, ServiceError> {
    let file = files::find(&auth.session, file_path.to_path_buf()).await?;
    let range = range.parse()?;
    let download = files::download(&state.app, &auth.session, file, range).await?;

    Ok(FileResponse(download))
}

/// Deletes the file at `file_path`.
pub async fn delete_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<StatusCode, ServiceError> {
    files::delete(&auth.session, file_path.to_path_buf()).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Renames the file at `file_path`, moves it to another folder, or both.
pub async fn patch_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    JsonBody(patch_data): JsonBody<PatchFileData>,
) -> Result<StatusCode, ServiceError> {
    let PatchFileData {
        file_name,
        parent_folder_path,
    } = patch_data;
    let changes = EntryChanges {
        new_name: file_name,
        new_parent: parent_folder_path,
    };

    files::update(&auth.session, file_path.to_path_buf(), changes).await?;

    Ok(StatusCode::NO_CONTENT)
}
