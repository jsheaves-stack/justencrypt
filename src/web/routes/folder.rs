use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    enums::service_error::ServiceError,
    service::folders::{self, Entry, EntryChanges, FileSummary, FolderSummary},
    web::{
        extractors::{AuthenticatedSession, JsonBody, QueryParams},
        responses::ArchiveResponse,
        state::WebState,
        unrestricted_path::UnrestrictedPath,
    },
};

/// One entry of a folder listing, as `GET /folder` returns it.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FolderEntry {
    File(FileEntry),
    Folder(FolderEntrySummary),
}

/// A file in a folder listing.
#[derive(Serialize, Deserialize)]
pub struct FileEntry {
    pub file_extension: Option<String>,
    pub file_name: String,
    pub file_size: Option<u64>,
    pub created_date: Option<String>,
    pub last_modified_date: Option<String>,
}

/// A folder in a folder listing, with the totals of everything below it.
#[derive(Serialize, Deserialize)]
pub struct FolderEntrySummary {
    pub file_name: String,
    pub file_size: Option<u64>,
    pub created_date: Option<String>,
    pub last_modified_date: Option<String>,
    pub file_count: u64,
    pub folder_count: u64,
}

impl From<Entry> for FolderEntry {
    fn from(entry: Entry) -> Self {
        match entry {
            Entry::File(FileSummary {
                extension,
                name,
                size,
                created_date,
                last_modified_date,
            }) => FolderEntry::File(FileEntry {
                file_extension: extension,
                file_name: name,
                file_size: size,
                created_date,
                last_modified_date,
            }),
            Entry::Folder(FolderSummary {
                name,
                size,
                created_date,
                last_modified_date,
                file_count,
                folder_count,
            }) => FolderEntry::Folder(FolderEntrySummary {
                file_name: name,
                file_size: size,
                created_date,
                last_modified_date,
                file_count,
                folder_count,
            }),
        }
    }
}

/// The query of `GET /folder`. With `download`, whatever its value, the
/// folder is sent as an archive instead of listed.
#[derive(Deserialize)]
pub struct FolderQuery {
    pub download: Option<String>,
}

/// The body of `PATCH /folder`: a new name, a new parent folder, or both.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFolderData {
    pub folder_name: Option<String>,
    pub parent_folder_path: Option<String>,
}

/// Answers the CORS preflight for `/folder/<folder_path..>`.
pub async fn folder_options() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Lists the files and folders directly inside the folder at `folder_path`,
/// or, with `?download`, streams the folder and everything below it as a TAR
/// archive.
pub async fn get_folder(
    State(state): State<WebState>,
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    QueryParams(query): QueryParams<FolderQuery>,
) -> Result<Response, ServiceError> {
    if query.download.is_some() {
        let archive =
            folders::archive(&state.app, &auth.session, folder_path.to_path_buf()).await?;

        return Ok(ArchiveResponse(archive).into_response());
    }

    let entries = folders::list(&auth.session, folder_path.to_path_buf()).await?;
    let entries: Vec<FolderEntry> = entries.into_iter().map(FolderEntry::from).collect();

    Ok(Json(entries).into_response())
}

/// Creates the folder at `folder_path`, and any missing parent folders.
pub async fn create_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<StatusCode, ServiceError> {
    folders::create(&auth.session, folder_path.to_path_buf()).await?;

    Ok(StatusCode::CREATED)
}

/// Deletes the folder at `folder_path` and everything below it.
pub async fn delete_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<StatusCode, ServiceError> {
    folders::delete(&auth.session, folder_path.to_path_buf()).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Renames the folder at `folder_path`, moves it to another folder, or both.
pub async fn patch_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    JsonBody(patch_data): JsonBody<PatchFolderData>,
) -> Result<StatusCode, ServiceError> {
    let PatchFolderData {
        folder_name,
        parent_folder_path,
    } = patch_data;
    let changes = EntryChanges {
        new_name: folder_name,
        new_parent: parent_folder_path,
    };

    folders::update(&auth.session, folder_path.to_path_buf(), changes).await?;

    Ok(StatusCode::NO_CONTENT)
}
