//! A user's folders: listing, creating, renaming and moving, deleting, and
//! downloading one with everything below it.

use std::path::PathBuf;

use crate::{
    app::App,
    db::sqlite::{self, FolderContent},
    enums::service_error::ServiceError,
    session::user_session::UserSession,
    util::folder_archive::FolderArchive,
};

/// One entry of a folder listing.
pub enum Entry {
    File(FileSummary),
    Folder(FolderSummary),
}

/// A file in a folder listing.
pub struct FileSummary {
    pub extension: Option<String>,
    pub name: String,
    pub size: Option<u64>,
    pub created_date: Option<String>,
    pub last_modified_date: Option<String>,
}

/// A folder in a folder listing, with the totals of everything below it.
pub struct FolderSummary {
    pub name: String,
    pub size: Option<u64>,
    pub created_date: Option<String>,
    pub last_modified_date: Option<String>,
    pub file_count: u64,
    pub folder_count: u64,
}

/// What to change about a file or folder: a new name, a new parent folder, or
/// both.
pub struct EntryChanges {
    pub new_name: Option<String>,
    pub new_parent: Option<String>,
}

impl EntryChanges {
    /// Fails unless there is something to change.
    pub fn check_not_empty(&self) -> Result<(), ServiceError> {
        if self.new_name.is_none() && self.new_parent.is_none() {
            return Err(ServiceError::InvalidInput("Nothing to change".into()));
        }

        Ok(())
    }
}

impl From<FolderContent> for Entry {
    fn from(content: FolderContent) -> Self {
        match content {
            FolderContent::File(sqlite::File {
                file_extension,
                file_name,
                file_size,
                created_date,
                last_modified_date,
            }) => Entry::File(FileSummary {
                extension: file_extension,
                name: file_name,
                size: file_size,
                created_date,
                last_modified_date,
            }),
            FolderContent::Folder(sqlite::Folder {
                file_name,
                file_size,
                created_date,
                last_modified_date,
                file_count,
                folder_count,
            }) => Entry::Folder(FolderSummary {
                name: file_name,
                size: file_size,
                created_date,
                last_modified_date,
                file_count,
                folder_count,
            }),
        }
    }
}

/// The files and folders directly inside the folder at `folder_path`.
pub async fn list(session: &UserSession, folder_path: PathBuf) -> Result<Vec<Entry>, ServiceError> {
    let contents = session.context.get_folder(folder_path).await?;

    Ok(contents.into_iter().map(Entry::from).collect())
}

/// Creates the folder at `folder_path`, and any missing parent folders.
pub async fn create(session: &UserSession, folder_path: PathBuf) -> Result<(), ServiceError> {
    Ok(session.context.add_folder(folder_path).await?)
}

/// Deletes the folder at `folder_path` and everything below it.
pub async fn delete(session: &UserSession, folder_path: PathBuf) -> Result<(), ServiceError> {
    // All database rows go in one transaction; the blobs are removed only once
    // it has committed, so a failure can never leave rows without their data.
    let blobs = session.context.delete_folder_tree(folder_path).await?;

    for encoded_name in blobs {
        session
            .context
            .remove_blob_and_thumbnail(&encoded_name)
            .await;
    }

    Ok(())
}

/// Renames the folder at `folder_path`, moves it to another folder, or both.
pub async fn update(
    session: &UserSession,
    folder_path: PathBuf,
    changes: EntryChanges,
) -> Result<(), ServiceError> {
    changes.check_not_empty()?;

    Ok(session
        .context
        .update_folder(folder_path, changes.new_name, changes.new_parent)
        .await?)
}

/// Starts streaming the folder at `folder_path`, with everything below it, as
/// a TAR archive.
pub async fn archive(
    app: &App,
    session: &UserSession,
    folder_path: PathBuf,
) -> Result<FolderArchive, ServiceError> {
    // Waits while the user already has as many folder downloads running as
    // they may. This comes first, so a download waiting on its own user never
    // holds one of the server-wide permits other users need.
    let user_permit = session
        .context
        .folder_download_permit()
        .await
        .ok_or(ServiceError::TooManyActiveDownloads)?;

    let server_permit = app
        .download_semaphore
        .as_ref()
        .map(|semaphore| semaphore.clone().try_acquire_owned())
        .transpose()
        .map_err(|_| ServiceError::TooManyActiveDownloads)?;

    Ok(session
        .context
        .stream_folder_archive(
            folder_path,
            session.username.clone(),
            (server_permit, user_permit),
            app.config.download_stall_timeout(),
        )
        .await?)
}
