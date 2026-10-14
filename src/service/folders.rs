//! A user's folders: listing, creating, renaming and moving, deleting, and
//! downloading one with everything below it.

use std::path::PathBuf;

use crate::{
    app::App, db::sqlite::FolderContent, enums::service_error::ServiceError,
    session::user_session::UserSession, util::folder_archive::FolderArchive,
};

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

/// The files and folders directly inside the folder at `folder_path`.
pub async fn list(
    session: &UserSession,
    folder_path: PathBuf,
) -> Result<Vec<FolderContent>, ServiceError> {
    Ok(session.context.get_folder(folder_path).await?)
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
