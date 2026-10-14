//! A user's files, folders and uploads in progress, as their database records
//! them. Every query runs on one of the user's connections, on one of their
//! blocking threads, through their [`UserContext`].

use std::{collections::HashSet, path::PathBuf, time::Duration};

use tokio::sync::{mpsc, oneshot};

use crate::{
    db::sqlite::{self, FolderContent},
    encryption::{FileEncryptionMetadata, MPSC_CHANNEL_CAPACITY},
    enums::db_error::DbError,
    storage::user_context::UserContext,
    util::folder_archive::{self, ChannelWriter, FolderArchive},
};

/// An upload recorded in the database: its id, the session that started it,
/// and the encoded name of its partial file.
pub type RecordedUpload = (String, String, String);

impl UserContext {
    /// The name of the encrypted file stored for the file at `file_path`.
    #[cfg(test)]
    pub async fn get_encoded_file_name(&self, file_path: PathBuf) -> Result<String, DbError> {
        self.with_db(move |db| {
            sqlite::get_encoded_file_name(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
    }

    /// Records an upload in progress for `session_id`, so its partial file can
    /// be found and removed if the upload is never finished.
    pub async fn add_active_upload(
        &self,
        upload_id: String,
        session_id: String,
        encoded_file_name: String,
        file_path: String,
    ) -> Result<(), DbError> {
        self.with_db(move |db| {
            sqlite::add_active_upload(&db, &upload_id, &session_id, &encoded_file_name, &file_path)
        })
        .await
    }

    /// Removes the record of an upload that has finished or been abandoned.
    pub async fn remove_active_upload(&self, upload_id: String) -> Result<(), DbError> {
        self.with_db(move |db| sqlite::remove_active_upload(&db, &upload_id))
            .await
    }

    /// Every upload recorded as in progress, in any of the user's sessions.
    pub async fn recorded_uploads(&self) -> Result<Vec<RecordedUpload>, DbError> {
        self.with_db(|db| sqlite::get_all_active_uploads(&db)).await
    }

    /// The encoded names of every blob the database refers to: those of stored
    /// files, and those of uploads still in progress (in any session).
    pub async fn referenced_blob_names(
        &self,
    ) -> Result<(HashSet<String>, HashSet<String>), DbError> {
        self.with_db(|db| {
            let files = sqlite::get_all_encoded_names(&db)?.into_iter().collect();
            let uploads = sqlite::get_all_active_uploads(&db)?
                .into_iter()
                .map(|(_, _, encoded_file_name)| encoded_file_name)
                .collect();

            Ok((files, uploads))
        })
        .await
    }

    /// Stores a file and returns the encoded name of the blob it replaced, if
    /// any. The caller owns deleting that blob.
    pub async fn add_file(
        &self,
        file_path: PathBuf,
        encoded_file_name: String,
        metadata: FileEncryptionMetadata,
    ) -> Result<Option<String>, DbError> {
        self.with_db(move |mut db| {
            sqlite::add_file(
                &mut db,
                file_path.to_str().ok_or(DbError::InvalidPath)?,
                &encoded_file_name,
                metadata,
            )
        })
        .await
    }

    /// Deletes a file and returns the encoded name of its blob, or `None` if
    /// there was no such file. The caller owns deleting that blob.
    pub async fn delete_file(&self, file_path: PathBuf) -> Result<Option<String>, DbError> {
        self.with_db(move |mut db| {
            sqlite::delete_file(&mut db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
    }

    /// Deletes a folder and everything under it, and returns the encoded names
    /// of the blobs that belonged to the deleted files. The caller owns
    /// deleting those blobs.
    pub async fn delete_folder_tree(&self, folder_path: PathBuf) -> Result<Vec<String>, DbError> {
        self.with_db(move |mut db| {
            sqlite::delete_folder_tree(&mut db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
    }

    /// Creates the folder at `folder_path`, and any missing parent folders.
    pub async fn add_folder(&self, folder_path: PathBuf) -> Result<(), DbError> {
        self.with_db(move |mut db| {
            sqlite::add_folder(&mut db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
    }

    /// Renames and/or moves a folder in one transaction.
    pub async fn update_folder(
        &self,
        folder_path: PathBuf,
        new_name: Option<String>,
        destination: Option<String>,
    ) -> Result<(), DbError> {
        self.with_db(move |mut db| {
            sqlite::update_folder(
                &mut db,
                folder_path.to_str().ok_or(DbError::InvalidPath)?,
                new_name.as_deref(),
                destination.as_deref(),
            )
        })
        .await
    }

    /// Renames and/or moves a file in one transaction.
    pub async fn update_file(
        &self,
        file_path: PathBuf,
        new_name: Option<String>,
        destination: Option<String>,
    ) -> Result<(), DbError> {
        self.with_db(move |mut db| {
            sqlite::update_file(
                &mut db,
                file_path.to_str().ok_or(DbError::InvalidPath)?,
                new_name.as_deref(),
                destination.as_deref(),
            )
        })
        .await
    }

    /// The id of the folder at `folder_path`, if it exists.
    #[cfg(test)]
    pub async fn get_folder_id(&self, folder_path: PathBuf) -> Result<Option<i32>, DbError> {
        self.with_db(move |db| {
            sqlite::get_folder_id(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
    }

    /// The files and folders directly inside the folder at `folder_path`.
    pub async fn get_folder(&self, folder_path: PathBuf) -> Result<Vec<FolderContent>, DbError> {
        self.with_db(move |db| {
            sqlite::get_folder(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
    }

    /// Starts streaming a folder of `username`'s, with everything below it, as
    /// a TAR archive. Returns once the archive's length is known; its bytes
    /// then arrive on the returned channel as fast as they are read. `hold`
    /// (the download's permits) is kept until the archive is finished, the
    /// reader goes away, or the reader takes nothing for `stall_timeout`.
    pub async fn stream_folder_archive<H: Send + 'static>(
        &self,
        folder_path: PathBuf,
        username: String,
        hold: H,
        stall_timeout: Duration,
    ) -> Result<FolderArchive, DbError> {
        let folder_path = folder_path.to_str().ok_or(DbError::InvalidPath)?.to_owned();
        let connection = self.reserve_connection().await?;
        let context = self.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (tx, rx) = mpsc::channel(MPSC_CHANNEL_CAPACITY);
        let out = ChannelWriter::new(tx, stall_timeout);

        // The producer occupies one of the user's blocking threads, and one
        // of their connections, for as long as the download runs.
        self.start_blocking(move || {
            let _held = (hold, connection);

            folder_archive::produce(&context, &folder_path, &username, ready_tx, out);
        })
        .await?;

        let (len, file_name) = ready_rx
            .await
            .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(FolderArchive { rx, len, file_name })
    }

    /// The name of the encrypted file stored for the file at `file_path`, with
    /// its key and size.
    pub async fn get_file_decryption_data(
        &self,
        file_path: PathBuf,
    ) -> Result<(String, FileEncryptionMetadata), DbError> {
        self.with_db(move |db| {
            sqlite::get_file_decryption_data(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
    }
}
