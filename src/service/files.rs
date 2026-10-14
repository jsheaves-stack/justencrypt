//! A user's files: storing one in a single upload, downloading all or part of
//! one, renaming and moving, and deleting.

use std::path::PathBuf;

use tokio::{io::AsyncRead, sync::mpsc};
use uuid::Uuid;

use crate::{
    app::App,
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor, MPSC_CHANNEL_CAPACITY,
    },
    enums::{encryption_error::EncryptionError, service_error::ServiceError},
    service::{
        folders::EntryChanges,
        limits::{max_file_size, read_with_limit},
        uploads::commit_file,
    },
    session::user_session::UserSession,
};

/// A byte range of a file, as a client asks for it, before it is checked
/// against the file's size. Positions are inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteRangeSpec {
    /// From the first position to the second.
    FromTo(u64, u64),
    /// From a position to the end of the file.
    From(u64),
    /// The last so many bytes.
    Suffix(u64),
}

impl ByteRangeSpec {
    /// The inclusive range to send of a `total_size`-byte file. A range that
    /// starts at or past the end of the file, or asks for no bytes, is not
    /// satisfiable.
    pub fn resolve(self, total_size: u64) -> Result<(u64, u64), ServiceError> {
        let not_satisfiable = || ServiceError::RangeNotSatisfiable { total_size };

        let (start, end) = match self {
            ByteRangeSpec::Suffix(suffix_length) => {
                if suffix_length == 0 || total_size == 0 {
                    return Err(not_satisfiable());
                }

                return Ok((total_size.saturating_sub(suffix_length), total_size - 1));
            },
            ByteRangeSpec::From(start) => (start, total_size.saturating_sub(1)),
            ByteRangeSpec::FromTo(start, end) => (start, end),
        };

        if start > end || start >= total_size {
            return Err(not_satisfiable());
        }

        Ok((start, end.min(total_size - 1)))
    }
}

/// A file download: the decrypted bytes `start..=end` of a `total_size`-byte
/// file, arriving on `chunks` as fast as they are read. `partial` is whether a
/// range was asked for, rather than the whole file.
pub struct FileDownload {
    pub chunks: mpsc::Receiver<Vec<u8>>,
    pub start: u64,
    pub end: u64,
    pub total_size: u64,
    pub partial: bool,
}

/// Encrypts `body` as it is read and stores it at `file_path`, replacing any
/// file already there.
pub async fn store<R: AsyncRead + Unpin>(
    app: &App,
    session: &UserSession,
    file_path: PathBuf,
    body: R,
) -> Result<(), ServiceError> {
    let context = &session.context;
    let encoded_file_name = Uuid::new_v4().to_string();

    let upload_id = Uuid::new_v4().to_string();

    if let Err(e) = context
        .add_active_upload(
            upload_id.clone(),
            session.session_id.clone(),
            encoded_file_name.clone(),
            file_path.to_string_lossy().to_string(),
        )
        .await
    {
        error!("Failed to add active upload to db for put_file: {}", e);
    }

    let mut encryptor = match context.create_upload(&encoded_file_name).await {
        Ok(file) => ChunkEncryptor::new(file),
        Err(e) => {
            error!("Failed to create the upload's file: {}", e);

            session.abort_upload(&upload_id, &encoded_file_name).await;

            return Err(e.into());
        },
    };

    let max_file_size = max_file_size(&app.config.limits);
    let mut stream = read_with_limit(body, max_file_size);

    // The data must be on disk before the file is renamed into place and
    // recorded, so a crash can't leave a record of a file that isn't there.

    let written = match encryptor.encrypt_stream(&mut stream, max_file_size).await {
        Ok(_) => encryptor.sync().await,
        Err(e) => Err(e),
    };

    if let Err(e) = written {
        session.abort_upload(&upload_id, &encoded_file_name).await;

        return Err(e.into());
    }

    let metadata = encryptor.get_metadata();

    commit_file(session, &upload_id, encoded_file_name, file_path, metadata).await
}

/// Starts streaming the file at `file_path`, decrypting it as it is read: all
/// of it, or just `range`. Fails with `NotFound` if there is no such file.
pub async fn download(
    app: &App,
    session: &UserSession,
    file_path: PathBuf,
    range: Option<ByteRangeSpec>,
) -> Result<FileDownload, ServiceError> {
    let (encoded_file_name, metadata) = session.context.get_file_decryption_data(file_path).await?;
    let total_size = metadata.total_size;

    let (start, end, partial) = match range {
        Some(range) => {
            let (start, end) = range.resolve(total_size)?;

            (start, end, true)
        },
        None => (0, total_size.saturating_sub(1), false),
    };

    // Nothing to decrypt. Dropping the sender ends the stream immediately.

    if total_size == 0 {
        let (_, chunks) = mpsc::channel::<Vec<u8>>(1);

        return Ok(FileDownload {
            chunks,
            start,
            end,
            total_size,
            partial,
        });
    }

    let blob = session
        .context
        .open_blob(&encoded_file_name)
        .await
        .map_err(|e| {
            error!("Failed to open encrypted file {}: {}", encoded_file_name, e);

            ServiceError::from(e)
        })?;
    let mut decryptor = ChunkDecryptor::new(blob, metadata).map_err(|e| {
        error!("Failed to create ChunkDecryptor: {}", e);

        ServiceError::FailedToProcessData
    })?;

    let (tx, chunks) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);
    let stall_timeout = app.config.download_stall_timeout();

    tokio::spawn(async move {
        match decryptor.decrypt_range(start, end, tx, stall_timeout).await {
            Ok(()) => {},
            Err(e @ EncryptionError::Stalled(_)) => warn!("Abandoned a file download: {}", e),
            Err(e) => error!("Decryption error during stream: {:?}", e),
        }
    });

    Ok(FileDownload {
        chunks,
        start,
        end,
        total_size,
        partial,
    })
}

/// Deletes the file at `file_path`.
pub async fn delete(session: &UserSession, file_path: PathBuf) -> Result<(), ServiceError> {
    // The blob to remove comes from the deleted row itself, not from an
    // earlier lookup, so a concurrent overwrite can't make us delete the wrong
    // one.

    match session.context.delete_file(file_path).await? {
        Some(encoded_file_name) => {
            session
                .context
                .remove_blob_and_thumbnail(&encoded_file_name)
                .await;

            Ok(())
        },
        None => Err(ServiceError::NotFound),
    }
}

/// Renames the file at `file_path`, moves it to another folder, or both.
pub async fn update(
    session: &UserSession,
    file_path: PathBuf,
    changes: EntryChanges,
) -> Result<(), ServiceError> {
    changes.check_not_empty()?;

    Ok(session
        .context
        .update_file(file_path, changes.new_name, changes.new_parent)
        .await?)
}
