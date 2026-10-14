//! Chunked uploads: a file sent as chunks, in any order and in parallel,
//! then stored once every chunk has arrived.

use std::path::PathBuf;

use tokio::io::AsyncRead;
use uuid::Uuid;

use crate::{
    app::App,
    encryption::{chunk_encryptor::ChunkEncryptor, FileEncryptionMetadata, CHUNK_SIZE},
    enums::service_error::ServiceError,
    service::{
        chunks::check_uploaded_chunks,
        limits::{max_chunk_request_size, max_file_size, read_with_limit},
    },
    session::user_session::{UploadState, UserSession},
    util::names::{is_valid_entry_path, INVALID_ENTRY_NAME_MESSAGE},
};

/// Starts a chunked upload to `file_path` and returns its id.
pub async fn initiate(
    app: &App,
    session: &UserSession,
    file_path: PathBuf,
) -> Result<String, ServiceError> {
    // Checked again when the file is added, but a bad name should be reported
    // before the client uploads any chunks.

    if !is_valid_entry_path(&file_path.to_string_lossy()) {
        return Err(ServiceError::InvalidInput(
            INVALID_ENTRY_NAME_MESSAGE.to_string(),
        ));
    }

    session.sweep_stale_uploads(app.config.upload_ttl()).await;

    let max_uploads = app.config.max_active_uploads.map(|limit| limit.get());

    // Reject early so a client at the limit doesn't cost any I/O. The limit is
    // checked again under the same lock as the insert below, because the file
    // and DB work in between happens without holding it.

    if let Some(limit) = max_uploads {
        if session.active_uploads.lock().await.len() >= limit {
            return Err(ServiceError::TooManyActiveUploads);
        }
    }

    let upload_id = Uuid::new_v4().to_string();
    let encoded_file_name = Uuid::new_v4().to_string();

    if let Err(e) = session
        .context
        .add_active_upload(
            upload_id.clone(),
            session.session_id.clone(),
            encoded_file_name.clone(),
            file_path.to_string_lossy().to_string(),
        )
        .await
    {
        error!("Failed to add active upload to db: {}", e);
    }

    let encryptor = match session.context.create_upload(&encoded_file_name).await {
        Ok(file) => ChunkEncryptor::new(file),
        Err(e) => {
            error!("Failed to create the upload's file: {}", e);

            session.abort_upload(&upload_id, &encoded_file_name).await;

            return Err(e.into());
        },
    };

    let upload_state = UploadState::new(file_path, encoded_file_name.clone(), encryptor);

    let mut active_uploads = session.active_uploads.lock().await;

    if max_uploads.is_some_and(|limit| active_uploads.len() >= limit) {
        drop(active_uploads);

        session.abort_upload(&upload_id, &encoded_file_name).await;

        return Err(ServiceError::TooManyActiveUploads);
    }

    active_uploads.insert(upload_id.clone(), upload_state);

    Ok(upload_id)
}

/// Encrypts and stores one chunk of an upload, read from `body`. `offset` is
/// where the chunk starts in the file, and must be a multiple of the chunk
/// size.
pub async fn write_chunk<R: AsyncRead + Unpin>(
    app: &App,
    session: &UserSession,
    upload_id: &str,
    offset: u64,
    body: R,
) -> Result<(), ServiceError> {
    if !offset.is_multiple_of(CHUNK_SIZE as u64) {
        return Err(ServiceError::InvalidInput(format!(
            "Offset must be a multiple of {}",
            CHUNK_SIZE
        )));
    }

    let max_file_size = max_file_size(&app.config.limits);

    if offset > max_file_size {
        return Err(ServiceError::TooLarge);
    }

    let max_bytes = max_chunk_request_size(&app.config.limits).min(max_file_size - offset);

    let upload_state = session
        .active_uploads
        .lock()
        .await
        .get(upload_id)
        .cloned()
        .ok_or(ServiceError::NotFound)?;

    upload_state.touch();

    let encryptor = upload_state.encryptor.read().await;
    let mut stream = read_with_limit(body, max_bytes);

    encryptor
        .encrypt_stream_at_offset(&mut stream, offset, max_bytes, &upload_state.written_chunks)
        .await?;

    Ok(())
}

/// Completes a chunked upload once every chunk of its `total_size` bytes has
/// arrived, and stores the file, replacing any file already at its path. A
/// missing chunk is reported and the upload kept, so the client can send it
/// and try again.
pub async fn finalize(
    app: &App,
    session: &UserSession,
    upload_id: &str,
    total_size: u64,
) -> Result<(), ServiceError> {
    if total_size > max_file_size(&app.config.limits) {
        return Err(ServiceError::TooLarge);
    }

    let upload_state = session
        .active_uploads
        .lock()
        .await
        .remove(upload_id)
        .ok_or(ServiceError::NotFound)?;

    // Exclusive access waits for chunk writes still in progress. It is held,
    // with the chunk record, until the file is sealed, so no chunk write can
    // slip in after the check.
    let mut encryptor = upload_state.encryptor.write().await;
    let written_chunks = upload_state.written_chunks.lock().await;

    if let Err(e) = check_uploaded_chunks(&written_chunks, total_size) {
        drop(written_chunks);
        drop(encryptor);

        // Re-insert the upload state so the client can retry
        session
            .active_uploads
            .lock()
            .await
            .insert(upload_id.to_string(), upload_state);

        return Err(e);
    }

    let sealed = encryptor.seal(total_size).await;

    drop(written_chunks);

    if let Err(e) = sealed {
        error!("Failed to seal uploaded file: {}", e);

        drop(encryptor);
        session
            .abort_upload(upload_id, &upload_state.encoded_file_name)
            .await;

        return Err(e.into());
    }

    let metadata = encryptor.get_metadata();

    drop(encryptor);

    commit_file(
        session,
        upload_id,
        upload_state.encoded_file_name,
        upload_state.file_path,
        metadata,
    )
    .await
}

/// Moves the fully written file of upload `upload_id` into place and records
/// it at `file_path`, replacing any file already there. If a step fails, the
/// upload is cleaned up and nothing is recorded.
pub(super) async fn commit_file(
    session: &UserSession,
    upload_id: &str,
    encoded_file_name: String,
    file_path: PathBuf,
    metadata: FileEncryptionMetadata,
) -> Result<(), ServiceError> {
    let context = &session.context;

    if let Err(e) = context.commit_upload(&encoded_file_name).await {
        error!("Failed to rename part file to final file: {}", e);

        session.abort_upload(upload_id, &encoded_file_name).await;

        return Err(e.into());
    }

    if let Err(e) = context.sync_blob_dir(&encoded_file_name).await {
        error!("Failed to sync the renamed file's directory: {}", e);

        let _ = context.remove_blob(&encoded_file_name).await;
        let _ = context.remove_active_upload(upload_id.to_string()).await;

        return Err(e.into());
    }

    let replaced = match context
        .add_file(file_path, encoded_file_name.clone(), metadata)
        .await
    {
        Ok(replaced) => replaced,
        Err(e) => {
            let _ = context.remove_blob(&encoded_file_name).await;
            let _ = context.remove_active_upload(upload_id.to_string()).await;

            return Err(e.into());
        },
    };

    let _ = context.remove_active_upload(upload_id.to_string()).await;

    if let Some(old_name) = replaced {
        context.remove_blob_and_thumbnail(&old_name).await;
    }

    Ok(())
}
