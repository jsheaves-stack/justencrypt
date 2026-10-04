use rocket::{
    data::{Data, Limits},
    delete, get,
    http::Status,
    options, patch, post, put,
    serde::json::Json,
    tokio::{self, fs, sync::mpsc},
    State,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor, CHUNK_SIZE,
        MPSC_CHANNEL_CAPACITY,
    },
    enums::{
        encryption_error::EncryptionError, request_error::RequestError,
        request_success::RequestSuccess,
    },
    session::user_session::UploadState,
    util::{
        chunked_upload::check_uploaded_chunks,
        names::{is_valid_entry_path, INVALID_ENTRY_NAME_MESSAGE},
        range::parse_range,
        sharded_path::{
            get_sharded_path, remove_blob_and_thumbnail, remove_sharded_path, sync_parent_dir,
        },
        unrestricted_path::UnrestrictedPath,
        upload_limits::{max_chunk_request_size, max_file_size, open_with_limit},
    },
    web::{
        forwarding_guards::{AuthenticatedSession, RangeHeader},
        responders::RangeResponder,
    },
    AppState,
};

#[derive(Serialize, Deserialize)]
pub struct InitUploadResponse {
    pub upload_id: String,
}

#[post("/upload/initiate/<file_path..>")]
pub async fn init_upload(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    state: &State<AppState>,
) -> Result<Json<InitUploadResponse>, RequestError> {
    // Checked again when the file is added, but a bad name should be reported
    // before the client uploads any chunks.

    if !is_valid_entry_path(&file_path.to_path_buf().to_string_lossy()) {
        return Err(RequestError::BadRequest(
            INVALID_ENTRY_NAME_MESSAGE.to_string(),
        ));
    }

    let session = auth.session.clone();

    session.sweep_stale_uploads(state.config.upload_ttl()).await;

    let max_uploads = state.config.max_active_uploads.map(|limit| limit.get());

    // Reject early so a client at the limit doesn't cost any I/O. The limit is
    // checked again under the same lock as the insert below, because the file
    // and DB work in between happens without holding it.

    if let Some(limit) = max_uploads {
        if session.active_uploads.lock().await.len() >= limit {
            return Err(RequestError::TooManyActiveUploads);
        }
    }

    let upload_id = Uuid::new_v4().to_string();
    let encoded_file_name = Uuid::new_v4().to_string();
    let encoded_file_path = get_sharded_path(session.get_user_path(), &encoded_file_name).await;
    let encoded_file_path_part = encoded_file_path.with_extension("part");

    if let Err(e) = session
        .add_active_upload_db(
            upload_id.clone(),
            encoded_file_name.clone(),
            file_path.to_path_buf().to_string_lossy().to_string(),
        )
        .await
    {
        error!("Failed to add active upload to db: {}", e);
    }

    let encryptor = match ChunkEncryptor::new(encoded_file_path_part).await {
        Ok(encryptor) => encryptor,
        Err(e) => {
            error!("Failed to create ChunkEncryptor: {}", e);

            session.abort_upload(&upload_id, &encoded_file_name).await;

            return Err(RequestError::FailedToProcessData);
        },
    };

    let upload_state = UploadState::new(
        file_path.to_path_buf(),
        encoded_file_name.clone(),
        encryptor,
    );

    let mut active_uploads = session.active_uploads.lock().await;

    if max_uploads.is_some_and(|limit| active_uploads.len() >= limit) {
        drop(active_uploads);

        session.abort_upload(&upload_id, &encoded_file_name).await;

        return Err(RequestError::TooManyActiveUploads);
    }

    active_uploads.insert(upload_id.clone(), upload_state);

    Ok(Json(InitUploadResponse { upload_id }))
}

#[put("/upload/chunk/<upload_id>?<offset>", data = "<data>")]
pub async fn upload_chunk(
    upload_id: &str,
    offset: u64,
    auth: AuthenticatedSession,
    limits: &Limits,
    data: Data<'_>,
) -> Result<RequestSuccess, RequestError> {
    if !offset.is_multiple_of(CHUNK_SIZE as u64) {
        return Err(RequestError::BadRequest(format!(
            "Offset must be a multiple of {}",
            CHUNK_SIZE
        )));
    }

    let max_file_size = max_file_size(limits);

    if offset > max_file_size {
        return Err(RequestError::PayloadTooLarge);
    }

    let max_bytes = max_chunk_request_size(limits).min(max_file_size - offset);

    let upload_state = auth
        .session
        .active_uploads
        .lock()
        .await
        .get(&upload_id.to_string())
        .cloned()
        .ok_or(RequestError::NotFound)?;

    upload_state.touch();

    let encryptor = upload_state.encryptor.read().await;
    let mut stream = open_with_limit(data, max_bytes);

    encryptor
        .encrypt_stream_at_offset(&mut stream, offset, max_bytes, &upload_state.written_chunks)
        .await?;

    Ok(RequestSuccess::NoContent)
}

#[post("/upload/finalize/<upload_id>?<total_size>")]
pub async fn finalize_upload(
    upload_id: &str,
    total_size: u64,
    auth: AuthenticatedSession,
    limits: &Limits,
) -> Result<RequestSuccess, RequestError> {
    if total_size > max_file_size(limits) {
        return Err(RequestError::PayloadTooLarge);
    }

    let session = auth.session.clone();
    let upload_state = session
        .active_uploads
        .lock()
        .await
        .remove(upload_id)
        .ok_or(RequestError::NotFound)?;

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

        return Err(RequestError::FailedToProcessData);
    }

    let metadata = encryptor.get_metadata();

    drop(encryptor);

    let user_path = session.get_user_path();
    let encoded_file_path =
        get_sharded_path(user_path.clone(), &upload_state.encoded_file_name).await;
    let encoded_file_path_part = encoded_file_path.with_extension("part");

    if let Err(e) = fs::rename(&encoded_file_path_part, &encoded_file_path).await {
        error!("Failed to rename part file to final file: {}", e);

        session
            .abort_upload(upload_id, &upload_state.encoded_file_name)
            .await;

        return Err(RequestError::FailedToProcessData);
    }

    if let Err(e) = sync_parent_dir(&encoded_file_path).await {
        error!("Failed to sync the renamed file's directory: {}", e);

        let _ = remove_sharded_path(&user_path, &encoded_file_path).await;
        let _ = session.remove_active_upload_db(upload_id.to_string()).await;

        return Err(RequestError::FailedToProcessData);
    }

    let replaced = match session
        .add_file(
            upload_state.file_path,
            upload_state.encoded_file_name,
            metadata,
        )
        .await
    {
        Ok(replaced) => replaced,
        Err(e) => {
            let _ = remove_sharded_path(&user_path, &encoded_file_path).await;
            let _ = session.remove_active_upload_db(upload_id.to_string()).await;

            return Err(e.into());
        },
    };

    let _ = session.remove_active_upload_db(upload_id.to_string()).await;

    if let Some(old_name) = replaced {
        remove_blob_and_thumbnail(&user_path, &old_name).await;
    }

    Ok(RequestSuccess::Created)
}

#[options("/<_file_path..>")]
pub fn file_options(_file_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[put("/<file_path..>", data = "<data>")]
pub async fn put_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    limits: &Limits,
    data: Data<'_>,
) -> Result<RequestSuccess, RequestError> {
    let file_path_buf = file_path.to_path_buf();
    let user_path = {
        let session = auth.session.clone();
        session.get_user_path()
    };

    let encoded_file_name = Uuid::new_v4().to_string();
    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;
    let encoded_file_path_part = encoded_file_path.with_extension("part");

    let upload_id = Uuid::new_v4().to_string();

    if let Err(e) = auth
        .session
        .add_active_upload_db(
            upload_id.clone(),
            encoded_file_name.clone(),
            file_path_buf.to_string_lossy().to_string(),
        )
        .await
    {
        error!("Failed to add active upload to db for put_file: {}", e);
    }

    let encryptor = ChunkEncryptor::new(encoded_file_path_part.clone())
        .await
        .map_err(|e| e.to_string());

    let mut encryptor = match encryptor {
        Ok(enc) => enc,
        Err(e) => {
            error!("Failed to create ChunkEncryptor: {}", e);

            let _ = auth
                .session
                .remove_active_upload_db(upload_id.clone())
                .await;

            return Err(RequestError::FailedToProcessData);
        },
    };

    let max_file_size = max_file_size(limits);
    let mut stream = open_with_limit(data, max_file_size);

    // The data must be on disk before the file is renamed into place and
    // recorded, so a crash can't leave a record of a file that isn't there.

    let written = match encryptor.encrypt_stream(&mut stream, max_file_size).await {
        Ok(_) => encryptor.sync().await,
        Err(e) => Err(e),
    };

    if let Err(e) = written {
        let _ = remove_sharded_path(&user_path, &encoded_file_path_part).await;
        let _ = auth
            .session
            .remove_active_upload_db(upload_id.clone())
            .await;

        return Err(e.into());
    }

    if let Err(e) = fs::rename(&encoded_file_path_part, &encoded_file_path).await {
        error!("Failed to rename part file to final file: {}", e);

        let _ = remove_sharded_path(&user_path, &encoded_file_path_part).await;
        let _ = auth
            .session
            .remove_active_upload_db(upload_id.clone())
            .await;

        return Err(RequestError::FailedToProcessData);
    }

    if let Err(e) = sync_parent_dir(&encoded_file_path).await {
        error!("Failed to sync the renamed file's directory: {}", e);

        let _ = remove_sharded_path(&user_path, &encoded_file_path).await;
        let _ = auth
            .session
            .remove_active_upload_db(upload_id.clone())
            .await;

        return Err(RequestError::FailedToProcessData);
    }

    let metadata = encryptor.get_metadata();

    let replaced = match auth
        .session
        .add_file(file_path_buf, encoded_file_name, metadata)
        .await
    {
        Ok(replaced) => replaced,
        Err(e) => {
            let _ = remove_sharded_path(&user_path, &encoded_file_path).await;
            let _ = auth
                .session
                .remove_active_upload_db(upload_id.clone())
                .await;

            return Err(e.into());
        },
    };

    let _ = auth
        .session
        .remove_active_upload_db(upload_id.clone())
        .await;

    if let Some(old_name) = replaced {
        remove_blob_and_thumbnail(&user_path, &old_name).await;
    }

    Ok(RequestSuccess::Created)
}

#[get("/<file_path..>")]
pub async fn get_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    range: RangeHeader,
    state: &State<AppState>,
) -> Result<RangeResponder, RequestError> {
    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.clone();
    let user_path = session.get_user_path();

    let (encoded_file_name, metadata) = session.get_file_decryption_data(file_path_buf).await?;
    drop(session);

    let total_size = metadata.total_size;

    let requested_range = match range.0 {
        Some(range_str) => parse_range(&range_str, total_size)?,
        None => None,
    };

    let (start, end, status) = match requested_range {
        Some((start, end)) => (start, end, Status::PartialContent),
        None => (0, total_size.saturating_sub(1), Status::Ok),
    };

    // Nothing to decrypt. Dropping the sender ends the body immediately.

    if total_size == 0 {
        let (_, rx) = mpsc::channel::<Vec<u8>>(1);

        return Ok(RangeResponder {
            rx,
            status,
            start,
            end,
            total_size,
        });
    }

    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;
    let mut decryptor = ChunkDecryptor::new(encoded_file_path, metadata)
        .await
        .map_err(|e| {
            error!("Failed to create ChunkDecryptor: {}", e);

            RequestError::FailedToProcessData
        })?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);
    let stall_timeout = state.config.download_stall_timeout();

    tokio::spawn(async move {
        match decryptor.decrypt_range(start, end, tx, stall_timeout).await {
            Ok(()) => {},
            Err(e @ EncryptionError::Stalled(_)) => warn!("Abandoned a file download: {}", e),
            Err(e) => error!("Decryption error during stream: {:?}", e),
        }
    });

    Ok(RangeResponder {
        rx,
        status,
        start,
        end,
        total_size,
    })
}

#[delete("/<file_path..>")]
pub async fn delete_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    let session = auth.session.clone();
    let user_path = session.get_user_path();

    // The blob to remove comes from the deleted row itself, not from an
    // earlier lookup, so a concurrent overwrite can't make us delete the wrong
    // one.

    match session.delete_file(file_path.to_path_buf()).await? {
        Some(encoded_file_name) => {
            remove_blob_and_thumbnail(&user_path, &encoded_file_name).await;

            Ok(RequestSuccess::NoContent)
        },
        None => Err(RequestError::NotFound),
    }
}

#[patch("/<file_path..>", data = "<patch_data>")]
pub async fn patch_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    patch_data: Json<PatchFileData>,
) -> Result<RequestSuccess, RequestError> {
    let PatchFileData {
        file_name,
        parent_folder_path,
    } = patch_data.into_inner();

    if file_name.is_none() && parent_folder_path.is_none() {
        return Err(RequestError::BadRequest("Nothing to change".into()));
    }

    auth.session
        .update_file(file_path.to_path_buf(), file_name, parent_folder_path)
        .await?;

    Ok(RequestSuccess::NoContent)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFileData {
    pub file_name: Option<String>,
    pub parent_folder_path: Option<String>,
}
