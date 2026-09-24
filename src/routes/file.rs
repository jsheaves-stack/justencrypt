use std::{collections::BTreeMap, env, time::Duration};

use rocket::{
    data::{ByteUnit, Data, Limits},
    delete, get,
    http::Status,
    options, patch, post, put,
    serde::json::Json,
    tokio::{self, fs, sync::mpsc},
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
        range::parse_range,
        sharded_path::{get_sharded_path, remove_sharded_path},
        unrestricted_path::UnrestrictedPath,
    },
    web::{
        forwarding_guards::{AuthenticatedSession, RangeHeader},
        responders::RangeResponder,
    },
};

#[derive(Serialize, Deserialize)]
pub struct InitUploadResponse {
    pub upload_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct FinalizeErrorResponse {
    pub missing_chunks: Vec<u64>,
}

const DEFAULT_MAX_FILE_SIZE: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_MAX_CHUNK_REQUEST_SIZE: u64 = 32 * 1024 * 1024;
const MAX_REPORTED_MISSING_CHUNKS: usize = 100;

/// Largest file, in plaintext bytes, that may be stored. Configured through
/// Rocket's `file` limit (`JUSTENCRYPT_LIMITS_FILE`).
fn max_file_size(limits: &Limits) -> u64 {
    limits
        .get("file")
        .map(|limit| limit.as_u64())
        .unwrap_or(DEFAULT_MAX_FILE_SIZE)
}

/// Most bytes a single chunk-upload request may carry. Configured through
/// Rocket's `file-chunk` limit (`JUSTENCRYPT_LIMITS_FILE_CHUNK`).
fn max_chunk_request_size(limits: &Limits) -> u64 {
    limits
        .get("file-chunk")
        .map(|limit| limit.as_u64())
        .unwrap_or(DEFAULT_MAX_CHUNK_REQUEST_SIZE)
}

/// Opens a request body so that reading more than `max_bytes` is detectable:
/// Rocket ends the stream silently at its limit, so the limit is one byte
/// higher and the encryptor reports the overflow.
fn open_with_limit(data: Data<'_>, max_bytes: u64) -> rocket::data::DataStream<'_> {
    data.open(ByteUnit::Byte(max_bytes.saturating_add(1)))
}

fn encryption_failure(e: EncryptionError) -> RequestError {
    match e {
        EncryptionError::TooLarge => RequestError::PayloadTooLarge,
        EncryptionError::InvalidOffset(msg) => RequestError::BadRequest(msg),
        e => {
            error!("Encryption error: {}", e);

            RequestError::FailedToProcessData
        },
    }
}

/// Checks that the chunks uploaded so far make up exactly `total_size`
/// plaintext bytes: every chunk from the first to the last is present, every
/// chunk but the last is full, and nothing lies past the end.
fn check_uploaded_chunks(chunks: &BTreeMap<u64, u32>, total_size: u64) -> Result<(), RequestError> {
    let chunk_size = CHUNK_SIZE as u64;
    let expected_chunks = total_size.div_ceil(chunk_size);
    let present = chunks.range(..expected_chunks).count() as u64;

    if present < expected_chunks {
        let missing_count = expected_chunks - present;
        let missing: Vec<u64> = (0..expected_chunks)
            .filter(|i| !chunks.contains_key(i))
            .take(MAX_REPORTED_MISSING_CHUNKS)
            .collect();
        let mut message = format!("Missing chunks: {:?}", missing);

        if missing_count > missing.len() as u64 {
            message.push_str(&format!(
                " (and {} more)",
                missing_count - missing.len() as u64
            ));
        }

        return Err(RequestError::BadRequest(message));
    }

    let size_mismatch =
        || RequestError::BadRequest("total_size does not match uploaded data".to_string());

    if chunks.len() as u64 != expected_chunks {
        return Err(size_mismatch());
    }

    for (&index, &len) in chunks {
        let is_last = index + 1 == expected_chunks;
        let expected_len = if is_last {
            total_size - index * chunk_size
        } else {
            chunk_size
        };

        if len as u64 != expected_len {
            if is_last {
                return Err(size_mismatch());
            }

            return Err(RequestError::BadRequest(format!(
                "Chunk {} is incomplete: expected {} bytes, got {}",
                index, expected_len, len
            )));
        }
    }

    Ok(())
}

const DEFAULT_UPLOAD_TTL_SECONDS: u64 = 24 * 60 * 60;

fn upload_ttl() -> Duration {
    let seconds = env::var("JUSTENCRYPT_UPLOAD_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_UPLOAD_TTL_SECONDS);

    Duration::from_secs(seconds)
}

#[post("/upload/initiate/<file_path..>")]
pub async fn init_upload(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<Json<InitUploadResponse>, RequestError> {
    trace!("Entering route [POST /file/upload/initiate/{}]", file_path);

    let session = auth.session.clone();

    session.sweep_stale_uploads(upload_ttl()).await;

    let max_uploads = env::var("JUSTENCRYPT_MAX_ACTIVE_UPLOADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

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
    trace!(
        "Entering route [PUT /file/upload/chunk/{}] at offset {}",
        upload_id,
        offset
    );

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

    let mut encryptor = upload_state.encryptor.lock().await;
    let mut written_chunks = upload_state.written_chunks.lock().await;

    let mut stream = open_with_limit(data, max_bytes);
    encryptor
        .encrypt_stream_at_offset(&mut stream, offset, max_bytes, &mut written_chunks)
        .await
        .map_err(encryption_failure)?;

    Ok(RequestSuccess::NoContent)
}

#[post("/upload/finalize/<upload_id>?<total_size>")]
pub async fn finalize_upload(
    upload_id: &str,
    total_size: u64,
    auth: AuthenticatedSession,
    limits: &Limits,
) -> Result<RequestSuccess, RequestError> {
    trace!(
        "Entering route [POST /file/upload/finalize/{}] with total_size {}",
        upload_id,
        total_size
    );

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

    // Same lock order as `upload_chunk`: encryptor, then chunks. Both are held
    // until the file is sealed so no chunk write can slip in after the check.
    let mut encryptor = upload_state.encryptor.lock().await;
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
    let old_encoded_name = session
        .get_encoded_file_name(upload_state.file_path.clone())
        .await
        .ok();

    let encoded_file_path =
        get_sharded_path(user_path.clone(), &upload_state.encoded_file_name).await;
    let encoded_file_path_part = encoded_file_path.with_extension("part");

    if let Err(e) = fs::rename(&encoded_file_path_part, &encoded_file_path).await {
        error!("Failed to rename part file to final file: {}", e);

        let _ = remove_sharded_path(&user_path, &encoded_file_path_part).await;

        return Err(RequestError::FailedToProcessData);
    }

    if let Err(e) = session
        .add_file(
            upload_state.file_path,
            upload_state.encoded_file_name,
            metadata,
        )
        .await
    {
        let _ = remove_sharded_path(&user_path, &encoded_file_path).await;

        return Err(e.into());
    }

    let _ = session.remove_active_upload_db(upload_id.to_string()).await;

    if let Some(old_name) = old_encoded_name {
        let old_file_path = get_sharded_path(user_path.clone(), &old_name).await;
        let old_thumb_path = get_sharded_path(user_path.join(".cache"), &old_name).await;

        let _ = remove_sharded_path(&user_path, &old_file_path).await;
        let _ = remove_sharded_path(&user_path, &old_thumb_path).await;
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
    trace!("Entering route [PUT /file/{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let user_path = {
        let session = auth.session.clone();
        session.get_user_path()
    };

    let old_encoded_name = {
        let session = auth.session.clone();
        session
            .get_encoded_file_name(file_path_buf.clone())
            .await
            .ok()
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

    if let Err(e) = encryptor.encrypt_stream(&mut stream, max_file_size).await {
        let _ = remove_sharded_path(&user_path, &encoded_file_path_part).await;
        let _ = auth
            .session
            .remove_active_upload_db(upload_id.clone())
            .await;

        return Err(encryption_failure(e));
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

    let metadata = encryptor.get_metadata();

    {
        let session = auth.session.clone();

        if let Err(e) = session
            .add_file(file_path_buf, encoded_file_name, metadata)
            .await
        {
            let _ = remove_sharded_path(&user_path, &encoded_file_path).await;
            let _ = session.remove_active_upload_db(upload_id.clone()).await;

            return Err(e.into());
        }
    }

    let _ = auth
        .session
        .remove_active_upload_db(upload_id.clone())
        .await;

    if let Some(old_name) = old_encoded_name {
        let old_file_path = get_sharded_path(user_path.clone(), &old_name).await;
        let old_thumb_path = get_sharded_path(user_path.join(".cache"), &old_name).await;

        let _ = remove_sharded_path(&user_path, &old_file_path).await;
        let _ = remove_sharded_path(&user_path, &old_thumb_path).await;
    }

    Ok(RequestSuccess::Created)
}

#[get("/<file_path..>")]
pub async fn get_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    range: RangeHeader,
) -> Result<RangeResponder, RequestError> {
    trace!("Entering route [GET /file/{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.clone();
    let user_path = session.get_user_path();

    let (encoded_file_name, metadata) = session.get_file_decryption_data(file_path_buf).await?;
    drop(session);

    let total_size = metadata.total_size;
    let (start, end, status) = if let Some(range_str) = range.0 {
        parse_range(&range_str, total_size)?
    } else {
        (0, total_size.saturating_sub(1), Status::Ok)
    };

    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;
    let mut decryptor = ChunkDecryptor::new(encoded_file_path, metadata)
        .await
        .map_err(|e| {
            error!("Failed to create ChunkDecryptor: {}", e);

            RequestError::FailedToProcessData
        })?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);

    tokio::spawn(async move {
        if let Err(e) = decryptor.decrypt_range(start, end, tx).await {
            error!("Decryption error during stream: {:?}", e);
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
    trace!("Entering route [DELETE /file/{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let (user_path, encoded_file_name) = {
        let session = auth.session.clone();
        let user_path = session.get_user_path();
        let encoded_file_name = session.get_encoded_file_name(file_path_buf.clone()).await?;
        (user_path, encoded_file_name)
    };

    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;
    let cache_path = user_path.join(".cache");
    let encoded_thumb_path = get_sharded_path(cache_path.clone(), &encoded_file_name).await;

    {
        let session = auth.session.clone();
        session.delete_file(file_path_buf).await?;
    }

    if encoded_thumb_path.exists() {
        if let Err(e) = remove_sharded_path(&user_path, &encoded_thumb_path).await {
            warn!("Failed to delete thumbnail file: {}", e);
        }
    }

    remove_sharded_path(&user_path, &encoded_file_path)
        .await
        .map_err(|e| {
            error!("Failed to delete physical file: {}", e);

            RequestError::FailedToRemoveFile
        })?;

    Ok(RequestSuccess::NoContent)
}

#[patch("/<file_path..>", data = "<patch_data>")]
pub async fn patch_file(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
    patch_data: Json<PatchFileData>,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PATCH /file/{}]", file_path);

    let mut current_path_buf = file_path.to_path_buf();

    if let Some(new_name) = &patch_data.file_name {
        let session = auth.session.clone();
        session
            .rename_file(current_path_buf.clone(), new_name.clone())
            .await?;

        current_path_buf.set_file_name(new_name);
    }

    if let Some(destination_folder) = &patch_data.parent_folder_path {
        let session = auth.session.clone();
        session
            .move_file(current_path_buf, destination_folder.clone())
            .await?;
    }

    Ok(RequestSuccess::NoContent)
}

#[derive(serde::Deserialize)]
pub struct PatchFileData {
    pub file_name: Option<String>,
    pub parent_folder_path: Option<String>,
}
