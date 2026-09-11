use std::{
    collections::HashSet,
    env,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use rocket::{
    data::{ByteUnit, Data, ToByteUnit},
    delete, get,
    http::Status,
    options, patch, post, put,
    serde::json::Json,
    tokio::{
        self, fs,
        sync::{mpsc, Mutex},
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor, CHUNK_SIZE,
        MPSC_CHANNEL_CAPACITY,
    },
    enums::{request_error::RequestError, request_success::RequestSuccess},
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
#[post("/upload/initiate/<file_path..>")]
pub async fn init_upload(
    file_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<Json<InitUploadResponse>, RequestError> {
    trace!("Entering route [POST /file/upload/initiate/{}]", file_path);

    let session = auth.session.clone();
    let user_path = session.get_user_path();

    let now = SystemTime::now();
    let stale_threshold = Duration::from_secs(24 * 60 * 60); // 24 hours
    let mut stale_ids = Vec::new();

    let mut active_uploads = session.active_uploads.lock().await;

    let max_uploads = env::var("JUSTENCRYPT_MAX_ACTIVE_UPLOADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

    if let Some(limit) = max_uploads {
        if active_uploads.len() >= limit {
            return Err(RequestError::TooManyActiveUploads);
        }
    }

    for (id, state) in active_uploads.iter() {
        if let Ok(last_updated) = state
            .last_updated
            .lock()
            .await
            .duration_since(SystemTime::UNIX_EPOCH)
        {
            if let Ok(current_time) = now.duration_since(SystemTime::UNIX_EPOCH) {
                if current_time.saturating_sub(last_updated) > stale_threshold {
                    stale_ids.push(id.clone());
                }
            }
        }
    }

    for id in stale_ids {
        if let Some(state) = session.active_uploads.lock().await.remove(&id) {
            let encoded_file_path =
                get_sharded_path(user_path.clone(), &state.encoded_file_name).await;

            fs::remove_file(encoded_file_path.clone())
                .await
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to remove stale upload file {}: {}",
                        encoded_file_path.display(),
                        e
                    )
                });
        }
    }

    let upload_id = Uuid::new_v4().to_string();
    let encoded_file_name = Uuid::new_v4().to_string();
    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;
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

    let encryptor = ChunkEncryptor::new(encoded_file_path_part)
        .await
        .map_err(|e| {
            error!("Failed to create ChunkEncryptor: {}", e);

            RequestError::FailedToProcessData
        })?;

    let upload_state = UploadState {
        file_path: file_path.to_path_buf(),
        encoded_file_name,
        written_chunks: Arc::new(Mutex::new(HashSet::new())),
        encryptor: Arc::new(Mutex::new(encryptor)),
        last_updated: Arc::new(Mutex::new(SystemTime::now())),
    };

    active_uploads.insert(upload_id.clone(), upload_state);

    Ok(Json(InitUploadResponse { upload_id }))
}

#[put("/upload/chunk/<upload_id>?<offset>", data = "<data>")]
pub async fn upload_chunk(
    upload_id: &str,
    offset: u64,
    auth: AuthenticatedSession,
    data: Data<'_>,
) -> Result<RequestSuccess, RequestError> {
    trace!(
        "Entering route [PUT /file/upload/chunk/{}] at offset {}",
        upload_id,
        offset
    );

    let max_file_size_str = env::var("JUSTENCRYPT_LIMITS_FILE").unwrap_or_else(|_| "64GiB".into());
    let max_file_size = FromStr::from_str(&max_file_size_str)
        .unwrap_or(ByteUnit::Gibibyte(64))
        .as_u64();

    if offset > max_file_size {
        return Err(RequestError::BadRequest(
            "Offset exceeds max file size limit".into(),
        ));
    }

    let upload_state = auth
        .session
        .active_uploads
        .lock()
        .await
        .get(&upload_id.to_string())
        .cloned()
        .ok_or(RequestError::NotFound)?;

    {
        let mut last_updated = upload_state.last_updated.lock().await;
        *last_updated = SystemTime::now();
    }

    let mut encryptor = upload_state.encryptor.lock().await;
    let mut written_chunks = upload_state.written_chunks.lock().await;

    let mut stream = data.open(5.gibibytes());
    encryptor
        .encrypt_stream_at_offset(&mut stream, offset, &mut written_chunks)
        .await
        .map_err(|e| {
            error!("Encryption error: {}", e);

            RequestError::FailedToProcessData
        })?;

    Ok(RequestSuccess::NoContent)
}

#[post("/upload/finalize/<upload_id>?<total_size>")]
pub async fn finalize_upload(
    upload_id: &str,
    total_size: u64,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!(
        "Entering route [POST /file/upload/finalize/{}] with total_size {}",
        upload_id,
        total_size
    );

    let session = auth.session.clone();
    let upload_state = session
        .active_uploads
        .lock()
        .await
        .remove(upload_id)
        .ok_or(RequestError::NotFound)?;

    let written_chunks = upload_state.written_chunks.lock().await;
    let expected_chunks = total_size.div_ceil(CHUNK_SIZE as u64);

    let mut missing_chunks = Vec::new();
    for i in 0..expected_chunks {
        if !written_chunks.contains(&i) {
            missing_chunks.push(i);
        }
    }

    if !missing_chunks.is_empty() {
        drop(written_chunks);

        // Re-insert the upload state so the client can retry
        session
            .active_uploads
            .lock()
            .await
            .insert(upload_id.to_string(), upload_state);

        return Err(RequestError::BadRequest(format!(
            "Missing chunks: {:?}",
            missing_chunks
        )));
    }

    drop(written_chunks);

    let mut encryptor = upload_state.encryptor.lock().await;

    encryptor.finalize_metadata(total_size);

    let metadata = encryptor.get_metadata();

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

    let mut stream = data.open(5.gibibytes());

    let encrypt_result = encryptor
        .encrypt_stream(&mut stream)
        .await
        .map_err(|e| e.to_string());

    if let Err(e) = encrypt_result {
        error!("Encryption error: {}", e);

        let _ = remove_sharded_path(&user_path, &encoded_file_path_part).await;
        let _ = auth
            .session
            .remove_active_upload_db(upload_id.clone())
            .await;

        return Err(RequestError::FailedToProcessData);
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
