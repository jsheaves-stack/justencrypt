use crate::{
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor, MPSC_CHANNEL_CAPACITY,
    },
    enums::{request_error::RequestError, request_success::RequestSuccess},
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
use rocket::{
    data::{Data, ToByteUnit},
    delete, get,
    http::Status,
    options, patch, put,
    serde::json::Json,
    tokio::{self, sync::mpsc},
};

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
    let session = auth.session.read().await;
    let user_path = session.get_user_path();

    let encoded_file_name = uuid::Uuid::new_v4().to_string();
    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;

    let mut encryptor = ChunkEncryptor::new(encoded_file_path).await.map_err(|e| {
        error!("Failed to create ChunkEncryptor: {}", e);
        RequestError::FailedToProcessData
    })?;

    let mut stream = data.open(5.gibibytes());
    encryptor.encrypt_stream(&mut stream).await.map_err(|e| {
        error!("Encryption error: {}", e);
        RequestError::FailedToProcessData
    })?;

    let metadata = encryptor.get_metadata();
    session
        .add_file(file_path_buf, encoded_file_name, metadata)
        .await?;

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
    let session = auth.session.read().await;
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
        decryptor.decrypt_range(start, end, tx).await;
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
    let session = auth.session.read().await;
    let user_path = session.get_user_path();

    let encoded_file_name = session.get_encoded_file_name(file_path_buf.clone()).await?;
    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;

    session.delete_file(file_path_buf).await?;
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

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;

    if let Some(new_name) = &patch_data.file_name {
        session
            .rename_file(file_path_buf.clone(), new_name.clone())
            .await?;
    }

    if let Some(destination_folder) = &patch_data.parent_folder_path {
        session
            .move_file(file_path_buf, destination_folder.clone())
            .await?;
    }

    Ok(RequestSuccess::NoContent)
}

#[derive(serde::Deserialize)]
pub struct PatchFileData {
    pub file_name: Option<String>,
    pub parent_folder_path: Option<String>,
}
