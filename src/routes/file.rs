use crate::{
    encryption::{
        stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor,
        MPSC_CHANNEL_CAPACITY, NONCE_SIZE, SALT_SIZE, STREAM_LIMIT,
    },
    enums::{db_error::DbError, request_error::RequestError, request_success::RequestSuccess},
    util::{
        sharded_path::{get_sharded_path, remove_sharded_path},
        unrestricted_path::UnrestrictedPath,
    },
    web::forwarding_guards::AuthenticatedSession,
};
use rocket::{
    data::ByteUnit,
    delete, get, options, patch, put,
    response::stream::ByteStream,
    serde::{json::Json, Deserialize},
    tokio::{self, fs::File, io::BufReader, sync::mpsc},
    Data,
};
use uuid::Uuid;

#[options("/<file_path..>")]
pub fn file_options(file_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /file{}]", file_path);
    Ok(RequestSuccess::NoContent)
}

#[put("/<file_path..>", data = "<reqdata>")]
pub async fn put_file(
    file_path: UnrestrictedPath, // The path where the file should be stored, extracted from the URL.
    reqdata: Data<'_>,           // The raw data of the file being uploaded.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PUT /file{}]", file_path);

    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();
    let encoded_file_name = Uuid::new_v4().to_string();
    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;

    trace!(
        "Generated encoded_file_name: {} for path: {:?}",
        encoded_file_name,
        encoded_file_path
    );

    let mut encryptor = match StreamEncryptor::new(encoded_file_path).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create StreamEncryptor: {}", e);
            return Err(RequestError::FailedToAddFile);
        }
    };

    trace!("StreamEncryptor created.");

    let metadata = encryptor.get_file_encryption_metadata();
    let file_path_buf = file_path.to_path_buf();

    match session
        .add_file(file_path_buf, encoded_file_name, metadata)
        .await
    {
        Ok(_) => {
            trace!("File metadata added to DB successfully.");
            drop(session)
        }
        Err(e) => {
            error!("Failed to add file to db: {}", e);
            return Err(RequestError::FailedToAddFile);
        }
    };

    let mut data_stream = reqdata.open(ByteUnit::from(STREAM_LIMIT));

    match encryptor
        .encrypt_source_to_encryptor(&mut data_stream)
        .await
    {
        Ok(_) => {
            trace!("Exiting route [PUT /file{}] successfully.", file_path);
            Ok(RequestSuccess::Created)
        }
        Err(e) => {
            error!("encrypt_source_to_encryptor failed: {}", e);
            Err(RequestError::FailedToAddFile)
        }
    }
}

#[derive(Deserialize)]
pub struct PatchFileRequest {
    parent_folder_path: Option<String>,
    file_name: Option<String>,
}

#[patch("/<file_path..>", data = "<patch_file_request>")]
pub async fn patch_file(
    file_path: UnrestrictedPath,
    patch_file_request: Json<PatchFileRequest>,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PATCH /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let updates = patch_file_request.into_inner();

    if let Some(parent_folder_path) = updates.parent_folder_path {
        trace!(
            "Attempting to move file to new parent folder: {}",
            parent_folder_path
        );
        match session
            .move_file(file_path_buf.clone(), parent_folder_path)
            .await
        {
            Ok(_) => trace!("File moved successfully."),
            Err(e) => {
                error!("Failed to move file: {}", e);
                return Err(RequestError::FailedToMoveFile);
            }
        }
    };

    if let Some(new_file_name) = updates.file_name {
        trace!("Attempting to rename file to: {}", new_file_name);
        match session.rename_file(file_path_buf, new_file_name).await {
            Ok(_) => trace!("File renamed successfully."),
            Err(e) => {
                error!("Failed to rename file: {}", e);
                return Err(RequestError::FailedToRenameFile);
            }
        }
    };

    drop(session);

    trace!("Exiting route [PATCH /file{}] successfully.", file_path);

    Ok(RequestSuccess::NoContent)
}

#[get("/<file_path..>")]
pub async fn get_file(
    file_path: UnrestrictedPath, // The name/path of the file being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<ByteStream![Vec<u8>], RequestError> {
    trace!("Entering route [GET /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();

    let encoded_file_name = match session.get_encoded_file_name(file_path.to_path_buf()).await {
        Ok(e) => e,
        Err(DbError::NotFound) => return Err(RequestError::NotFound),
        Err(e) => {
            error!("Failed to get encoded file name from db: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    trace!("Retrieved encoded_file_name: {}", encoded_file_name);

    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;

    trace!("Constructed encoded_file_path: {:?}", encoded_file_path);

    let metadata = match session.get_file_encryption_metadata(file_path_buf).await {
        Ok(m) => {
            trace!("Successfully retrieved file encryption metadata.");
            drop(session);
            m
        }
        Err(DbError::NotFound) => return Err(RequestError::NotFound),
        Err(e) => {
            error!("Failed to get file encryption metadata for file: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    // Initialize the stream decryptor for the requested file.
    let mut decryptor = match StreamDecryptor::new(encoded_file_path, metadata).await {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to create StreamDecryptor: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    trace!("StreamDecryptor created.");

    // Open the encrypted file.
    let input_file = match File::open(decryptor.get_file_path()).await {
        Ok(i) => i,
        Err(e) => {
            error!("Failed to open file: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    trace!("Encrypted file opened for reading.");

    let mut reader = BufReader::new(input_file);
    let offset = (SALT_SIZE + NONCE_SIZE) as u64;

    // Create an unbounded channel for streaming decrypted file chunks.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);

    trace!("MPSC channel created for file download.");

    // Spawn an async task to read, decrypt, and send file chunks.
    tokio::spawn(async move {
        decryptor
            .decrypt_stream_to_channel(&mut reader, tx, offset)
            .await
    });

    // Stream the decrypted file chunks as they become available.
    trace!("Returning ByteStream to client.");

    Ok(ByteStream! {
        while let Some(chunk) = rx.recv().await {
            yield chunk;
        }
    })
}

#[delete("/<file_path..>")]
pub async fn delete_file(
    file_path: UnrestrictedPath, // The name/path of the file being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [DELETE /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();

    let encoded_file_name = match session.get_encoded_file_name(file_path.to_path_buf()).await {
        Ok(e) => e,
        Err(DbError::NotFound) => return Err(RequestError::NotFound),
        Err(e) => {
            error!("Failed to get encoded file name from db: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };
    trace!("Retrieved encoded_file_name: {}", encoded_file_name);

    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;

    trace!("Constructed encoded_file_path: {:?}", encoded_file_path);

    match session.delete_file(file_path_buf).await {
        Ok(_) => {
            trace!("File metadata deleted from DB successfully.");
            drop(session)
        }
        Err(e) => {
            error!("Failed to delete file from db: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    match remove_sharded_path(&user_path, &encoded_file_path).await {
        Ok(_) => trace!("Physical file deleted successfully."),
        Err(e) => {
            error!("Failed to delete file: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    trace!("Exiting route [DELETE /file{}] successfully.", file_path);

    Ok(RequestSuccess::NoContent)
}
