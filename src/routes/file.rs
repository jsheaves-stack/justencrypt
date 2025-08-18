use std::io::SeekFrom;

use encryption::{
    stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor, BUFFER_SIZE, NONCE_SIZE,
    SALT_SIZE, TAG_SIZE,
};
use rocket::serde::{json::Json, Deserialize};

use rocket::{
    data::ByteUnit,
    delete, get, put,
    response::stream::ByteStream,
    tokio::{
        self,
        fs::File,
        io::{AsyncReadExt, AsyncSeekExt, BufReader},
        sync::mpsc,
    },
    Data,
};
use uuid::Uuid;

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    get_sharded_path, remove_sharded_path,
    web::forwarding_guards::AuthenticatedSession,
    UnrestrictedPath,
};

const STREAM_LIMIT: usize = 50 * (1000 * (1000 * 1000)); // 50 Gigabyte

const MPSC_CHANNEL_CAPACITY: usize = 2;

#[options("/<_file_path..>")]
pub fn file_options(_file_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[put("/<file_path..>", data = "<reqdata>")]
pub async fn put_file(
    file_path: UnrestrictedPath, // The path where the file should be stored, extracted from the URL.
    reqdata: Data<'_>,           // The raw data of the file being uploaded.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    let session = auth.session.read().await;

    let user_path = session.get_user_path().clone();
    let encoded_file_name = Uuid::new_v4().to_string();
    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name);

    // Initialize the stream encryptor for the file.
    let mut encryptor = match StreamEncryptor::new(encoded_file_path).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create StreamEncryptor: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    let metadata = encryptor.get_file_encryption_metadata();
    let file_path_buf = file_path.to_path_buf();

    match session
        .add_file(file_path_buf, encoded_file_name, metadata)
        .await
    {
        Ok(_) => drop(session),
        Err(e) => {
            error!("Failed to add file to db: {}", e);
            return Err(RequestError::FailedToAddFile);
        }
    };

    // Create a channel for transferring file data chunks with a specified buffer size.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);

    // Spawn an async task to handle file encryption and writing.
    tokio::spawn(async move {
        // Write encryption metadata (salt and nonce) to the file.
        match encryptor.write_salt_and_nonce().await {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to write salt and nonce chunks: {}", e);
                return;
            }
        };

        // Continuously read data chunks from the channel, encrypt, and write them.
        while let Some(data) = rx.recv().await {
            let encrypted_chunk = match encryptor.encrypt_chunk(&data).await {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to encrypt chunk: {}", e);
                    return;
                }
            };

            match encryptor.write_chunk(encrypted_chunk).await {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to write encrypted chunk: {}", e);
                    return;
                }
            }
        }
    });

    // Buffer to store data chunks read from the request.
    let mut read_buffer = [0u8; BUFFER_SIZE];

    // Open the request data stream with a limit.
    let mut data_stream = reqdata.open(ByteUnit::from(STREAM_LIMIT));
    let mut current_buffer_fill = 0;

    loop {
        // Read a chunk of data from the stream.
        let bytes_read = match data_stream
            .read(&mut read_buffer[current_buffer_fill..])
            .await
        {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to read chunk from data stream: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

        // Break the loop if no more data is available.
        if bytes_read == 0 {
            if current_buffer_fill > 0
                && tx
                    .send(read_buffer[..current_buffer_fill].to_vec())
                    .await
                    .is_err()
            {
                error!("Failed to send final data chunk: channel closed prematurely.");
                return Err(RequestError::FailedToProcessData);
            }
            break;
        }

        current_buffer_fill += bytes_read;

        // If the buffer is full, send it through the channel and reset the current size.
        if current_buffer_fill == BUFFER_SIZE {
            if tx.send(read_buffer.to_vec()).await.is_err() {
                error!("Failed to send data chunk: channel closed prematurely.");
                return Err(RequestError::FailedToProcessData);
            }
            current_buffer_fill = 0;
        }
    }

    Ok(RequestSuccess::Created)
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
    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;

    let updates = patch_file_request.into_inner();

    if let Some(parent_folder_path) = updates.parent_folder_path {
        match session
            .move_file(file_path_buf.clone(), parent_folder_path)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to move file: {}", e);

                return Err(RequestError::FailedToProcessData);
            }
        }
    };

    if let Some(new_file_name) = updates.file_name {
        match session.rename_file(file_path_buf, new_file_name).await {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to move file: {}", e);

                return Err(RequestError::FailedToProcessData);
            }
        }
    };

    drop(session);

    Ok(RequestSuccess::NoContent)
}

#[get("/<file_path..>")]
pub async fn get_file(
    file_path: UnrestrictedPath, // The name/path of the file being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<ByteStream![Vec<u8>], RequestError> {
    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;

    let user_path = session.get_user_path().clone();

    let encoded_file_name = match session.get_encoded_file_name(file_path.to_path_buf()).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to get encoded file name from db: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name);

    let metadata = match session.get_file_encryption_metadata(file_path_buf).await {
        Ok(m) => {
            drop(session);
            m
        }
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

    // Open the encrypted file.
    let input_file = match File::open(decryptor.get_file_path()).await {
        Ok(i) => i,
        Err(e) => {
            error!("Failed to open file: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    let mut reader = BufReader::new(input_file);

    let salt_nonce_size = (SALT_SIZE + NONCE_SIZE).try_into().unwrap();

    // Skip the encryption metadata (salt and nonce) at the beginning of the file.
    match reader.seek(SeekFrom::Start(salt_nonce_size)).await {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to seek in file: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    // Create an unbounded channel for streaming decrypted file chunks.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);

    // Spawn an async task to read, decrypt, and send file chunks.
    tokio::spawn(async move {
        let mut encrypted_read_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

        // Loop to read and decrypt the file in chunks.
        loop {
            let bytes_read = match reader.read(&mut encrypted_read_buffer).await {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to read encrypted file chunk: {}", e);
                    return;
                }
            };

            if bytes_read == 0 {
                break;
            }

            let decrypted_chunk = match decryptor
                .decrypt_chunk(&encrypted_read_buffer[..bytes_read])
                .await
            {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to decrypt file chunk: {}", e);
                    return;
                }
            };

            // Break the loop if the decrypted chunk is empty.
            if decrypted_chunk.is_empty() {
                break;
            }

            // Send the decrypted chunk for streaming.
            if tx.send(decrypted_chunk).await.is_err() {
                info!(
                    "Failed to send decrypted chunk: channel closed (client likely disconnected)."
                );
                return;
            }
        }
    });

    // Stream the decrypted file chunks as they become available.
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
    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;

    let user_path = session.get_user_path().clone();

    let encoded_file_name = match session.get_encoded_file_name(file_path.to_path_buf()).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to get encoded file name from db: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name);

    match session.delete_file(file_path_buf).await {
        Ok(_) => drop(session),
        Err(e) => {
            error!("Failed to add file to db: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    match remove_sharded_path(&user_path, &encoded_file_path).await {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to delete file: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    Ok(RequestSuccess::NoContent)
}
