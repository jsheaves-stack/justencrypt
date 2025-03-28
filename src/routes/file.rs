use std::{io::SeekFrom, path::PathBuf};

use encryption::{
    get_encoded_file_name, stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor,
    BUFFER_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};

use rocket::{
    data::ByteUnit,
    delete, get, put,
    response::stream::ByteStream,
    tokio::{
        self,
        fs::{self, File},
        io::{AsyncReadExt, AsyncSeekExt, BufReader},
        sync::mpsc,
    },
    Data,
};

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    web::forwarding_guards::AuthenticatedSession,
};

const STREAM_LIMIT: usize = 50 * (1000 * (1000 * 1000)); // 50 Gigabyte

#[options("/<_file_path..>")]
pub fn file_options(_file_path: PathBuf) -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[put("/<file_path..>", data = "<reqdata>")]
pub async fn put_file(
    file_path: PathBuf, // The path where the file should be stored, extracted from the URL.
    reqdata: Data<'_>,  // The raw data of the file being uploaded.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    let mut session = auth.session.lock().await;
    let user_path = session.get_user_path().clone();
    let encoded_file_name = get_encoded_file_name(file_path.clone()).unwrap();
    let encoded_file_path = user_path.join(encoded_file_name.clone());

    // Initialize the stream encryptor for the file.
    let mut encryptor = match StreamEncryptor::new(encoded_file_path).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create StreamEncryptor: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    let metadata = encryptor.get_file_encryption_metadata();

    match session
        .add_file(file_path.clone(), encoded_file_name, metadata)
        .await
    {
        Ok(_) => drop(session),
        Err(e) => {
            error!("Failed to add file to db: {}", e);
            return Err(RequestError::FailedToAddFile);
        }
    };

    // Create a channel for transferring file data chunks with a specified buffer size.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(BUFFER_SIZE);

    // Spawn an async task to handle file encryption and writing.
    tokio::spawn(async move {
        // Write encryption metadata (salt and nonce) to the file.
        match encryptor.write_salt_and_nonce().await {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to write salt and nonce chunks: {}", e);
                return Err(RequestError::FailedToWriteData);
            }
        };

        // Continuously read data chunks from the channel, encrypt, and write them.
        while let Some(data) = rx.recv().await {
            let encrypted_chunk = match encryptor.encrypt_chunk(&data).await {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to encrypt chunk: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };

            match encryptor.write_chunk(encrypted_chunk).await {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to write encrypted chunk: {}", e);
                    return Err(RequestError::FailedToWriteData);
                }
            }
        }

        Ok(())
    });

    // Buffer to store data chunks read from the request.
    let mut buffer = [0u8; BUFFER_SIZE];

    // Open the request data stream with a limit.
    let mut data_stream = reqdata.open(ByteUnit::from(STREAM_LIMIT));
    let mut current_size = 0;

    loop {
        // Read a chunk of data from the stream.
        let chunk_size = match data_stream.read(&mut buffer[current_size..]).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to read chunk from data stream: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

        // Break the loop if no more data is available.
        if chunk_size == 0 {
            if current_size == 0 {
                break;
            }

            // Send the last chunk of data if not empty.
            match tx.send(buffer[..current_size].to_vec()).await {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to send buffer through channel: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };

            current_size = 0;
        }

        current_size += chunk_size;

        // If the buffer is full, send it through the channel and reset the current size.
        if current_size >= BUFFER_SIZE {
            match tx.send(buffer[..BUFFER_SIZE].to_vec()).await {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to send buffer through channel: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };

            current_size -= BUFFER_SIZE;
        }
    }

    Ok(RequestSuccess::Created)
}

#[get("/<file_path..>")]
pub async fn get_file(
    file_path: PathBuf, // The name/path of the file being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<ByteStream![Vec<u8>], RequestError> {
    let session = auth.session.lock().await;

    let encoded_file_name = get_encoded_file_name(file_path.clone()).unwrap();
    let encoded_file_path = session.get_user_path().join(encoded_file_name);

    let metadata = match session.get_file_encryption_metadata(file_path).await {
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
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(BUFFER_SIZE + TAG_SIZE);

    // Spawn an async task to read, decrypt, and send file chunks.
    tokio::spawn(async move {
        let mut buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

        // Loop to read and decrypt the file in chunks.
        loop {
            let chunk_size = match reader.read(&mut buffer).await {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to read file: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };

            // Break the loop if end of file is reached.
            if chunk_size == 0 {
                break;
            }

            // Decrypt the current chunk.
            let decrypted_chunk = match decryptor.decrypt_chunk(&buffer[..chunk_size]).await {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to decrypt file chunk: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };

            // Break the loop if the decrypted chunk is empty.
            if decrypted_chunk.is_empty() {
                break;
            }

            // Send the decrypted chunk for streaming.
            match tx.send(decrypted_chunk).await {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to send file chunk through channel: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };
        }

        Ok(())
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
    file_path: PathBuf, // The name/path of the file being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    let session = auth.session.lock().await;

    let file_name = get_encoded_file_name(file_path.clone()).unwrap();
    let full_file_path = session.get_user_path().join(&file_name);

    match fs::remove_file(&full_file_path).await {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to delete file: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    match fs::remove_file(full_file_path.with_extension("meta")).await {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to delete meta file: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    Ok(RequestSuccess::NoContent)
}
