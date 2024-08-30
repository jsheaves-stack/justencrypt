use std::{io::SeekFrom, path::PathBuf};

use encryption::{
    get_encoded_file_name, StreamDecryptor, StreamEncryptor, BUFFER_SIZE, NONCE_SIZE, SALT_SIZE,
    TAG_SIZE,
};

use rocket::{
    data::ByteUnit,
    delete, get,
    http::CookieJar,
    put,
    response::stream::ByteStream,
    tokio::{
        self,
        fs::{self, File},
        io::{AsyncReadExt, AsyncSeekExt, BufReader},
        sync::mpsc,
    },
    Data, State,
};

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    AppState,
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
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> Result<RequestSuccess, RequestError> {
    // Lock the active sessions map for write access.
    let mut active_sessions = state.active_sessions.write().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => return Err(RequestError::MissingSessionId),
    };

    let session = match active_sessions.get_mut(cookie.value()) {
        Some(s) => s,
        None => return Err(RequestError::MissingActiveSession),
    };

    // Process the file path to separate it into components.
    let mut components = file_path
        .iter()
        .filter_map(|s| s.to_str())
        .map(String::from)
        .collect::<Vec<String>>();

    // Extract the file name from the path and prepare the user's directory path.
    let file_name = components.pop().unwrap();
    let user_path = session.user_path.clone();

    // Insert the file path into the user's manifest and update the manifest.
    session.manifest.files.insert_path(
        components.into_iter(),
        file_name.clone(),
        get_encoded_file_name(&file_path).unwrap(),
    );

    match session.update_manifest().await {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to write user manifest: {}", e);
            return Err(RequestError::FailedToWriteUserManifest);
        }
    };

    // Clone the passphrase for use in the spawned encryption task.
    let passphrase = session.passphrase.clone();

    // Drop active_sessions to release the write lock so we're not holding onto it the entire time we're processing a file.
    drop(active_sessions);

    // Create a channel for transferring file data chunks with a specified buffer size.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(BUFFER_SIZE);

    // Spawn an async task to handle file encryption and writing.
    tokio::spawn(async move {
        // Initialize the stream encryptor for the file.
        let mut encryptor = match StreamEncryptor::new(&user_path, &file_path, &passphrase).await {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to create StreamEncryptor: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

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

            match encryptor.write_chunk(&encrypted_chunk).await {
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

            current_size = current_size - BUFFER_SIZE;
        }
    }

    Ok(RequestSuccess::Created)
}

#[get("/<file_path..>")]
pub async fn get_file(
    file_path: PathBuf, // The name/path of the file being requested, extracted from the URL.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> Result<ByteStream![Vec<u8>], RequestError> {
    // Read access to the active sessions map.
    let active_sessions = state.active_sessions.read().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => return Err(RequestError::MissingSessionId),
    };

    let session = match active_sessions.get(cookie.value()) {
        Some(s) => s,
        None => return Err(RequestError::MissingActiveSession),
    };

    // Initialize the stream decryptor for the requested file.
    let mut decryptor =
        match StreamDecryptor::new(&session.user_path, &file_path, &session.passphrase).await {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to create StreamDecryptor: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

    // Open the encrypted file.
    let input_file = match File::open(decryptor.file_path.clone()).await {
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
            if decrypted_chunk.len() == 0 {
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
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> Result<RequestSuccess, RequestError> {
    // Lock the active sessions map for write access.
    let mut active_sessions = state.active_sessions.write().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => return Err(RequestError::MissingSessionId),
    };

    let session = match active_sessions.get_mut(cookie.value()) {
        Some(s) => s,
        None => return Err(RequestError::MissingActiveSession),
    };

    let file_name = get_encoded_file_name(&file_path).unwrap();

    match fs::remove_file(session.user_path.join(file_name)).await {
        Ok(_) => (),
        Err(_) => return Err(RequestError::FailedToRemoveFile),
    };

    match session.manifest.files.delete_item(&file_path) {
        Ok(_) => (),
        Err(_) => return Err(RequestError::FailedToRemoveFile),
    };

    match session.update_manifest().await {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to write user manifest: {}", e);
            return Err(RequestError::FailedToWriteUserManifest);
        }
    };

    Ok(RequestSuccess::NoContent)
}
