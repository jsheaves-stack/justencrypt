use std::io::SeekFrom;

use encryption::{
    stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor, BUFFER_SIZE, NONCE_SIZE,
    SALT_SIZE, TAG_SIZE,
};
use rocket::serde::{json::Json, Deserialize};

use rocket::{
    data::ByteUnit,
    delete, get, options, patch, put,
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
    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name);
    trace!(
        "Generated encoded_file_name: {} for path: {:?}",
        encoded_file_name,
        encoded_file_path
    );

    // Initialize the stream encryptor for the file.
    let mut encryptor = match StreamEncryptor::new(encoded_file_path).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create StreamEncryptor: {}", e);
            return Err(RequestError::FailedToProcessData);
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

    // Create a channel for transferring file data chunks with a specified buffer size.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);
    trace!("MPSC channel created for file upload.");

    // Spawn an async task to handle file encryption and writing.
    tokio::spawn(async move {
        trace!("Spawned task for file encryption and writing.");
        // Write encryption metadata (salt and nonce) to the file.
        match encryptor.write_salt_and_nonce().await {
            Ok(_) => trace!("Salt and nonce written to file."),
            Err(e) => {
                error!("Failed to write salt and nonce chunks: {}", e);
                return;
            }
        };

        // Continuously read data chunks from the channel, encrypt, and write them.
        while let Some(data) = rx.recv().await {
            trace!("Received chunk of size {} for encryption.", data.len());
            let encrypted_chunk = match encryptor.encrypt_chunk(&data).await {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to encrypt chunk: {}", e);
                    return;
                }
            };

            match encryptor.write_chunk(encrypted_chunk).await {
                Ok(_) => trace!("Encrypted chunk written to file."),
                Err(e) => {
                    error!("Failed to write encrypted chunk: {}", e);
                    return;
                }
            }
        }
        trace!("Finished processing all chunks in encryption task.");
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
        trace!("Read {} bytes from input stream.", bytes_read);

        // Break the loop if no more data is available.
        if bytes_read == 0 {
            if current_buffer_fill > 0 {
                trace!(
                    "End of stream. Sending final chunk of size {}.",
                    current_buffer_fill
                );
                if tx
                    .send(read_buffer[..current_buffer_fill].to_vec())
                    .await
                    .is_err()
                {
                    error!("Failed to send final data chunk: channel closed prematurely.");
                    return Err(RequestError::FailedToProcessData);
                }
            } else {
                trace!("End of stream. No final chunk to send.");
            }
            break;
        }

        current_buffer_fill += bytes_read;

        // If the buffer is full, send it through the channel and reset the current size.
        if current_buffer_fill == BUFFER_SIZE {
            trace!("Buffer full. Sending chunk of size {}.", BUFFER_SIZE);
            if tx.send(read_buffer.to_vec()).await.is_err() {
                error!("Failed to send data chunk: channel closed prematurely.");
                return Err(RequestError::FailedToProcessData);
            }
            current_buffer_fill = 0;
        }
    }

    trace!("Exiting route [PUT /file{}] successfully.", file_path);
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
                return Err(RequestError::FailedToProcessData);
            }
        }
    };

    if let Some(new_file_name) = updates.file_name {
        trace!("Attempting to rename file to: {}", new_file_name);
        match session.rename_file(file_path_buf, new_file_name).await {
            Ok(_) => trace!("File renamed successfully."),
            Err(e) => {
                error!("Failed to rename file: {}", e);
                return Err(RequestError::FailedToProcessData);
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
        Err(e) => {
            error!("Failed to get encoded file name from db: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };
    trace!("Retrieved encoded_file_name: {}", encoded_file_name);

    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name);
    trace!("Constructed encoded_file_path: {:?}", encoded_file_path);

    let metadata = match session.get_file_encryption_metadata(file_path_buf).await {
        Ok(m) => {
            trace!("Successfully retrieved file encryption metadata.");
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

    let salt_nonce_size = (SALT_SIZE + NONCE_SIZE).try_into().unwrap();

    // Skip the encryption metadata (salt and nonce) at the beginning of the file.
    match reader.seek(SeekFrom::Start(salt_nonce_size)).await {
        Ok(_) => trace!("Seeked past salt and nonce in file."),
        Err(e) => {
            error!("Failed to seek in file: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    // Create an unbounded channel for streaming decrypted file chunks.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);
    trace!("MPSC channel created for file download.");

    // Spawn an async task to read, decrypt, and send file chunks.
    tokio::spawn(async move {
        trace!("Spawned task for file decryption and streaming.");
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
            trace!("Read {} encrypted bytes from file.", bytes_read);

            if bytes_read == 0 {
                trace!("End of file reached.");
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
            trace!("Decrypted chunk of size {}.", decrypted_chunk.len());

            // Break the loop if the decrypted chunk is empty.
            if decrypted_chunk.is_empty() {
                trace!("Decrypted chunk is empty, assuming end of stream.");
                break;
            }

            // Send the decrypted chunk for streaming.
            if tx.send(decrypted_chunk).await.is_err() {
                info!(
                    "Failed to send decrypted chunk: channel closed (client likely disconnected)."
                );
                return;
            }
            trace!("Sent decrypted chunk to stream.");
        }
        trace!("Finished processing all chunks in decryption task.");
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
        Err(e) => {
            error!("Failed to get encoded file name from db: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };
    trace!("Retrieved encoded_file_name: {}", encoded_file_name);

    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{get_app_config, session::user_session::UserSession, AppState};
    use rocket::{
        http::{Cookie, Status},
        local::asynchronous::Client,
        tokio::sync::{RwLock, Semaphore},
        Build, Orbit, Rocket,
    };
    use secrecy::SecretString;
    use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};
    use uuid::Uuid;

    async fn setup() -> (Rocket<Build>, PathBuf, String) {
        dotenv::dotenv().ok();

        let temp_user = Uuid::new_v4().to_string();
        let temp_dir = std::env::temp_dir().join(temp_user.clone());

        tokio::fs::create_dir_all(&temp_dir)
            .await
            .expect("Failed to create temp dir");

        std::env::set_var(
            "JUSTENCRYPT_ROCKET_SECRET_KEY",
            "BlN4QMqM8+wmRLPNRn10X/ZwmM58tEcCOgeY8cuMsB8=",
        );
        std::env::set_var("JUSTENCRYPT_USER_DATA_PATH", "/tmp/");

        let state = AppState {
            active_sessions: RwLock::new(HashMap::new()),
            thumbnail_semaphore: Arc::new(Semaphore::new(1)),
        };
        let app_config = get_app_config();

        let rocket = rocket::custom(app_config).manage(state).mount(
            "/file",
            routes![put_file, get_file, delete_file, file_options, patch_file],
        );

        (rocket, temp_dir, temp_user)
    }

    async fn cleanup(temp_dir: PathBuf) {
        tokio::fs::remove_dir_all(temp_dir)
            .await
            .expect("Failed to remove temp dir");
    }

    async fn create_test_session(
        rocket: &Rocket<Orbit>,
        temp_user: String,
    ) -> (String, Cookie<'static>) {
        // fs::create_dir("./user_data/test_user").unwrap();
        let session_id = Uuid::new_v4().to_string();
        let passphrase = SecretString::from_str("test_password").unwrap();

        let user_session = match UserSession::open(&temp_user, &passphrase).await {
            Ok(session) => Arc::new(RwLock::new(session)),
            Err(e) => panic!("Failed to open user session: {}", e),
        };

        let state = rocket.state::<AppState>().unwrap();

        state
            .active_sessions
            .write()
            .await
            .insert(session_id.clone(), user_session);

        let cookie = Cookie::build(("session_id", session_id.clone())).build();

        (session_id, cookie)
    }

    #[rocket::async_test]
    async fn test_put_file() {
        let (rocket, temp_dir, temp_user) = setup().await;

        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let file_path = "test_file.txt";
        let file_content = "Hello, world!";

        let response = client
            .put(format!("/file/{}", file_path))
            .private_cookie(cookie)
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = session_guard.get(&session_id).unwrap().clone();
        let session = session.read().await;

        let file_entry = Some(
            session
                .get_encoded_file_name(file_path.into())
                .await
                .unwrap(),
        );

        assert!(file_entry.is_some());

        let encoded_file_name = file_entry.map(|f| f).unwrap();
        let sharded_path = get_sharded_path(session.get_user_path().clone(), &encoded_file_name);

        assert!(tokio::fs::metadata(sharded_path).await.is_ok());

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_get_file() {
        let (rocket, temp_dir, temp_user) = setup().await;

        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let file_path = "test_file.txt";
        let file_content = "Hello, world!";

        let response = client
            .put(format!("/file/{}", file_path))
            .private_cookie(cookie.clone())
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let response = client
            .get(format!("/file/{}", file_path))
            .private_cookie(cookie)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        println!("{:?}", body);
        assert_eq!(body, file_content);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = session_guard.get(&session_id).unwrap().clone();
        let session = session.read().await;

        let file_entry = Some(
            session
                .get_encoded_file_name(file_path.into())
                .await
                .unwrap(),
        );

        assert!(file_entry.is_some());

        let encoded_file_name = file_entry.map(|f| f).unwrap();
        let sharded_path = get_sharded_path(session.get_user_path().clone(), &encoded_file_name);

        assert!(tokio::fs::metadata(sharded_path).await.is_ok());

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_put_file_no_auth() {
        let (rocket, temp_dir, _) = setup().await;
        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let file_path = "test_file.txt";
        let file_content = "Hello, world!";

        let response = client
            .put(format!("/file/{}", file_path))
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Unauthorized);

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_put_file_empty_content() {
        let (rocket, temp_dir, temp_user) = setup().await;
        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let file_path = "test_file.txt";
        let file_content = "";

        let response = client
            .put(format!("/file/{}", file_path))
            .private_cookie(cookie)
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = session_guard.get(&session_id).unwrap().clone();
        let session = session.read().await;

        let file_entry = Some(
            session
                .get_encoded_file_name(file_path.into())
                .await
                .unwrap(),
        );

        assert!(file_entry.is_some());

        let encoded_file_name = file_entry.map(|f| f).unwrap();
        let sharded_path = get_sharded_path(session.get_user_path().clone(), &encoded_file_name);

        assert!(tokio::fs::metadata(sharded_path).await.is_ok());

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_put_file_large_content() {
        let (rocket, temp_dir, temp_user) = setup().await;
        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let file_path = "test_file.txt";
        let file_content = "A".repeat(64 * 1024 * 1024); // 64MB

        let response = client
            .put(format!("/file/{}", file_path))
            .private_cookie(cookie)
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = session_guard.get(&session_id).unwrap().clone();
        let session = session.read().await;

        let file_entry = Some(
            session
                .get_encoded_file_name(file_path.into())
                .await
                .unwrap(),
        );

        assert!(file_entry.is_some());

        cleanup(temp_dir).await;
    }
}
