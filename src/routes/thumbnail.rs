use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    AppState,
};
use encryption::{
    get_encoded_file_name, DerivedKey, Salt, SecretKey, StreamDecryptor, StreamEncryptor,
    BUFFER_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};
use image::ImageFormat;
use rocket::{
    get,
    http::{ContentType, CookieJar},
    tokio::{
        fs::{self, File},
        io::{AsyncReadExt, AsyncSeekExt, BufReader, SeekFrom},
    },
    State,
};
use std::{
    io::Cursor,
    path::{Path, PathBuf},
};

#[options("/<_file_path..>")]
pub fn thumbnail_options(_file_path: PathBuf) -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[get("/<file_path..>")]
pub async fn get_thumbnail(
    file_path: PathBuf, // The name/path of the file being requested, extracted from the URL.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    cookies: &CookieJar<'_>, // Cookies associated with the request, used for session management.
) -> Result<Vec<u8>, RequestError> {
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

    let derived_key = DerivedKey {
        salt: Salt::from_slice(session.manifest_key.salt.as_ref()).unwrap(),
        key: SecretKey::from_slice(session.manifest_key.key.unprotected_as_bytes()).unwrap(),
    };

    let user_path = session.user_path.clone();
    let cache_path = Path::new(&user_path).join(".cache");

    if !cache_path.exists() {
        match fs::create_dir(&cache_path).await {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to create user cache directory: {}", e);
                return Err(RequestError::FailedToWriteData);
            }
        };
    }

    let encoded_thumbnail_file_name =
        PathBuf::from(get_encoded_file_name(&Path::new(".cache").join(&file_path)).unwrap());

    let thumbnail_path: PathBuf = cache_path.join(&encoded_thumbnail_file_name);

    let thumbnail_extension = file_path.extension().unwrap();

    if !thumbnail_path.exists() {
        let content_type =
            ContentType::from_extension(thumbnail_extension.to_str().unwrap()).unwrap();

        // Initialize the stream decryptor for the requested file.
        let mut decryptor = match StreamDecryptor::new(
            &session.user_path,
            &PathBuf::from(&file_path),
            &session.manifest_key,
        )
        .await
        {
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

        let mut file_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];
        let mut decrypted_file_buffer = Vec::new();

        loop {
            let chunk_size = match reader.read(&mut file_buffer).await {
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
            let decrypted_chunk = match decryptor.decrypt_chunk(&file_buffer[..chunk_size]).await {
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

            decrypted_file_buffer.extend_from_slice(&decrypted_chunk);
        }

        let image_format = match content_type {
            _ if content_type == ContentType::JPEG => ImageFormat::Jpeg,
            _ if content_type == ContentType::PNG => ImageFormat::Png,
            _ if content_type == ContentType::GIF => ImageFormat::Gif,
            _ if content_type == ContentType::WEBP => ImageFormat::WebP,
            _ if content_type == ContentType::AVIF => ImageFormat::Avif,
            _ => return Err(RequestError::UnsupportedFileType),
        };

        let img = match image::load_from_memory_with_format(&decrypted_file_buffer, image_format) {
            Ok(i) => i,
            Err(_) => return Err(RequestError::FailedToProcessData),
        };

        let resized_image = img.thumbnail(150, 150);

        let mut thumbnail_buffer = Cursor::new(Vec::new());

        match resized_image.write_to(&mut thumbnail_buffer, image_format) {
            Ok(_) => (),
            Err(_) => return Err(RequestError::FailedToProcessData),
        };

        thumbnail_buffer.set_position(0);

        // Initialize the stream encryptor for the file.
        let mut encryptor = match StreamEncryptor::new(
            &user_path.join(".cache"),
            &PathBuf::from(".cache").join(file_path),
            derived_key,
        )
        .await
        {
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

        let mut encryption_file_buffer = [0u8; BUFFER_SIZE];

        loop {
            let chunk_size = match thumbnail_buffer.read(&mut encryption_file_buffer).await {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to read file: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };

            if chunk_size == 0 {
                break;
            }

            let encrypted_chunk = match encryptor
                .encrypt_chunk(&encryption_file_buffer[..chunk_size])
                .await
            {
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

        return Ok(thumbnail_buffer.into_inner());
    } else {
        // Initialize the stream decryptor for the requested file.
        let mut decryptor = match StreamDecryptor::new(
            &user_path.join(".cache"),
            &PathBuf::from(".cache").join(file_path),
            &session.manifest_key,
        )
        .await
        {
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

        let mut file_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];
        let mut decrypted_file_buffer = Vec::new();

        loop {
            let chunk_size = match reader.read(&mut file_buffer).await {
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
            let decrypted_chunk = match decryptor.decrypt_chunk(&file_buffer[..chunk_size]).await {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to decrypt file chunk: {}", e);
                    return Err(RequestError::FailedToProcessData);
                }
            };

            if decrypted_chunk.len() == 0 {
                break;
            }

            decrypted_file_buffer.extend_from_slice(&decrypted_chunk);
        }

        return Ok(decrypted_file_buffer);
    }
}
