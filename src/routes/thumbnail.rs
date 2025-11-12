use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    get_sharded_path,
    streaming::encryption_streaming::{decrypt_stream_to_writer, encrypt_source_to_encryptor},
    web::forwarding_guards::AuthenticatedSession,
    AppState, UnrestrictedPath,
};
use encryption::{
    stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor, NONCE_SIZE, SALT_SIZE,
};
use image::ImageFormat;
use rocket::{
    get,
    http::ContentType,
    options,
    tokio::{
        self,
        fs::{self, File},
        io::BufReader,
    },
    State,
};
use std::io::Cursor;
use uuid::Uuid;

#[options("/<file_path..>")]
pub fn thumbnail_options(file_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /thumbnail{}]", file_path);
    Ok(RequestSuccess::NoContent)
}

#[get("/<file_path..>")]
pub async fn get_thumbnail(
    file_path: UnrestrictedPath, // The name/path of the file being requested, extracted from the URL.
    state: &State<AppState>, // Application state for accessing global resources like session management.
    auth: AuthenticatedSession,
) -> Result<Vec<u8>, RequestError> {
    trace!("Entering route [GET /thumbnail{}]", file_path);
    let file_path_buf = file_path.to_path_buf();

    let thumbnail_extension = file_path_buf.extension().unwrap_or_default();

    let content_type =
        ContentType::from_extension(thumbnail_extension.to_str().unwrap_or_default()).unwrap();

    let image_format = match content_type {
        _ if content_type == ContentType::JPEG => ImageFormat::Jpeg,
        _ if content_type == ContentType::PNG => ImageFormat::Png,
        _ if content_type == ContentType::GIF => ImageFormat::Gif,
        _ if content_type == ContentType::WEBP => ImageFormat::WebP,
        _ if content_type == ContentType::AVIF => ImageFormat::Avif,
        _ => {
            return Err(RequestError::UnsupportedFileType);
        }
    };
    trace!("Determined image format: {:?}", image_format);

    let permit = state
        .thumbnail_semaphore
        .acquire()
        .await
        .map_err(|_| RequestError::FailedToProcessData)?;
    trace!("Acquired thumbnail semaphore permit.");

    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();
    let cache_path = user_path.join(".cache");

    if !cache_path.exists() {
        trace!("Cache directory does not exist, creating it.");
        match fs::create_dir(&cache_path).await {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to create user cache directory: {}", e);
                return Err(RequestError::FailedToWriteData);
            }
        };
    }

    let encoded_thumbnail_file_name = match session
        .get_encoded_thumbnail_file_name(file_path.to_path_buf())
        .await
    {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to get encoded thumbnail file name: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    }
    .unwrap_or_else(|| {
        let new_uuid = Uuid::new_v4().to_string();
        trace!(
            "No existing thumbnail found, generated new UUID: {}",
            new_uuid
        );
        new_uuid
    });

    let encoded_thumbnail_file_path =
        get_sharded_path(cache_path.clone(), &encoded_thumbnail_file_name);
    trace!(
        "Constructed thumbnail path: {:?}",
        encoded_thumbnail_file_path
    );

    let metadata = match session
        .get_file_encryption_metadata(file_path_buf.clone())
        .await
    {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to get file encryption metadata for file: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };
    trace!("Retrieved original file encryption metadata.");

    if !encoded_thumbnail_file_path.exists() {
        trace!("Thumbnail does not exist in cache, generating new one.");
        let encoded_file_name = match session.get_encoded_file_name(file_path_buf.clone()).await {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to get encoded file name: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

        let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name);

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

        let mut decrypted_original_image_data = Vec::new();

        decrypt_stream_to_writer(
            &mut reader,
            &mut decryptor,
            &mut decrypted_original_image_data,
            (SALT_SIZE + NONCE_SIZE) as u64,
        )
        .await?;
        trace!("Decrypted original image data.");

        let mut thumbnail_buffer: Cursor<Vec<u8>> = tokio::task::spawn_blocking(move || {
            trace!("Entering blocking task for image resizing.");
            let mut thumbnail_buffer = Cursor::new(Vec::new());

            let img =
                image::load_from_memory_with_format(&decrypted_original_image_data, image_format)
                    .map_err(|e| {
                    error!("Failed to decode image: {}", e);
                    RequestError::FailedToProcessData
                })?;

            let resized_image = img.thumbnail(150, 150);

            resized_image
                .write_to(&mut thumbnail_buffer, image_format)
                .map_err(|e| {
                    error!("Failed to write resized image: {}", e);
                    RequestError::FailedToProcessData
                })?;

            thumbnail_buffer.set_position(0);
            trace!("Exiting blocking task for image resizing.");
            Ok(thumbnail_buffer)
        })
        .await
        .map_err(|e| {
            error!("Blocking image resize task panicked: {}", e);
            RequestError::FailedToProcessData
        })??;

        drop(permit);
        trace!("Semaphore permit released after generation.");

        // Initialize the stream encryptor for the file.
        let mut encryptor = match StreamEncryptor::new(encoded_thumbnail_file_path.clone()).await {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to create StreamEncryptor: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

        let thumbnail_metadata = encryptor.get_file_encryption_metadata();

        match session
            .add_thumbnail(
                file_path_buf,
                encoded_thumbnail_file_name,
                thumbnail_metadata,
            )
            .await
        {
            Ok(_) => {
                trace!("Added thumbnail metadata to DB.");
                drop(session)
            }
            Err(e) => {
                error!("Failed to add thumbnail to db: {}", e);
                return Err(RequestError::FailedToAddFile);
            }
        };

        encrypt_source_to_encryptor(&mut thumbnail_buffer, &mut encryptor).await?;

        trace!("Encrypted and wrote thumbnail to cache.");

        trace!(
            "Exiting route [GET /thumbnail{}] after generating new thumbnail successfully.",
            file_path
        );
        Ok(thumbnail_buffer.into_inner())
    } else {
        trace!("Thumbnail exists in cache, decrypting it.");
        drop(permit);
        trace!("Semaphore permit released immediately.");

        let thumbnail_metadata = match session.get_thumbnail(file_path_buf).await {
            Ok(f) => {
                drop(session);
                f
            }
            Err(e) => {
                error!("Failed to get thumbnail encryption metadata from db: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };
        trace!("Retrieved thumbnail encryption metadata.");

        // Initialize the stream decryptor for the requested file.
        let mut decryptor =
            match StreamDecryptor::new(encoded_thumbnail_file_path, thumbnail_metadata).await {
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

        let mut decrypted_thumbnail_data = Vec::new();
        decrypt_stream_to_writer(
            &mut reader,
            &mut decryptor,
            &mut decrypted_thumbnail_data,
            (SALT_SIZE + NONCE_SIZE) as u64,
        )
        .await?;
        trace!("Decrypted thumbnail data from cache.");

        trace!(
            "Exiting route [GET /thumbnail{}] with cached thumbnail successfully.",
            file_path
        );
        Ok(decrypted_thumbnail_data)
    }
}
