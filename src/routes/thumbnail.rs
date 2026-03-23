use crate::{
    encryption::{stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor},
    enums::{db_error::DbError, request_error::RequestError, request_success::RequestSuccess},
    util::{sharded_path::get_sharded_path, unrestricted_path::UnrestrictedPath},
    web::forwarding_guards::AuthenticatedSession,
    AppState,
};
use image::ImageFormat;
use rocket::{
    get,
    http::ContentType,
    options,
    tokio::{self, fs},
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
    file_path: UnrestrictedPath,
    state: &State<AppState>,
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
        _ => return Err(RequestError::UnsupportedFileType),
    };

    let permit = state
        .thumbnail_semaphore
        .acquire()
        .await
        .map_err(|_| RequestError::FailedToProcessData)?;

    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();
    let cache_path = user_path.join(".cache");

    if !cache_path.exists() {
        fs::create_dir(&cache_path).await.map_err(|e| {
            error!("Failed to create user cache directory: {}", e);
            RequestError::FailedToWriteData
        })?;
    }

    let encoded_thumbnail_file_name = session
        .get_encoded_thumbnail_file_name(file_path_buf.clone())
        .await
        .map_err(|e| {
            if let DbError::NotFound = e {
                RequestError::NotFound
            } else {
                error!("Failed to get encoded thumbnail file name: {}", e);
                RequestError::FailedToProcessData
            }
        })?
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let encoded_thumbnail_file_path =
        get_sharded_path(cache_path.clone(), &encoded_thumbnail_file_name).await;

    let metadata = session
        .get_file_encryption_metadata(file_path_buf.clone())
        .await
        .map_err(|e| {
            if let DbError::NotFound = e {
                RequestError::NotFound
            } else {
                error!("Failed to get file encryption metadata: {}", e);
                RequestError::FailedToProcessData
            }
        })?;

    if !encoded_thumbnail_file_path.exists() {
        let encoded_file_name = session.get_encoded_file_name(file_path_buf.clone()).await.map_err(|e| {
            if let DbError::NotFound = e {
                RequestError::NotFound
            } else {
                error!("Failed to get encoded file name: {}", e);
                RequestError::FailedToProcessData
            }
        })?;

        let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;

        let mut decryptor = StreamDecryptor::new(encoded_file_path, metadata).await.map_err(|e| {
            error!("Failed to create StreamDecryptor: {}", e);
            RequestError::FailedToProcessData
        })?;

        let decrypted_original_image_data = decryptor.decrypt_all().await.map_err(|e| {
            error!("Failed to decrypt original image data: {}", e);
            RequestError::FailedToProcessData
        })?;

        let mut thumbnail_buffer: Cursor<Vec<u8>> = tokio::task::spawn_blocking(move || {
            let mut thumbnail_buffer = Cursor::new(Vec::new());
            let img =
                image::load_from_memory_with_format(&decrypted_original_image_data, image_format)
                    .map_err(|e| {
                    error!("Failed to decode image: {}", e);
                    RequestError::FailedToProcessData
                })?;

            img.thumbnail(150, 150)
                .write_to(&mut thumbnail_buffer, image_format)
                .map_err(|e| {
                    error!("Failed to write resized image: {}", e);
                    RequestError::FailedToProcessData
                })?;

            thumbnail_buffer.set_position(0);
            Ok(thumbnail_buffer)
        })
        .await
        .map_err(|e| {
            error!("Blocking image resize task panicked: {}", e);
            RequestError::FailedToProcessData
        })??;

        drop(permit);

        let mut encryptor = StreamEncryptor::new(encoded_thumbnail_file_path).await.map_err(|e| {
            error!("Failed to create StreamEncryptor: {}", e);
            RequestError::FailedToProcessData
        })?;

        encryptor.encrypt_stream(&mut thumbnail_buffer).await.map_err(|e| {
            error!("Failed to encrypt thumbnail data: {}", e);
            RequestError::FailedToProcessData
        })?;

        let thumbnail_metadata = encryptor.get_metadata();

        session
            .add_thumbnail(
                file_path_buf,
                encoded_thumbnail_file_name,
                thumbnail_metadata,
            )
            .await
            .map_err(|e| {
                error!("Failed to add thumbnail to db: {}", e);
                RequestError::FailedToAddFile
            })?;

        Ok(thumbnail_buffer.into_inner())
    } else {
        drop(permit);

        let thumbnail_metadata = session.get_thumbnail(file_path_buf).await.map_err(|e| {
            if let DbError::NotFound = e {
                RequestError::NotFound
            } else {
                error!("Failed to get thumbnail metadata: {}", e);
                RequestError::FailedToProcessData
            }
        })?;
        drop(session);

        let mut decryptor = StreamDecryptor::new(encoded_thumbnail_file_path, thumbnail_metadata).await.map_err(|e| {
            error!("Failed to create StreamDecryptor: {}", e);
            RequestError::FailedToProcessData
        })?;

        let decrypted_thumbnail_data = decryptor.decrypt_all().await.map_err(|e| {
            error!("Failed to decrypt thumbnail data: {}", e);
            RequestError::FailedToProcessData
        })?;

        Ok(decrypted_thumbnail_data)
    }
}
