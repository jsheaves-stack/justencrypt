use std::io::{BufReader, Cursor};

use image::ImageFormat;
use rocket::{
    get,
    http::ContentType,
    options,
    tokio::{self, fs},
    State,
};

use crate::{
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor,
        sync_chunk_decryptor::SyncChunkDecryptReader,
    },
    enums::{request_error::RequestError, request_success::RequestSuccess},
    util::{sharded_path::get_sharded_path, unrestricted_path::UnrestrictedPath},
    web::forwarding_guards::AuthenticatedSession,
    AppState,
};

#[options("/<_file_path..>")]
pub fn thumbnail_options(_file_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[get("/<file_path..>")]
pub async fn get_thumbnail(
    file_path: UnrestrictedPath,
    state: &State<AppState>,
    auth: AuthenticatedSession,
) -> Result<Vec<u8>, RequestError> {
    trace!("Entering route [GET /thumbnail/{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let content_type = ContentType::from_extension(
        file_path_buf
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default(),
    )
    .unwrap_or(ContentType::Binary);

    let image_format = match content_type {
        _ if content_type == ContentType::JPEG => ImageFormat::Jpeg,
        _ if content_type == ContentType::PNG => ImageFormat::Png,
        _ if content_type == ContentType::GIF => ImageFormat::Gif,
        _ if content_type == ContentType::WEBP => ImageFormat::WebP,
        _ if content_type == ContentType::AVIF => ImageFormat::Avif,
        _ => return Err(RequestError::UnsupportedFileType),
    };

    let _permit = state
        .thumbnail_semaphore
        .acquire()
        .await
        .map_err(|_| RequestError::FailedToProcessData)?;

    let session = auth.session.clone();
    let user_path = session.get_user_path();
    let cache_path = user_path.join(".cache");

    if !cache_path.exists() {
        fs::create_dir_all(&cache_path).await.map_err(|e| {
            error!("Failed to create cache dir: {}", e);

            RequestError::FailedToWriteData
        })?;
    }

    let (encoded_file_name, parent_metadata) = session
        .get_file_decryption_data(file_path_buf.clone())
        .await?;

    let thumbnail_metadata = parent_metadata
        .derive_thumbnail_metadata(encoded_file_name.as_bytes())
        .map_err(|e| {
            error!("Failed to derive thumbnail metadata: {}", e);

            RequestError::FailedToProcessData
        })?;
    let encoded_thumbnail_file_path =
        get_sharded_path(cache_path.clone(), &encoded_file_name).await;

    if !encoded_thumbnail_file_path.exists() {
        let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;

        let mut thumbnail_buffer: Cursor<Vec<u8>> = tokio::task::spawn_blocking(move || {
            let decrypt_reader = SyncChunkDecryptReader::new(encoded_file_path, parent_metadata)
                .map_err(|e| {
                    error!("Failed to create SyncChunkDecryptReader: {}", e);

                    RequestError::FailedToProcessData
                })?;

            let buf_reader = BufReader::new(decrypt_reader);

            let mut buf = Cursor::new(Vec::new());
            let img = image::load(buf_reader, image_format).map_err(|e| {
                error!("Image load error: {}", e);

                RequestError::FailedToProcessData
            })?;

            img.thumbnail(150, 150)
                .write_to(&mut buf, image_format)
                .map_err(|e| {
                    error!("Image write error: {}", e);

                    RequestError::FailedToProcessData
                })?;

            buf.set_position(0);
            Ok::<Cursor<Vec<u8>>, RequestError>(buf)
        })
        .await
        .map_err(|e| {
            error!("Blocking task error: {}", e);

            RequestError::FailedToProcessData
        })??;

        let mut encryptor =
            ChunkEncryptor::new_with_metadata(encoded_thumbnail_file_path, thumbnail_metadata)
                .await
                .map_err(|e| {
                    error!("Failed to create ChunkEncryptor: {}", e);

                    RequestError::FailedToProcessData
                })?;

        encryptor
            .encrypt_stream(&mut thumbnail_buffer)
            .await
            .map_err(|e| {
                error!("Encryption error: {}", e);

                RequestError::FailedToProcessData
            })?;

        Ok(thumbnail_buffer.into_inner())
    } else {
        let mut decryptor = ChunkDecryptor::new(encoded_thumbnail_file_path, thumbnail_metadata)
            .await
            .map_err(|e| {
                error!("Failed to create ChunkDecryptor: {}", e);

                RequestError::FailedToProcessData
            })?;

        let decrypted_thumbnail_data = decryptor.decrypt_all().await.map_err(|e| {
            error!("Decryption error: {}", e);

            RequestError::FailedToProcessData
        })?;

        Ok(decrypted_thumbnail_data)
    }
}
