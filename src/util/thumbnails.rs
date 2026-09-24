use std::{
    io::{BufReader, Cursor},
    path::{Path, PathBuf},
};

use image::ImageFormat;
use rocket::{
    http::ContentType,
    tokio::{fs, io::AsyncReadExt, task},
};
use uuid::Uuid;

use crate::{
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor,
        sync_chunk_decryptor::SyncChunkDecryptReader, FileEncryptionMetadata,
    },
    enums::{encryption_error::EncryptionError, request_error::RequestError},
    session::user_session::UserSession,
    util::sharded_path::{get_sharded_path, is_not_found, remove_sharded_path, sync_parent_dir},
};

const THUMBNAIL_SIZE: u32 = 150;

/// The image format for a file, judged by its extension, if thumbnails are
/// supported for it.
pub fn image_format_for(file_path: &Path) -> Option<ImageFormat> {
    let content_type = ContentType::from_extension(
        file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default(),
    )?;

    match content_type {
        _ if content_type == ContentType::JPEG => Some(ImageFormat::Jpeg),
        _ if content_type == ContentType::PNG => Some(ImageFormat::Png),
        _ if content_type == ContentType::GIF => Some(ImageFormat::Gif),
        _ if content_type == ContentType::WEBP => Some(ImageFormat::WebP),
        _ if content_type == ContentType::AVIF => Some(ImageFormat::Avif),
        _ => None,
    }
}

/// Returns the thumbnail of the image at `file_path`, from the encrypted cache
/// if it has a good copy, otherwise by generating it.
///
/// A cache entry that fails to decrypt (for example, one damaged by a crash)
/// is deleted and regenerated. Writing the cache is best-effort: if it fails,
/// the freshly generated thumbnail is still returned.
pub async fn get_or_create_thumbnail(
    session: &UserSession,
    file_path: PathBuf,
    format: ImageFormat,
) -> Result<Vec<u8>, RequestError> {
    let user_path = session.get_user_path();
    let (encoded_file_name, file_metadata) = session.get_file_decryption_data(file_path).await?;
    let thumbnail_metadata = file_metadata
        .derive_thumbnail_metadata(encoded_file_name.as_bytes())
        .map_err(|e| {
            error!("Failed to derive thumbnail metadata: {}", e);

            RequestError::FailedToProcessData
        })?;
    let cache_path = get_sharded_path(user_path.join(".cache"), &encoded_file_name).await;

    if fs::try_exists(&cache_path).await.unwrap_or(false) {
        match read_cached(&cache_path, thumbnail_metadata.clone()).await {
            Ok(thumbnail) => return Ok(thumbnail),
            Err(e) => {
                warn!(
                    "Cached thumbnail for {} is unreadable ({}); regenerating it",
                    encoded_file_name, e
                );

                if let Err(e) = remove_sharded_path(&user_path, &cache_path).await {
                    if !is_not_found(e.as_ref()) {
                        warn!("Failed to remove unreadable thumbnail: {}", e);
                    }
                }
            },
        }
    }

    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;
    let thumbnail = generate(encoded_file_path, file_metadata, format).await?;

    if let Err(e) = write_encrypted_atomically(
        &cache_path,
        thumbnail_metadata,
        &mut Cursor::new(&thumbnail),
    )
    .await
    {
        warn!(
            "Failed to cache the thumbnail for {}: {}",
            encoded_file_name, e
        );
    }

    Ok(thumbnail)
}

/// Encrypts `source` into a temporary file next to `final_path`, makes sure it
/// is on disk, then renames it into place. A rename on the same filesystem is
/// atomic, so `final_path` only ever holds a complete file, even with several
/// writers at once (the last one wins). On error the temporary file is removed
/// and `final_path` is left as it was.
pub async fn write_encrypted_atomically<R: AsyncReadExt + Unpin>(
    final_path: &Path,
    metadata: FileEncryptionMetadata,
    source: &mut R,
) -> Result<(), EncryptionError> {
    let temp_path = final_path.with_file_name(format!("{}.part", Uuid::new_v4()));

    let result = async {
        let mut encryptor = ChunkEncryptor::new_with_metadata(temp_path.clone(), metadata).await?;

        encryptor.encrypt_stream(source, u64::MAX).await?;
        encryptor.sync().await?;
        fs::rename(&temp_path, final_path).await?;
        sync_parent_dir(final_path).await?;

        Ok(())
    }
    .await;

    if result.is_err() {
        let _ = fs::remove_file(&temp_path).await;
    }

    result
}

async fn read_cached(
    cache_path: &Path,
    metadata: FileEncryptionMetadata,
) -> Result<Vec<u8>, EncryptionError> {
    ChunkDecryptor::new(cache_path.to_path_buf(), metadata)
        .await?
        .decrypt_all()
        .await
}

// Decrypts the image and scales it down, off the async runtime.
async fn generate(
    encoded_file_path: PathBuf,
    metadata: FileEncryptionMetadata,
    format: ImageFormat,
) -> Result<Vec<u8>, RequestError> {
    task::spawn_blocking(move || {
        let decrypt_reader =
            SyncChunkDecryptReader::new(encoded_file_path, metadata).map_err(|e| {
                error!("Failed to create SyncChunkDecryptReader: {}", e);

                RequestError::FailedToProcessData
            })?;

        let img = image::load(BufReader::new(decrypt_reader), format).map_err(|e| {
            error!("Image load error: {}", e);

            RequestError::FailedToProcessData
        })?;

        let mut buf = Cursor::new(Vec::new());
        img.thumbnail(THUMBNAIL_SIZE, THUMBNAIL_SIZE)
            .write_to(&mut buf, format)
            .map_err(|e| {
                error!("Image write error: {}", e);

                RequestError::FailedToProcessData
            })?;

        Ok(buf.into_inner())
    })
    .await
    .map_err(|e| {
        error!("Blocking task error: {}", e);

        RequestError::FailedToProcessData
    })?
}
