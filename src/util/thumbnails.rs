use std::{
    io::{self, BufReader, Cursor},
    path::{Path, PathBuf},
};

use image::{ImageError, ImageFormat, ImageReader, Limits};
use rocket::{
    http::ContentType,
    tokio::{io::AsyncReadExt, sync::Semaphore},
};

use crate::{
    config::ThumbnailConfig,
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor,
        sync_chunk_decryptor::SyncChunkDecryptReader, FileEncryptionMetadata,
    },
    enums::{encryption_error::EncryptionError, request_error::RequestError},
    session::{user_context::UserContext, user_session::UserSession, user_storage::BlobFile},
};

const THUMBNAIL_SIZE: u32 = 150;

/// Largest width or height of an image that gets a thumbnail.
const MAX_IMAGE_DIMENSION: u32 = 16_384;

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

/// Returns the thumbnail of the image at `file_path` and its content type,
/// from the encrypted cache if it has a good copy, otherwise by generating it.
/// The thumbnail has the same format as the image.
///
/// A cache entry that fails to decrypt (for example, one damaged by a crash)
/// is deleted and regenerated. Writing the cache is best-effort: if it fails,
/// the freshly generated thumbnail is still returned.
pub async fn get_or_create_thumbnail(
    session: &UserSession,
    file_path: PathBuf,
    format: ImageFormat,
    config: &ThumbnailConfig,
    server_permits: &Semaphore,
) -> Result<(ContentType, Vec<u8>), RequestError> {
    let content_type =
        ContentType::parse_flexible(format.to_mime_type()).unwrap_or(ContentType::Binary);
    let (encoded_file_name, file_metadata) = session.get_file_decryption_data(file_path).await?;
    let thumbnail_metadata = file_metadata
        .derive_thumbnail_metadata(encoded_file_name.as_bytes())
        .map_err(|e| {
            error!("Failed to derive thumbnail metadata: {}", e);

            RequestError::FailedToProcessData
        })?;
    let context = &session.context;

    match context.open_thumbnail(&encoded_file_name).await {
        Ok(file) => match read_cached(file, thumbnail_metadata.clone()).await {
            Ok(thumbnail) => return Ok((content_type, thumbnail)),
            Err(e) => {
                warn!(
                    "Cached thumbnail for {} is unreadable ({}); regenerating it",
                    encoded_file_name, e
                );

                if let Err(e) = context.remove_thumbnail(&encoded_file_name).await {
                    if e.kind() != io::ErrorKind::NotFound {
                        warn!("Failed to remove unreadable thumbnail: {}", e);
                    }
                }
            },
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(e) => warn!(
            "Failed to open the cached thumbnail for {}: {}",
            encoded_file_name, e
        ),
    }

    let thumbnail = generate(
        context,
        server_permits,
        encoded_file_name.clone(),
        file_metadata,
        format,
        decode_limits(config),
    )
    .await?;

    if let Err(e) = write_encrypted_atomically(
        context,
        &encoded_file_name,
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

    Ok((content_type, thumbnail))
}

/// The image decoder's limits: the largest dimensions, and memory per `config`.
fn decode_limits(config: &ThumbnailConfig) -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(config.max_decode_memory.as_u64());

    limits
}

/// Encrypts `source` as the cached thumbnail of the encrypted file `name`: into
/// a temporary file, made sure to be on disk, then renamed into place. A
/// rename on the same filesystem is atomic, so the cache only ever holds a
/// complete thumbnail, even with several writers at once (the last one wins).
/// On error the temporary file is removed and the cache is left as it was.
pub async fn write_encrypted_atomically<R: AsyncReadExt + Unpin>(
    context: &UserContext,
    name: &str,
    metadata: FileEncryptionMetadata,
    source: &mut R,
) -> Result<(), EncryptionError> {
    let temp = context.create_thumbnail_temp(name).await?;

    let result = async {
        let mut encryptor = ChunkEncryptor::new_with_metadata(temp.file().clone(), metadata)?;

        encryptor.encrypt_stream(source, u64::MAX).await?;
        encryptor.sync().await?;
        temp.commit().await?;

        Ok(())
    }
    .await;

    if result.is_err() {
        temp.discard().await;
    }

    result
}

/// Decrypts a cached thumbnail.
async fn read_cached(
    file: BlobFile,
    metadata: FileEncryptionMetadata,
) -> Result<Vec<u8>, EncryptionError> {
    ChunkDecryptor::new(file, metadata)?.decrypt_all().await
}

// Decrypts the image and scales it down, on one of the user's blocking
// threads, and while holding one of the server-wide `server_permits` that cap
// how many images are decoded at once. The content must be in the format its
// extension names, and decoding it must fit within `limits`.
async fn generate(
    context: &UserContext,
    server_permits: &Semaphore,
    encoded_file_name: String,
    metadata: FileEncryptionMetadata,
    format: ImageFormat,
    limits: Limits,
) -> Result<Vec<u8>, RequestError> {
    // The user's turn comes first, so a request waiting on its own user never
    // holds one of the server-wide permits other users need.
    let slot = context.reserve_blocking().await?;
    let _server_permit = server_permits
        .acquire()
        .await
        .map_err(|_| RequestError::FailedToProcessData)?;
    let context = context.clone();

    slot.run(move || {
        let decrypt_reader = context
            .open_blob_on_this_thread(&encoded_file_name)
            .and_then(|file| SyncChunkDecryptReader::new(file, metadata))
            .map_err(|e| {
                error!("Failed to open the image for its thumbnail: {}", e);

                RequestError::FailedToProcessData
            })?;

        let mut reader = ImageReader::new(BufReader::new(decrypt_reader))
            .with_guessed_format()
            .map_err(|e| {
                error!("Failed to read image header: {}", e);

                RequestError::FailedToProcessData
            })?;

        if reader.format() != Some(format) {
            debug!(
                "Image content is {:?}, but its extension says {:?}",
                reader.format(),
                format
            );

            return Err(RequestError::UnsupportedFileType);
        }

        reader.limits(limits);

        let img = reader.decode().map_err(|e| match e {
            ImageError::Limits(e) => {
                debug!("Image exceeds the decode limits: {}", e);

                RequestError::ImageTooLarge
            },
            e => {
                error!("Image load error: {}", e);

                RequestError::FailedToProcessData
            },
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
    .await?
}
