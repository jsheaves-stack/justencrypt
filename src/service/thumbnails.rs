//! Thumbnails of a user's images, cached encrypted next to their files.

use std::{
    io::{self, BufReader, Cursor},
    path::{Path, PathBuf},
};

use image::{ImageError, ImageFormat, ImageReader, Limits};
use tokio::{io::AsyncReadExt, sync::Semaphore};

use crate::{
    app::App,
    config::ThumbnailConfig,
    encryption::{
        chunk_decryptor::ChunkDecryptor, chunk_encryptor::ChunkEncryptor,
        sync_chunk_decryptor::SyncChunkDecryptReader, FileEncryptionMetadata,
    },
    enums::{encryption_error::EncryptionError, service_error::ServiceError},
    session::user_session::UserSession,
    storage::{user_context::UserContext, user_storage::BlobFile},
};

const THUMBNAIL_SIZE: u32 = 150;

/// Largest width or height of an image that gets a thumbnail.
const MAX_IMAGE_DIMENSION: u32 = 16_384;

/// A thumbnail and its media type, which is the same as its image's.
pub struct Thumbnail {
    pub mime: &'static str,
    pub bytes: Vec<u8>,
}

/// The image format for a file, judged by its extension (in any case), if
/// thumbnails are supported for it.
pub fn image_format_for(file_path: &Path) -> Option<ImageFormat> {
    let extension = file_path.extension()?.to_str()?.to_ascii_lowercase();

    match extension.as_str() {
        "jpg" | "jpeg" => Some(ImageFormat::Jpeg),
        "png" => Some(ImageFormat::Png),
        "gif" => Some(ImageFormat::Gif),
        "webp" => Some(ImageFormat::WebP),
        "avif" => Some(ImageFormat::Avif),
        _ => None,
    }
}

/// Returns the thumbnail of the image at `file_path`, from the encrypted cache
/// if it has a good copy, otherwise by generating it. The thumbnail has the
/// same format as the image. Fails with `UnsupportedFileType` for a file whose
/// extension isn't a supported image format.
///
/// A cache entry that fails to decrypt (for example, one damaged by a crash)
/// is deleted and regenerated. Writing the cache is best-effort: if it fails,
/// the freshly generated thumbnail is still returned.
pub async fn get(
    app: &App,
    session: &UserSession,
    file_path: PathBuf,
) -> Result<Thumbnail, ServiceError> {
    let format = image_format_for(&file_path).ok_or(ServiceError::UnsupportedFileType)?;
    let mime = format.to_mime_type();
    let config = &app.config.thumbnail;
    let server_permits = &app.thumbnail_semaphore;
    let (encoded_file_name, file_metadata) =
        session.context.get_file_decryption_data(file_path).await?;
    let thumbnail_metadata = file_metadata
        .derive_thumbnail_metadata(encoded_file_name.as_bytes())
        .map_err(|e| {
            error!("Failed to derive thumbnail metadata: {}", e);

            ServiceError::FailedToProcessData
        })?;
    let context = &session.context;

    match context.open_thumbnail(&encoded_file_name).await {
        Ok(file) => match read_cached(file, thumbnail_metadata.clone()).await {
            Ok(bytes) => return Ok(Thumbnail { mime, bytes }),
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

    let bytes = generate(
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
        &mut Cursor::new(&bytes),
    )
    .await
    {
        warn!(
            "Failed to cache the thumbnail for {}: {}",
            encoded_file_name, e
        );
    }

    Ok(Thumbnail { mime, bytes })
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
) -> Result<Vec<u8>, ServiceError> {
    // The user's turn comes first, so a request waiting on its own user never
    // holds one of the server-wide permits other users need.
    let slot = context.reserve_blocking().await?;
    let _server_permit = server_permits
        .acquire()
        .await
        .map_err(|_| ServiceError::FailedToProcessData)?;
    let context = context.clone();

    slot.run(move || {
        let decrypt_reader = context
            .open_blob_on_this_thread(&encoded_file_name)
            .and_then(|file| SyncChunkDecryptReader::new(file, metadata))
            .map_err(|e| {
                error!("Failed to open the image for its thumbnail: {}", e);

                ServiceError::FailedToProcessData
            })?;

        let mut reader = ImageReader::new(BufReader::new(decrypt_reader))
            .with_guessed_format()
            .map_err(|e| {
                error!("Failed to read image header: {}", e);

                ServiceError::FailedToProcessData
            })?;

        if reader.format() != Some(format) {
            debug!(
                "Image content is {:?}, but its extension says {:?}",
                reader.format(),
                format
            );

            return Err(ServiceError::UnsupportedFileType);
        }

        reader.limits(limits);

        let img = reader.decode().map_err(|e| match e {
            ImageError::Limits(e) => {
                debug!("Image exceeds the decode limits: {}", e);

                ServiceError::ImageTooLarge
            },
            e => {
                error!("Image load error: {}", e);

                ServiceError::FailedToProcessData
            },
        })?;

        let mut buf = Cursor::new(Vec::new());
        img.thumbnail(THUMBNAIL_SIZE, THUMBNAIL_SIZE)
            .write_to(&mut buf, format)
            .map_err(|e| {
                error!("Image write error: {}", e);

                ServiceError::FailedToProcessData
            })?;

        Ok(buf.into_inner())
    })
    .await?
}
