use crate::enums::request_error::RequestError;
use encryption::{
    stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor, BUFFER_SIZE, TAG_SIZE,
};
use rocket::tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

/// Reads from an encrypted stream, decrypts it, and writes all data to the provided `writer`.
/// Skips `skip_offset` bytes at the beginning of the reader (e.g., for salt and nonce).
pub async fn decrypt_stream_to_writer<
    R: AsyncReadExt + AsyncSeekExt + Unpin,
    W: AsyncWriteExt + Unpin,
>(
    mut reader: R,
    decryptor: &mut StreamDecryptor,
    mut writer: W,
    skip_offset: u64,
) -> Result<(), RequestError> {
    if skip_offset > 0 {
        reader
            .seek(SeekFrom::Start(skip_offset))
            .await
            .map_err(|e| {
                error!("Failed to seek in input stream: {}", e);
                RequestError::FailedToProcessData
            })?;
    }

    let mut encrypted_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

    loop {
        let bytes_read = reader.read(&mut encrypted_buffer[..]).await.map_err(|e| {
            error!("Failed to read from input stream: {}", e);
            RequestError::FailedToProcessData
        })?;

        if bytes_read == 0 {
            break;
        }

        let decrypted_chunk = decryptor
            .decrypt_chunk(&encrypted_buffer[..bytes_read])
            .await
            .map_err(|e| {
                error!("Failed to decrypt chunk: {}", e);
                RequestError::FailedToProcessData
            })?;

        if decrypted_chunk.is_empty() {
            break;
        }
        writer.write_all(&decrypted_chunk).await.map_err(|e| {
            error!("Failed to write decrypted chunk to output stream: {}", e);
            RequestError::FailedToWriteData
        })?;
    }
    Ok(())
}

/// Reads plaintext data from `source_reader`, encrypts it chunk by chunk,
/// and writes it using the provided `StreamEncryptor`.
/// The caller is responsible for calling `encryptor.write_salt_and_nonce().await` *before* this function.
pub async fn encrypt_source_to_encryptor<R: AsyncReadExt + Unpin>(
    mut source_reader: R,
    encryptor: &mut StreamEncryptor,
) -> Result<(), RequestError> {
    let mut plaintext_buffer = [0u8; BUFFER_SIZE];

    loop {
        let bytes_read = source_reader
            .read(&mut plaintext_buffer[..])
            .await
            .map_err(|e| {
                error!("Failed to read from source_reader: {}", e);
                RequestError::FailedToProcessData
            })?;

        if bytes_read == 0 {
            break;
        }

        let encrypted_chunk = encryptor
            .encrypt_chunk(&plaintext_buffer[..bytes_read])
            .await
            .map_err(|e| {
                error!("Failed to encrypt chunk: {}", e);
                RequestError::FailedToProcessData
            })?;

        encryptor.write_chunk(encrypted_chunk).await.map_err(|e| {
            error!("Failed to write encrypted chunk: {}", e);
            RequestError::FailedToWriteData
        })?;
    }
    Ok(())
}
