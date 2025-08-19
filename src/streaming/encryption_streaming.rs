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
    trace!(
        "Entering encryption_streaming::decrypt_stream_to_writer with skip_offset: {}",
        skip_offset
    );
    if skip_offset > 0 {
        reader
            .seek(SeekFrom::Start(skip_offset))
            .await
            .map_err(|e| {
                error!("Failed to seek in input stream: {}", e);
                RequestError::FailedToProcessData
            })?;
        trace!("Seeked {} bytes in the input stream.", skip_offset);
    }

    let mut encrypted_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

    loop {
        let bytes_read = reader.read(&mut encrypted_buffer[..]).await.map_err(|e| {
            error!("Failed to read from input stream: {}", e);
            RequestError::FailedToProcessData
        })?;
        trace!("Read {} encrypted bytes from stream.", bytes_read);

        if bytes_read == 0 {
            trace!("End of stream reached.");
            break;
        }

        let decrypted_chunk = decryptor
            .decrypt_chunk(&encrypted_buffer[..bytes_read])
            .await
            .map_err(|e| {
                error!("Failed to decrypt chunk: {}", e);
                RequestError::FailedToProcessData
            })?;
        trace!("Decrypted chunk of size {}.", decrypted_chunk.len());

        if decrypted_chunk.is_empty() {
            trace!("Decrypted chunk is empty, assuming end of stream.");
            break;
        }
        writer.write_all(&decrypted_chunk).await.map_err(|e| {
            error!("Failed to write decrypted chunk to output stream: {}", e);
            RequestError::FailedToWriteData
        })?;
        trace!("Wrote decrypted chunk to writer.");
    }
    trace!("Exiting encryption_streaming::decrypt_stream_to_writer successfully.");
    Ok(())
}

/// Reads plaintext data from `source_reader`, encrypts it chunk by chunk,
/// and writes it using the provided `StreamEncryptor`.
/// The caller is responsible for calling `encryptor.write_salt_and_nonce().await` *before* this function.
pub async fn encrypt_source_to_encryptor<R: AsyncReadExt + Unpin>(
    mut source_reader: R,
    encryptor: &mut StreamEncryptor,
) -> Result<(), RequestError> {
    trace!("Entering encryption_streaming::encrypt_source_to_encryptor");
    let mut plaintext_buffer = [0u8; BUFFER_SIZE];

    loop {
        let bytes_read = source_reader
            .read(&mut plaintext_buffer[..])
            .await
            .map_err(|e| {
                error!("Failed to read from source_reader: {}", e);
                RequestError::FailedToProcessData
            })?;
        trace!("Read {} plaintext bytes from source.", bytes_read);

        if bytes_read == 0 {
            trace!("End of source stream reached.");
            break;
        }

        let encrypted_chunk = encryptor
            .encrypt_chunk(&plaintext_buffer[..bytes_read])
            .await
            .map_err(|e| {
                error!("Failed to encrypt chunk: {}", e);
                RequestError::FailedToProcessData
            })?;
        trace!("Encrypted chunk of size {}.", encrypted_chunk.len());

        encryptor.write_chunk(encrypted_chunk).await.map_err(|e| {
            error!("Failed to write encrypted chunk: {}", e);
            RequestError::FailedToWriteData
        })?;
        trace!("Wrote encrypted chunk using encryptor.");
    }
    trace!("Exiting encryption_streaming::encrypt_source_to_encryptor successfully.");
    Ok(())
}
