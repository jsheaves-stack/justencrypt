use crate::enums::request_error::RequestError;
use encryption::{
    stream_decryptor::StreamDecryptor, stream_encryptor::StreamEncryptor, BUFFER_SIZE, TAG_SIZE,
};
use rocket::tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
    sync::mpsc,
};

pub async fn encrypt_source_to_encryptor<R: AsyncReadExt + Unpin>(
    source: &mut R,
    encryptor: &mut StreamEncryptor,
) -> Result<(), RequestError> {
    trace!("Entering encrypt_source_to_encryptor");

    // Write encryption metadata (salt and nonce) to the file.
    if let Err(e) = encryptor.write_salt_and_nonce().await {
        error!("Failed to write salt and nonce chunks: {}", e);
        return Err(RequestError::FailedToWriteData);
    }

    trace!("Salt and nonce written.");

    let mut read_buffer = [0u8; BUFFER_SIZE];
    let mut current_buffer_fill = 0;

    loop {
        // Read a chunk of data from the source.
        let bytes_read = match source.read(&mut read_buffer[current_buffer_fill..]).await {
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read chunk from source stream: {}", e);
                return Err(RequestError::FailedToWriteData);
            }
        };

        current_buffer_fill += bytes_read;

        trace!(
            "Read {} bytes from source. Current buffer fill {}/{}",
            bytes_read,
            current_buffer_fill,
            BUFFER_SIZE
        );

        let final_chunk = bytes_read == 0 && current_buffer_fill > 0;

        if current_buffer_fill == BUFFER_SIZE || final_chunk {
            // Encrypt the chunk.
            let encrypted_chunk = match encryptor.encrypt_chunk(&read_buffer[..BUFFER_SIZE]).await {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to encrypt chunk: {}", e);
                    return Err(RequestError::FailedToWriteData);
                }
            };

            // Write the encrypted chunk to the encryptor's file.
            match encryptor.write_chunk(encrypted_chunk).await {
                Ok(_) => trace!("Encrypted chunk written to file."),
                Err(e) => {
                    error!("Failed to write encrypted chunk: {}", e);
                    return Err(RequestError::FailedToWriteData);
                }
            }

            if final_chunk {
                break;
            }

            current_buffer_fill = 0;
        }
    }

    trace!("Exiting encrypt_source_to_encryptor");

    Ok(())
}

pub async fn decrypt_stream_to_writer<
    R: AsyncReadExt + AsyncSeekExt + Unpin,
    W: AsyncWriteExt + Unpin,
>(
    source: &mut R,
    decryptor: &mut StreamDecryptor,
    writer: &mut W,
    offset: u64,
) -> Result<(), RequestError> {
    trace!("Entering decrypt_stream_to_writer");

    // Skip the encryption metadata (salt and nonce).
    if let Err(e) = source.seek(SeekFrom::Start(offset)).await {
        error!("Failed to seek in file: {}", e);
        return Err(RequestError::FailedToWriteData);
    }

    trace!("Seeked past metadata (offset: {}).", offset);

    let mut encrypted_read_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

    loop {
        // Read a chunk of data from the encrypted file.
        let bytes_read = match source.read(&mut encrypted_read_buffer).await {
            Ok(0) => {
                trace!("End of encrypted file.");
                break; // End of file
            }
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read encrypted file chunk: {}", e);
                return Err(RequestError::FailedToWriteData);
            }
        };

        trace!("Read {} encrypted bytes from file.", bytes_read);

        // Decrypt the chunk.
        let decrypted_chunk = match decryptor
            .decrypt_chunk(&encrypted_read_buffer[..bytes_read])
            .await
        {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to decrypt file chunk: {}", e);
                return Err(RequestError::FailedToWriteData);
            }
        };

        if decrypted_chunk.is_empty() {
            trace!("Decrypted chunk is empty, assuming end of stream.");
            break;
        }

        trace!("Decrypted chunk of size {}.", decrypted_chunk.len());

        // Write the decrypted chunk to the destination writer.
        if let Err(e) = writer.write_all(&decrypted_chunk).await {
            error!("Failed to write decrypted chunk to writer: {}", e);
            return Err(RequestError::FailedToWriteData);
        }
    }

    trace!("Exiting decrypt_stream_to_writer");

    Ok(())
}

pub async fn decrypt_stream_to_channel<R: AsyncReadExt + AsyncSeekExt + Unpin + Send + 'static>(
    mut source: R,
    mut decryptor: StreamDecryptor,
    tx: mpsc::Sender<Vec<u8>>,
    offset: u64,
) {
    trace!("Entering spawned task: decrypt_stream_to_channel");

    // Skip the encryption metadata (salt and nonce).
    if let Err(e) = source.seek(SeekFrom::Start(offset)).await {
        error!("Failed to seek in file: {}", e);
        return;
    }

    trace!("Seeked past metadata (offset: {}).", offset);

    let mut encrypted_read_buffer = [0u8; BUFFER_SIZE + TAG_SIZE];

    loop {
        // Read a chunk of data from the encrypted file.
        let bytes_read = match source.read(&mut encrypted_read_buffer).await {
            Ok(0) => {
                trace!("End of encrypted file.");
                break; // End of file
            }
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read encrypted file chunk: {}", e);
                return;
            }
        };

        trace!("Read {} encrypted bytes from file.", bytes_read);

        // Decrypt the chunk.
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

        if decrypted_chunk.is_empty() {
            trace!("Decrypted chunk is empty, assuming end of stream.");
            break;
        }

        trace!("Decrypted chunk of size {}.", decrypted_chunk.len());

        // Send the decrypted chunk for streaming.
        if tx.send(decrypted_chunk).await.is_err() {
            info!("Failed to send decrypted chunk: channel closed (client likely disconnected).");
            return;
        }

        trace!("Sent decrypted chunk to stream.");
    }

    trace!("Finished processing all chunks in decryption task.");
}
