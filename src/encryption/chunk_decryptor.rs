use std::{path::PathBuf, time::Duration};

use orion::aead;
use rocket::tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
    sync::mpsc::Sender,
    time,
};

use crate::{
    encryption::{FileEncryptionMetadata, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, INDEX_LEN},
    enums::encryption_error::EncryptionError,
};

pub struct ChunkDecryptor {
    file_path: PathBuf,
    metadata: FileEncryptionMetadata,
}

impl ChunkDecryptor {
    pub async fn new(
        file_path: PathBuf,
        metadata: FileEncryptionMetadata,
    ) -> Result<Self, EncryptionError> {
        metadata.check_version()?;

        Ok(ChunkDecryptor {
            file_path,
            metadata,
        })
    }

    /// Reads and decrypts the next chunk, which must be chunk `chunk_index`,
    /// and returns its plaintext; empty at the end of the file.
    async fn decrypt_chunk(
        &self,
        file: &mut File,
        chunk_index: u64,
        encrypted_buffer: &mut [u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let mut bytes_read = 0;

        while bytes_read < ENCRYPTED_CHUNK_SIZE {
            match file.read(&mut encrypted_buffer[bytes_read..]).await {
                Ok(0) => break,
                Ok(n) => bytes_read += n,

                Err(e) => return Err(EncryptionError::Io(e)),
            }
        }

        if bytes_read == 0 {
            return Ok(Vec::new());
        }

        let mut payload =
            aead::open(&self.metadata.key, &encrypted_buffer[..bytes_read]).map_err(|e| {
                error!("Decryption mismatch at chunk {}: {:?}", chunk_index, e);

                EncryptionError::Crypto(e)
            })?;

        if payload.len() < INDEX_LEN {
            return Err(EncryptionError::MalformedChunk(chunk_index));
        }

        let mut index_bytes = [0u8; INDEX_LEN];

        index_bytes.copy_from_slice(&payload[..INDEX_LEN]);

        let stored_index = u64::from_le_bytes(index_bytes);

        if stored_index != chunk_index {
            return Err(EncryptionError::TamperingDetected {
                expected: chunk_index,
                got: stored_index,
            });
        }

        // Strip the index in place rather than copying the plaintext out.
        payload.drain(..INDEX_LEN);

        Ok(payload)
    }

    /// Sends the plaintext bytes `start..=end` to `tx`, one chunk's worth at a
    /// time. Fails with `Truncated` if the file ends before `end`, and with
    /// `Stalled` if a chunk waits longer than `stall_timeout` for the receiver
    /// to make room; a receiver that goes away just ends the stream.
    pub async fn decrypt_range(
        &mut self,
        start: u64,
        end: u64,
        tx: Sender<Vec<u8>>,
        stall_timeout: Duration,
    ) -> Result<(), EncryptionError> {
        let first_chunk_index = start / CHUNK_SIZE as u64;
        let last_chunk_index = end / CHUNK_SIZE as u64;
        let disk_offset = first_chunk_index * ENCRYPTED_CHUNK_SIZE as u64;

        let mut file = match File::open(&self.file_path).await {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open file {:?}: {}", self.file_path, e);

                return Err(EncryptionError::Io(e));
            },
        };

        if let Err(e) = file.seek(SeekFrom::Start(disk_offset)).await {
            error!("Seek error: {}", e);

            return Err(EncryptionError::Io(e));
        }

        let mut encrypted_buffer = vec![0u8; ENCRYPTED_CHUNK_SIZE];
        let mut sent = 0;

        for chunk_index in first_chunk_index..=last_chunk_index {
            let mut chunk = self
                .decrypt_chunk(&mut file, chunk_index, &mut encrypted_buffer)
                .await
                .inspect_err(|e| error!("{}", e))?;

            if chunk.is_empty() {
                break;
            }

            // Keep only the part of this chunk inside `start..=end`.
            let chunk_start = chunk_index * CHUNK_SIZE as u64;
            let keep_until = (end + 1 - chunk_start).min(chunk.len() as u64) as usize;
            let keep_from = start.saturating_sub(chunk_start) as usize;

            if keep_from >= keep_until {
                break;
            }

            chunk.truncate(keep_until);
            chunk.drain(..keep_from);
            sent += chunk.len() as u64;

            match time::timeout(stall_timeout, tx.send(chunk)).await {
                Ok(Ok(())) => {},
                Ok(Err(_)) => return Ok(()),
                Err(_) => return Err(EncryptionError::Stalled(stall_timeout)),
            }
        }

        let expected = end - start + 1;

        if sent < expected {
            let error = EncryptionError::Truncated {
                expected,
                got: sent,
            };

            error!("{} ({:?})", error, self.file_path);

            return Err(error);
        }

        Ok(())
    }

    pub async fn decrypt_all(&mut self) -> Result<Vec<u8>, EncryptionError> {
        let mut result = Vec::with_capacity(self.metadata.total_size as usize);
        let mut file = File::open(&self.file_path).await?;
        let mut encrypted_buffer = vec![0u8; ENCRYPTED_CHUNK_SIZE];

        for chunk_index in 0u64.. {
            let decrypted_chunk = self
                .decrypt_chunk(&mut file, chunk_index, &mut encrypted_buffer)
                .await?;

            if decrypted_chunk.is_empty() {
                break;
            }
            result.extend_from_slice(&decrypted_chunk);
        }

        Ok(result)
    }
}
