use std::path::PathBuf;

use orion::aead;
use rocket::tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
    sync::mpsc::Sender,
};

use crate::{
    encryption::{FileEncryptionMetadata, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE},
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
        Ok(ChunkDecryptor {
            file_path,
            metadata,
        })
    }

    pub fn get_file_path(&self) -> PathBuf {
        self.file_path.clone()
    }

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

        let decrypted_payload = aead::open(&self.metadata.key, &encrypted_buffer[..bytes_read])
            .map_err(|e| {
                error!("Decryption mismatch at chunk {}: {:?}", chunk_index, e);

                EncryptionError::Crypto(e)
            })?;

        if decrypted_payload.len() < 8 {
            return Err(EncryptionError::MalformedChunk(chunk_index));
        }

        let mut index_bytes = [0u8; 8];

        index_bytes.copy_from_slice(&decrypted_payload[..8]);

        let stored_index = u64::from_le_bytes(index_bytes);

        if stored_index != chunk_index {
            return Err(EncryptionError::TamperingDetected {
                expected: chunk_index,
                got: stored_index,
            });
        }

        Ok(decrypted_payload[8..].to_vec())
    }

    pub async fn decrypt_range(
        &mut self,
        start: u64,
        end: u64,
        tx: Sender<Vec<u8>>,
    ) -> Result<(), EncryptionError> {
        trace!("Entering ChunkDecryptor::decrypt_range, {}-{}", start, end);

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

        for chunk_index in first_chunk_index..=last_chunk_index {
            let decrypted_chunk = match self
                .decrypt_chunk(&mut file, chunk_index, &mut encrypted_buffer)
                .await
            {
                Ok(data) if data.is_empty() => break,
                Ok(data) => data,
                Err(e) => {
                    error!("{}", e);

                    return Err(e);
                },
            };

            let chunk_start_plaintext = chunk_index * CHUNK_SIZE as u64;
            let chunk_end_plaintext = chunk_start_plaintext + decrypted_chunk.len() as u64 - 1;

            let slice_start = if start > chunk_start_plaintext {
                (start - chunk_start_plaintext) as usize
            } else {
                0
            };

            let slice_end = if end < chunk_end_plaintext {
                (end - chunk_start_plaintext) as usize
            } else {
                decrypted_chunk.len() - 1
            };

            if slice_start <= slice_end && slice_start < decrypted_chunk.len() {
                let final_slice =
                    &decrypted_chunk[slice_start..=slice_end.min(decrypted_chunk.len() - 1)];

                if tx.send(final_slice.to_vec()).await.is_err() {
                    break;
                }
            }
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
