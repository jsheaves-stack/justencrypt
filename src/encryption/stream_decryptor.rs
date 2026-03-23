use orion::aead;
use rocket::tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
    sync::mpsc::Sender,
};
use std::{error::Error, path::PathBuf};

use crate::encryption::{FileEncryptionMetadata, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE};

pub struct StreamDecryptor {
    file_path: PathBuf,
    metadata: FileEncryptionMetadata,
}

impl StreamDecryptor {
    pub async fn new(
        file_path: PathBuf,
        metadata: FileEncryptionMetadata,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(StreamDecryptor {
            file_path,
            metadata,
        })
    }

    pub fn get_file_path(&self) -> PathBuf {
        self.file_path.clone()
    }

    pub async fn decrypt_range(&mut self, start: u64, end: u64, tx: Sender<Vec<u8>>) {
        trace!("Entering decrypt_range, start: {}, end: {}", start, end);

        let first_chunk_index = start / CHUNK_SIZE as u64;
        let last_chunk_index = end / CHUNK_SIZE as u64;
        let disk_offset = first_chunk_index * ENCRYPTED_CHUNK_SIZE as u64;

        let mut file = match File::open(&self.file_path).await {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open file {:?}: {}", self.file_path, e);
                return;
            }
        };

        if let Err(e) = file.seek(SeekFrom::Start(disk_offset)).await {
            error!("Failed to seek to {}: {}", disk_offset, e);
            return;
        }

        for chunk_index in first_chunk_index..=last_chunk_index {
            let mut encrypted_buffer = vec![0u8; ENCRYPTED_CHUNK_SIZE];
            let mut bytes_read = 0;

            while bytes_read < ENCRYPTED_CHUNK_SIZE {
                match file.read(&mut encrypted_buffer[bytes_read..]).await {
                    Ok(0) => break,
                    Ok(n) => bytes_read += n,
                    Err(e) => {
                        error!("Failed to read chunk {}: {}", chunk_index, e);
                        return;
                    }
                }
            }

            if bytes_read == 0 {
                break;
            }

            let decrypted_payload =
                match aead::open(&self.metadata.key, &encrypted_buffer[..bytes_read]) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to decrypt chunk {}: {:?}", chunk_index, e);
                        return;
                    }
                };

            if decrypted_payload.len() < 8 {
                error!("Decrypted chunk {} is too short", chunk_index);
                return;
            }

            let mut index_bytes = [0u8; 8];
            index_bytes.copy_from_slice(&decrypted_payload[..8]);
            let stored_index = u64::from_le_bytes(index_bytes);
            if stored_index != chunk_index {
                error!(
                    "Chunk index mismatch! Expected {}, got {}",
                    chunk_index, stored_index
                );
                return;
            }

            let decrypted_chunk = &decrypted_payload[8..];

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
                let slice =
                    &decrypted_chunk[slice_start..=slice_end.min(decrypted_chunk.len() - 1)];
                if tx.send(slice.to_vec()).await.is_err() {
                    return;
                }
            }
        }
    }

    pub async fn decrypt_all(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut result = Vec::with_capacity(self.metadata.total_size as usize);
        let mut file = File::open(&self.file_path).await?;

        for chunk_index in 0u64.. {
            let mut encrypted_buffer = vec![0u8; ENCRYPTED_CHUNK_SIZE];
            let mut bytes_read = 0;

            while bytes_read < ENCRYPTED_CHUNK_SIZE {
                let n = file.read(&mut encrypted_buffer[bytes_read..]).await?;
                if n == 0 {
                    break;
                }
                bytes_read += n;
            }

            if bytes_read == 0 {
                break;
            }

            let decrypted_payload = aead::open(&self.metadata.key, &encrypted_buffer[..bytes_read])
                .map_err(|e| {
                    error!("Failed to decrypt chunk {}: {:?}", chunk_index, e);
                    format!("Decryption error at chunk {}", chunk_index)
                })?;

            if decrypted_payload.len() < 8 {
                return Err("Decrypted chunk too short".into());
            }

            let mut index_bytes = [0u8; 8];
            index_bytes.copy_from_slice(&decrypted_payload[..8]);
            let stored_index = u64::from_le_bytes(index_bytes);
            if stored_index != chunk_index {
                return Err(format!(
                    "Chunk index mismatch! Expected {}, got {}",
                    chunk_index, stored_index
                )
                .into());
            }

            result.extend_from_slice(&decrypted_payload[8..]);

            if bytes_read < ENCRYPTED_CHUNK_SIZE {
                break;
            }
        }

        Ok(result)
    }
}
