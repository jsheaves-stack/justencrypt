use orion::aead;
use rocket::tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use std::{collections::HashSet, error::Error, io::SeekFrom, path::PathBuf};

use crate::encryption::{FileEncryptionMetadata, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE};

pub struct ChunkEncryptor {
    file: File,
    metadata: FileEncryptionMetadata,
}

impl ChunkEncryptor {
    pub async fn new(file_path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let metadata = FileEncryptionMetadata::new();

        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
            .await?;

        Ok(ChunkEncryptor { file, metadata })
    }

    pub fn get_metadata(&self) -> FileEncryptionMetadata {
        self.metadata.clone()
    }

    pub fn finalize_metadata(&mut self, total_size: u64) {
        self.metadata.total_size = total_size;
    }

    pub async fn encrypt_stream_at_offset<R: AsyncReadExt + Unpin>(
        &mut self,
        source: &mut R,
        offset: u64,
        written_chunks: &mut HashSet<u64>,
    ) -> Result<u64, Box<dyn Error>> {
        trace!(
            "Entering ChunkEncryptor::encrypt_stream_at_offset at offset: {}",
            offset
        );

        if offset % (CHUNK_SIZE as u64) != 0 {
            return Err("Offset must be a multiple of CHUNK_SIZE".into());
        }

        let mut current_chunk_index = offset / (CHUNK_SIZE as u64);
        let mut total_bytes_read = 0;

        let physical_offset = current_chunk_index * (ENCRYPTED_CHUNK_SIZE as u64);
        self.file.seek(SeekFrom::Start(physical_offset)).await?;

        let mut plaintext_buffer = vec![0u8; CHUNK_SIZE];
        let mut indexed_plaintext = vec![0u8; 8 + CHUNK_SIZE];

        loop {
            let mut bytes_read = 0;

            while bytes_read < CHUNK_SIZE {
                let n = source.read(&mut plaintext_buffer[bytes_read..]).await?;

                if n == 0 {
                    break;
                }

                bytes_read += n;
            }

            if bytes_read == 0 {
                break;
            }

            indexed_plaintext[..8].copy_from_slice(&current_chunk_index.to_le_bytes());
            indexed_plaintext[8..8 + bytes_read].copy_from_slice(&plaintext_buffer[..bytes_read]);

            let encrypted_chunk =
                aead::seal(&self.metadata.key, &indexed_plaintext[..8 + bytes_read]).map_err(
                    |e| {
                        error!("Encryption error at chunk {}: {:?}", current_chunk_index, e);
                        "Encryption error"
                    },
                )?;

            self.file.write_all(&encrypted_chunk).await?;

            written_chunks.insert(current_chunk_index);

            total_bytes_read += bytes_read as u64;
            current_chunk_index += 1;

            if bytes_read < CHUNK_SIZE {
                break;
            }
        }

        trace!(
            "Exiting ChunkEncryptor::encrypt_stream_at_offset, total_bytes_read: {}",
            total_bytes_read
        );

        Ok(total_bytes_read)
    }

    pub async fn encrypt_stream<R: AsyncReadExt + Unpin>(
        &mut self,
        source: &mut R,
    ) -> Result<u64, Box<dyn Error>> {
        trace!("Entering ChunkEncryptor::encrypt_stream");

        let mut chunk_index: u64 = 0;
        let mut total_plaintext_size: u64 = 0;

        let mut plaintext_buffer = vec![0u8; CHUNK_SIZE];
        let mut indexed_plaintext = vec![0u8; 8 + CHUNK_SIZE];

        loop {
            let mut bytes_read = 0;
            while bytes_read < CHUNK_SIZE {
                let n = source.read(&mut plaintext_buffer[bytes_read..]).await?;
                if n == 0 {
                    break;
                }
                bytes_read += n;
            }

            if bytes_read == 0 {
                break;
            }

            indexed_plaintext[..8].copy_from_slice(&chunk_index.to_le_bytes());
            indexed_plaintext[8..8 + bytes_read].copy_from_slice(&plaintext_buffer[..bytes_read]);

            let encrypted_chunk =
                aead::seal(&self.metadata.key, &indexed_plaintext[..8 + bytes_read]).map_err(
                    |e| {
                        error!("Encryption error at chunk {}: {:?}", chunk_index, e);
                        "Encryption error"
                    },
                )?;

            self.file.write_all(&encrypted_chunk).await?;

            total_plaintext_size += bytes_read as u64;
            chunk_index += 1;

            if bytes_read < CHUNK_SIZE {
                break;
            }
        }

        self.metadata.total_size = total_plaintext_size;
        trace!(
            "Exiting ChunkEncryptor::encrypt_stream, total_size: {}",
            total_plaintext_size
        );

        Ok(total_plaintext_size)
    }
}
