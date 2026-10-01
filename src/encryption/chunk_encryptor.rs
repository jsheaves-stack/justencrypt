use std::{collections::BTreeMap, io::SeekFrom, path::PathBuf};

use orion::aead;
use rocket::tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};

use crate::{
    encryption::{encrypted_len, FileEncryptionMetadata, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE},
    enums::encryption_error::EncryptionError,
};

pub struct ChunkEncryptor {
    file: File,
    metadata: FileEncryptionMetadata,
}

impl ChunkEncryptor {
    pub async fn new(file_path: PathBuf) -> Result<Self, EncryptionError> {
        Self::new_with_metadata(file_path, FileEncryptionMetadata::new()).await
    }

    pub async fn new_with_metadata(
        file_path: PathBuf,
        metadata: FileEncryptionMetadata,
    ) -> Result<Self, EncryptionError> {
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

    /// Completes a chunked upload of `total_size` plaintext bytes. The file is
    /// cut to exactly the encrypted length of that size, which drops anything
    /// left past the end by an earlier, longer write of the last chunk.
    pub async fn seal(&mut self, total_size: u64) -> Result<(), EncryptionError> {
        self.file.set_len(encrypted_len(total_size)).await?;
        self.sync().await?;
        self.metadata.total_size = total_size;

        Ok(())
    }

    /// Writes everything out and waits until it is on disk, so the file
    /// survives a crash or power loss from here on.
    pub async fn sync(&mut self) -> Result<(), EncryptionError> {
        self.file.flush().await?;
        self.file.sync_all().await?;

        Ok(())
    }

    /// Encrypts `source` into the file starting at plaintext `offset`, and
    /// records the plaintext length of every chunk written in
    /// `written_chunks`. Fails with `TooLarge`, before writing the offending
    /// chunk, once more than `max_bytes` have been read.
    pub async fn encrypt_stream_at_offset<R: AsyncReadExt + Unpin>(
        &mut self,
        source: &mut R,
        offset: u64,
        max_bytes: u64,
        written_chunks: &mut BTreeMap<u64, u32>,
    ) -> Result<u64, EncryptionError> {
        if !offset.is_multiple_of(CHUNK_SIZE as u64) {
            return Err(EncryptionError::InvalidOffset(
                "Offset must be a multiple of CHUNK_SIZE".to_string(),
            ));
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

            if total_bytes_read + bytes_read as u64 > max_bytes {
                self.file.flush().await?;

                return Err(EncryptionError::TooLarge);
            }

            indexed_plaintext[..8].copy_from_slice(&current_chunk_index.to_le_bytes());
            indexed_plaintext[8..8 + bytes_read].copy_from_slice(&plaintext_buffer[..bytes_read]);

            let encrypted_chunk =
                aead::seal(&self.metadata.key, &indexed_plaintext[..8 + bytes_read]).map_err(
                    |e| {
                        error!("Encryption error at chunk {}: {:?}", current_chunk_index, e);

                        EncryptionError::Crypto(e)
                    },
                )?;

            self.file.write_all(&encrypted_chunk).await?;

            written_chunks.insert(current_chunk_index, bytes_read as u32);

            total_bytes_read += bytes_read as u64;
            current_chunk_index += 1;

            if bytes_read < CHUNK_SIZE {
                break;
            }
        }

        self.file.flush().await?;

        Ok(total_bytes_read)
    }

    /// Encrypts all of `source` into the file. Fails with `TooLarge`, before
    /// writing the offending chunk, once more than `max_bytes` have been read.
    pub async fn encrypt_stream<R: AsyncReadExt + Unpin>(
        &mut self,
        source: &mut R,
        max_bytes: u64,
    ) -> Result<u64, EncryptionError> {
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

            if total_plaintext_size + bytes_read as u64 > max_bytes {
                self.file.flush().await?;

                return Err(EncryptionError::TooLarge);
            }

            indexed_plaintext[..8].copy_from_slice(&chunk_index.to_le_bytes());
            indexed_plaintext[8..8 + bytes_read].copy_from_slice(&plaintext_buffer[..bytes_read]);

            let encrypted_chunk =
                aead::seal(&self.metadata.key, &indexed_plaintext[..8 + bytes_read]).map_err(
                    |e| {
                        error!("Encryption error at chunk {}: {:?}", chunk_index, e);

                        EncryptionError::Crypto(e)
                    },
                )?;

            self.file.write_all(&encrypted_chunk).await?;

            total_plaintext_size += bytes_read as u64;
            chunk_index += 1;

            if bytes_read < CHUNK_SIZE {
                break;
            }
        }

        self.file.flush().await?;

        self.metadata.total_size = total_plaintext_size;

        Ok(total_plaintext_size)
    }
}
