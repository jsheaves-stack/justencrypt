use orion::aead;
use rocket::tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};
use std::{error::Error, path::PathBuf};

use crate::encryption::{FileEncryptionMetadata, CHUNK_SIZE};

pub struct StreamEncryptor {
    file: File,
    metadata: FileEncryptionMetadata,
}

impl StreamEncryptor {
    pub async fn new(file_path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let metadata = FileEncryptionMetadata::new();

        let file_path_parts = file_path.parent().expect("Failed to get parent directory");
        fs::create_dir_all(file_path_parts).await?;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
            .await?;

        Ok(StreamEncryptor { file, metadata })
    }

    pub fn get_metadata(&self) -> FileEncryptionMetadata {
        self.metadata.clone()
    }

    pub async fn encrypt_stream<R: AsyncReadExt + Unpin>(
        &mut self,
        source: &mut R,
    ) -> Result<u64, Box<dyn Error>> {
        trace!("Entering encrypt_stream");

        let mut chunk_index: u64 = 0;
        let mut total_plaintext_size: u64 = 0;
        let mut buffer = vec![0u8; CHUNK_SIZE];

        loop {
            let mut bytes_read = 0;
            while bytes_read < CHUNK_SIZE {
                let n = source.read(&mut buffer[bytes_read..]).await?;
                if n == 0 {
                    break;
                }
                bytes_read += n;
            }

            if bytes_read == 0 {
                break;
            }

            let mut plaintext_with_index = Vec::with_capacity(8 + bytes_read);
            plaintext_with_index.extend_from_slice(&chunk_index.to_le_bytes());
            plaintext_with_index.extend_from_slice(&buffer[..bytes_read]);

            let encrypted_chunk =
                aead::seal(&self.metadata.key, &plaintext_with_index).map_err(|e| {
                    error!("Encryption error at chunk {}: {:?}", chunk_index, e);
                    "Encryption error"
                })?;

            self.file.write_all(&encrypted_chunk).await?;

            total_plaintext_size += bytes_read as u64;
            chunk_index += 1;

            if bytes_read < CHUNK_SIZE {
                break;
            }
        }

        self.metadata.total_size = total_plaintext_size;
        trace!("Exiting encrypt_stream, total_size: {}", total_plaintext_size);

        Ok(total_plaintext_size)
    }
}
