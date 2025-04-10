use std::{error::Error, path::PathBuf};

use orion::{
    aead::streaming::{Nonce, StreamSealer, StreamTag},
    kdf::Salt,
    kex::SecretKey,
};
use tokio::{
    fs::{self, File, OpenOptions},
    io::AsyncWriteExt,
};

use crate::{FileEncryptionMetadata, BUFFER_SIZE, KEY_LENGTH, NONCE_SIZE, SALT_SIZE, TAG_SIZE};

pub struct StreamEncryptor {
    file: File,
    sealer: StreamSealer,
    nonce: Nonce,
    salt: Salt,
    metadata: FileEncryptionMetadata,
}

impl StreamEncryptor {
    pub async fn new(file_path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let secret_key = SecretKey::generate(KEY_LENGTH)?;
        let salt = Salt::generate(SALT_SIZE)?;
        let (sealer, nonce) = StreamSealer::new(&secret_key)?;

        let metadata = FileEncryptionMetadata {
            key: secret_key,
            buffer_size: BUFFER_SIZE,
            nonce_size: NONCE_SIZE,
            salt_size: SALT_SIZE,
            tag_size: TAG_SIZE,
        };

        let file_path_parts = file_path.parent().unwrap();

        fs::create_dir_all(file_path_parts).await?;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
            .await?;

        Ok(StreamEncryptor {
            sealer,
            nonce,
            salt,
            file,
            metadata,
        })
    }

    pub fn get_file_encryption_metadata(&self) -> FileEncryptionMetadata {
        self.metadata.clone()
    }

    // Function to write salt and nonce to the output file
    pub async fn write_salt_and_nonce(&mut self) -> Result<(), Box<dyn Error>> {
        self.file.write_all(self.salt.as_ref()).await?;
        self.file.write_all(self.nonce.as_ref()).await?;

        Ok(())
    }

    // Encrypt a single chunk of data
    pub async fn encrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let stream_tag = if data.len() < BUFFER_SIZE {
            StreamTag::Finish
        } else {
            StreamTag::Message
        };

        let chunk = self.sealer.seal_chunk(data, &stream_tag)?;

        Ok(chunk)
    }

    pub async fn write_chunk(&mut self, data: Vec<u8>) -> Result<(), Box<dyn Error>> {
        self.file.write_all(&data).await?;

        Ok(())
    }
}
