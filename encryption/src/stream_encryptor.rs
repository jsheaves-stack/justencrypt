use std::{error::Error, path::PathBuf};

use orion::{
    aead::streaming::{Nonce, StreamSealer, StreamTag},
    kdf::Salt,
    kex::SecretKey,
};
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
};

use crate::{
    Auth, DerivedKey, Encryptor, FileEncryptionMetadata, FileEncryptor, BUFFER_SIZE, KEY_LENGTH,
    NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};

pub struct StreamEncryptor {
    file: File,
    sealer: StreamSealer,
    nonce: Nonce,
    salt: Salt,
}

impl Encryptor for StreamEncryptor {}

impl StreamEncryptor {
    pub async fn new(file_path: PathBuf, derived_key: DerivedKey) -> Result<Self, Box<dyn Error>> {
        let secret_key = SecretKey::generate(KEY_LENGTH)?;
        let salt = Salt::generate(SALT_SIZE)?;
        let (sealer, nonce) = StreamSealer::new(&secret_key)?;

        let mut key_encryptor = FileEncryptor::new(
            &file_path.with_extension("meta"),
            Auth::DerivedKey(
                SecretKey::from_slice(derived_key.key.unprotected_as_bytes().to_vec().as_slice())
                    .unwrap(),
                Salt::from_slice(derived_key.salt.as_ref().to_vec().as_slice()).unwrap(),
            ),
        )
        .await?;

        let file_encryption_metadata = FileEncryptionMetadata {
            key: secret_key.unprotected_as_bytes().to_vec(),
            buffer_size: BUFFER_SIZE,
            nonce_size: NONCE_SIZE,
            salt_size: SALT_SIZE,
            tag_size: TAG_SIZE,
        };

        key_encryptor
            .encrypt_file(&file_encryption_metadata.serialize())
            .await?;

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
        })
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
