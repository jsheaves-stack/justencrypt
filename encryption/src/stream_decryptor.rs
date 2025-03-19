use std::{error::Error, path::PathBuf};

use orion::{
    aead::streaming::{Nonce, StreamOpener},
    kdf::Salt,
    kex::SecretKey,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, BufReader},
};

use crate::{
    file_decryptor::FileDecryptor, Auth, DerivedKey, Encryptor, FileEncryptionMetadata, NONCE_SIZE,
    SALT_SIZE,
};

pub struct StreamDecryptor {
    opener: StreamOpener,
    pub file_path: PathBuf,
}

impl Encryptor for StreamDecryptor {}

impl StreamDecryptor {
    pub async fn new(file_path: PathBuf, derived_key: &DerivedKey) -> Result<Self, Box<dyn Error>> {
        let key_file_path = file_path.with_extension("meta");

        let auth = Auth::DerivedKey(
            SecretKey::from_slice(derived_key.key.unprotected_as_bytes().to_vec().as_slice())
                .unwrap(),
            Salt::from_slice(derived_key.salt.as_ref().to_vec().as_slice()).unwrap(),
        );

        let mut file_encryption_metadata_decryptor =
            FileDecryptor::new(&key_file_path, auth).await?;

        let file_encryption_metadata_vec =
            file_encryption_metadata_decryptor.decrypt_file().await?;

        let file_encryption_metadata =
            FileEncryptionMetadata::deserialize(&file_encryption_metadata_vec)?;

        let file = File::open(file_path.clone()).await?;
        let mut reader = BufReader::new(file);

        let mut salt_buf = [0u8; SALT_SIZE];
        let mut nonce_buf = [0u8; NONCE_SIZE];

        reader.read_exact(&mut salt_buf).await?;
        reader.read_exact(&mut nonce_buf).await?;

        let nonce = Nonce::from_slice(&nonce_buf)?;

        let opener = StreamOpener::new(
            &SecretKey::from_slice(file_encryption_metadata.key.as_slice()).unwrap(),
            &nonce,
        )?;

        Ok(StreamDecryptor { opener, file_path })
    }

    pub async fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.opener.open_chunk(data)?.0)
    }
}
