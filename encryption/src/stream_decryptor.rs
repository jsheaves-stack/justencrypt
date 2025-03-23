use std::{error::Error, path::PathBuf};

use orion::{
    aead::streaming::{Nonce, StreamOpener},
    kdf::Salt,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, BufReader},
};

use crate::{DerivedKey, FileEncryptionMetadata, NONCE_SIZE, SALT_SIZE};

pub struct StreamDecryptor {
    opener: StreamOpener,
    file_path: PathBuf,
}

impl StreamDecryptor {
    pub async fn new(
        file_path: PathBuf,
        metadata: FileEncryptionMetadata,
    ) -> Result<Self, Box<dyn Error>> {
        let file = File::open(file_path.clone()).await?;
        let mut reader = BufReader::new(file);

        let mut salt_buf = [0u8; SALT_SIZE];
        let mut nonce_buf = [0u8; NONCE_SIZE];

        reader.read_exact(&mut salt_buf).await?;
        reader.read_exact(&mut nonce_buf).await?;

        let nonce = Nonce::from_slice(&nonce_buf)?;

        let derived_key = DerivedKey {
            key: metadata.key,
            salt: Salt::from_slice(&salt_buf).unwrap(),
        };

        let opener = StreamOpener::new(&derived_key.key, &nonce)?;

        Ok(StreamDecryptor { opener, file_path })
    }

    pub async fn decrypt_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.opener.open_chunk(data)?.0)
    }

    pub fn get_file_path(&self) -> PathBuf {
        self.file_path.clone()
    }
}
