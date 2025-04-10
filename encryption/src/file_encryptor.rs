use std::{error::Error, path::PathBuf};

use orion::aead;
use tokio::{fs::File, io::AsyncWriteExt};

use crate::{derive_key_from_string, Auth, DerivedKey};

pub struct FileEncryptor {
    file: File,
    derived_key: DerivedKey,
}

impl FileEncryptor {
    pub async fn new(file_path: &PathBuf, auth: Auth) -> Result<Self, Box<dyn Error>> {
        let input_file = File::create(file_path).await?;

        let (key, salt) = match auth {
            Auth::Passphrase(passphrase) => {
                let key_salt = derive_key_from_string(&passphrase)?;

                (key_salt.key, key_salt.salt)
            }
            Auth::DerivedKey(key, salt) => (key, salt),
        };

        Ok(FileEncryptor {
            file: input_file,
            derived_key: DerivedKey { key, salt },
        })
    }

    pub async fn encrypt_file(&mut self, file_data: &[u8]) -> Result<(), Box<dyn Error>> {
        let encrypted_data = aead::seal(&self.derived_key.key, file_data)?;

        self.file.write_all(self.derived_key.salt.as_ref()).await?;
        self.file.write_all(encrypted_data.as_slice()).await?;

        Ok(())
    }
}
