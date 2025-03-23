use std::{error::Error, path::PathBuf};

use orion::{aead, kdf::Salt, kex::SecretKey};
use tokio::{fs::File, io::AsyncReadExt};

use crate::{derive_key_from_string_and_salt, Auth, DerivedKey, SALT_SIZE};

pub struct FileDecryptor {
    file: File,
    key_salt: DerivedKey,
}

impl FileDecryptor {
    pub async fn new(file_path: &PathBuf, auth: Auth) -> Result<Self, Box<dyn Error>> {
        let mut input_file = File::open(file_path).await?;
        let mut salt_buf = [0u8; SALT_SIZE];

        input_file.read_exact(&mut salt_buf).await?;

        let salt = Salt::from_slice(&salt_buf)?;

        let key = match auth {
            Auth::Passphrase(passphrase) => {
                let derived = derive_key_from_string_and_salt(&passphrase, &salt)?;
                derived.key
            }
            Auth::DerivedKey(key, _) => SecretKey::from_slice(key.unprotected_as_bytes())?,
        };

        let key_salt = DerivedKey {
            key: SecretKey::from_slice(key.unprotected_as_bytes().to_vec().as_slice()).unwrap(),
            salt: Salt::from_slice(salt.as_ref().to_vec().as_slice()).unwrap(),
        };

        Ok(FileDecryptor {
            file: input_file,
            key_salt,
        })
    }

    pub async fn decrypt_file(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut file_buffer = vec![];

        self.file.read_to_end(&mut file_buffer).await?;

        let decrypted_data = aead::open(&self.key_salt.key, &file_buffer)?;

        Ok(decrypted_data)
    }
}
