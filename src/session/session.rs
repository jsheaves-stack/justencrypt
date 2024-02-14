use std::{collections::HashMap, error::Error, path::PathBuf, str::FromStr};

use encryption::{FileDecryptor, FileEncryptor};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct UserManifest {
    pub files: HashMap<String, String>,
}

pub struct AppSession {
    pub user_name: String,
    pub passphrase: SecretString,
    pub user_path: PathBuf,
    pub manifest: UserManifest,
}

impl AppSession {
    pub async fn open<'a>(
        user_name: &String,
        passphrase: &SecretString,
    ) -> Result<Box<Self>, String> {
        let user_path = PathBuf::from(format!("./user_data/{}", user_name));

        if user_path.exists() {
            let mut decryptor = FileDecryptor::new(&user_path.join("user.manifest"), passphrase)
                .await
                .unwrap();

            let decrypted_file = decryptor.decrypt_file().await.unwrap();

            let manifest = match serde_json::from_slice(&decrypted_file) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };

            Ok(Box::new(Self {
                user_name: user_name.to_string(),
                passphrase: SecretString::from_str(passphrase.expose_secret()).unwrap(),
                user_path,
                manifest,
            }))
        } else {
            Err(String::from("Failed to find user data."))
        }
    }

    pub async fn update_manifest(self: &mut Self) -> Result<(), Box<dyn Error>> {
        let mut encryptor =
            FileEncryptor::new(&self.user_path.join("user.manifest"), &self.passphrase).await?;

        let json = serde_json::to_string(&self.manifest)?;

        encryptor.encrypt_file(json.as_bytes()).await?;

        Ok(())
    }
}
