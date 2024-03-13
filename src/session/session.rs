use std::{
    collections::HashMap,
    error::Error,
    path::{Path, PathBuf},
    str::FromStr,
};

use encryption::{FileDecryptor, FileEncryptor};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::enums::request_error::RequestError;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileSystemNode {
    is_file: bool,
    encoded_name: Option<String>, // Encoded name (only for files)
    file_extension: Option<String>,
    children: HashMap<String, FileSystemNode>, // Children nodes
}

impl FileSystemNode {
    fn new_file(encoded_file_name: String, file_extension: String) -> Self {
        FileSystemNode {
            is_file: true,
            encoded_name: Some(encoded_file_name),
            file_extension: Some(file_extension),
            children: HashMap::new(), // Files have no children
        }
    }

    fn new_folder() -> Self {
        FileSystemNode {
            is_file: false,
            encoded_name: None,
            file_extension: None,
            children: HashMap::new(),
        }
    }

    pub fn insert_path<I>(
        &mut self,
        mut components: I,
        file_name: String,
        encoded_file_name: String,
    ) where
        I: Iterator<Item = String>,
    {
        if !self.is_file {
            if let Some(component) = components.next() {
                self.children
                    .entry(component)
                    .or_insert_with(FileSystemNode::new_folder)
                    .insert_path(components, file_name, encoded_file_name);
            } else {
                let file_extension = Path::new(&file_name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or_default()
                    .to_string();

                let file_name = Path::new(&file_name)
                    .file_stem()
                    .and_then(|e| e.to_str())
                    .unwrap_or_default()
                    .to_string();

                let file_name_with_extension = format!("{}.{}", file_name, file_extension);

                // Insert the file at this location
                self.children.insert(
                    file_name_with_extension,
                    FileSystemNode::new_file(encoded_file_name, file_extension),
                );
            }
        }
    }
}

impl Default for FileSystemNode {
    fn default() -> Self {
        FileSystemNode::new_folder()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserManifest {
    pub files: FileSystemNode,
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
    ) -> Result<Box<Self>, RequestError> {
        let user_path = PathBuf::from(format!("./user_data/{}", user_name));

        if user_path.exists() {
            let mut decryptor = FileDecryptor::new(&user_path.join("user.manifest"), passphrase)
                .await
                .unwrap();

            let decrypted_file = match decryptor.decrypt_file().await {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to decrypt manifest file: {}", e);
                    return Err(RequestError::FailedToReadUserManifest);
                }
            };

            let manifest = serde_json::from_slice(&decrypted_file).unwrap();

            Ok(Box::new(Self {
                user_name: user_name.to_string(),
                passphrase: SecretString::from_str(passphrase.expose_secret()).unwrap(),
                user_path,
                manifest,
            }))
        } else {
            return Err(RequestError::UserDoesNotExist);
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
