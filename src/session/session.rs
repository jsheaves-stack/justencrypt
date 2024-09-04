use std::{
    collections::HashMap,
    error::Error,
    path::{Path, PathBuf},
};

pub use encryption::Salt;

use encryption::{Auth, DerivedKey, FileDecryptor, FileEncryptor, SecretKey};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::enums::request_error::RequestError;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileSystemNode {
    pub is_file: bool,
    pub file_name: String,
    encoded_name: Option<String>, // Encoded name (only for files)
    pub file_extension: Option<String>,
    children: HashMap<String, FileSystemNode>, // Children nodes
}

impl FileSystemNode {
    pub fn new_file(file_name: String, encoded_file_name: String, file_extension: String) -> Self {
        FileSystemNode {
            is_file: true,
            file_name: format!("{}.{}", file_name, file_extension),
            encoded_name: Some(encoded_file_name),
            file_extension: Some(file_extension),
            children: HashMap::new(), // Files have no children
        }
    }

    pub fn new_folder(file_name: String) -> Self {
        FileSystemNode {
            is_file: false,
            file_name,
            encoded_name: None,
            file_extension: None,
            children: HashMap::new(),
        }
    }

    pub fn _find_path(&self, path: &PathBuf) -> Option<&FileSystemNode> {
        let components = path.iter().filter_map(|s| s.to_str());
        let mut current_node = self;

        for component in components {
            match current_node.children.get(component) {
                Some(node) => current_node = node,
                None => return None,
            }
        }

        Some(current_node)
    }

    pub fn find_path_nodes(&self, path: &PathBuf) -> Vec<&FileSystemNode> {
        let components = path.iter().filter_map(|s| s.to_str());
        let mut current_node = self;

        for component in components {
            match current_node.children.get(component) {
                Some(node) => {
                    current_node = node;
                }
                None => return Vec::new(),
            }
        }

        current_node.children.values().collect()
    }

    pub fn delete_item(&mut self, path: &PathBuf) -> Result<(), String> {
        let mut components = path.iter().filter_map(|s| s.to_str()).peekable();

        let mut current_node = self;

        while let Some(component) = components.next() {
            if components.peek().is_none() {
                if current_node.children.remove(component).is_some() {
                    return Ok(());
                } else {
                    return Err(format!("Item '{}' not found", component));
                }
            } else {
                match current_node.children.get_mut(component) {
                    Some(node) => current_node = node,
                    None => return Err(format!("Path '{}' not found", component)),
                }
            }
        }

        Err("Invalid path".to_string())
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
                    .entry(component.clone())
                    .or_insert_with(|| FileSystemNode::new_folder(component))
                    .insert_path(components, file_name, encoded_file_name);
            } else if !file_name.is_empty() {
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
                    FileSystemNode::new_file(file_name, encoded_file_name, file_extension),
                );
            }
        }
    }
}

impl Default for FileSystemNode {
    fn default() -> Self {
        FileSystemNode::new_folder(String::from(""))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserManifest {
    pub files: FileSystemNode,
}

pub struct AppSession {
    pub _user_name: String,
    pub user_path: PathBuf,
    pub manifest: UserManifest,
    pub manifest_key: DerivedKey,
}

impl AppSession {
    pub async fn open<'a>(
        user_name: &String,
        passphrase: &SecretString,
    ) -> Result<Box<Self>, RequestError> {
        let user_path = PathBuf::from(format!("./user_data/{}", user_name));

        if user_path.exists() {
            let mut decryptor = FileDecryptor::new(
                &user_path.join("user.manifest"),
                &Auth::Passphrase(passphrase.clone()),
            )
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
                _user_name: user_name.to_string(),
                user_path,
                manifest,
                manifest_key: decryptor.key_salt,
            }))
        } else {
            return Err(RequestError::UserDoesNotExist);
        }
    }

    pub async fn update_manifest(self: &mut Self) -> Result<(), Box<dyn Error>> {
        let mut encryptor = FileEncryptor::new(
            &self.user_path.join("user.manifest"),
            Auth::DerivedKey(
                SecretKey::from_slice(self.manifest_key.key.unprotected_as_bytes()).unwrap(),
                Salt::from_slice(self.manifest_key.salt.as_ref()).unwrap(),
            ),
        )
        .await?;

        let json = serde_json::to_string(&self.manifest)?;

        encryptor.encrypt_file(json.as_bytes()).await?;

        Ok(())
    }
}
