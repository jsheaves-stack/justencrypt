use std::{
    collections::HashMap,
    env,
    error::Error,
    path::{Path, PathBuf},
};

pub use encryption::Salt;

use encryption::{
    file_decryptor::FileDecryptor, file_encryptor::FileEncryptor, Auth, DerivedKey, SecretKey,
};
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

    pub fn find_path(&self, path: &Path) -> Option<&FileSystemNode> {
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

    pub fn find_path_nodes(&self, path: &Path) -> Vec<&FileSystemNode> {
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

    pub fn delete_item(&mut self, path: PathBuf) -> Result<(), String> {
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

                self.children.insert(
                    file_name_with_extension,
                    FileSystemNode::new_file(file_name, encoded_file_name, file_extension),
                );
            }
        }
    }

    pub fn collect_encoded_names_at_path(&self, path: &Path) -> Option<Vec<String>> {
        let node = self.find_path(path)?;
        Some(node.collect_encoded_names())
    }

    fn collect_encoded_names(&self) -> Vec<String> {
        let mut names = Vec::new();

        if self.is_file {
            if let Some(encoded) = &self.encoded_name {
                names.push(encoded.clone());
            }
        } else {
            for child in self.children.values() {
                names.extend(child.collect_encoded_names());
            }
        }

        names
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
        let user_data = match env::var("JUSTENCRYPT_USER_DATA_PATH") {
            Ok(val) => val,
            Err(_) => String::from("./user_data"),
        };

        let user_data_path = PathBuf::from(user_data).join(user_name);

        if user_data_path.exists() {
            let mut decryptor = FileDecryptor::new(
                &user_data_path.join("user.manifest"),
                Auth::Passphrase(passphrase.clone()),
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
                user_path: user_data_path,
                manifest,
                manifest_key: decryptor.key_salt,
            }))
        } else {
            Err(RequestError::UserDoesNotExist)
        }
    }

    pub async fn update_manifest(&mut self) -> Result<(), Box<dyn Error>> {
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

    pub fn get_files_to_delete(&self, path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
        Ok(self
            .manifest
            .files
            .collect_encoded_names_at_path(path)
            .unwrap())
    }

    pub async fn remove_node_from_manifest(&mut self, path: &Path) -> Result<(), Box<dyn Error>> {
        self.manifest.files.delete_item(path.to_path_buf())?;
        self.update_manifest().await?;

        Ok(())
    }
}
