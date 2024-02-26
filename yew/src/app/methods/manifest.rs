use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use yew::Properties;

#[derive(Serialize, Deserialize, Clone, Debug, Properties, PartialEq)]
pub struct FileSystemNode {
    pub is_file: bool,
    pub encoded_name: Option<String>, // Encoded name (only for files)
    pub file_extension: Option<String>,
    pub children: HashMap<String, FileSystemNode>, // Children nodes
}

impl FileSystemNode {
    fn _new_file(encoded_file_name: String, file_extension: String) -> Self {
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

    pub fn _insert_path<I>(
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
                    ._insert_path(components, file_name, encoded_file_name);
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

                // Insert the file at this location
                self.children.insert(
                    format!("{}.{}", file_name, file_extension),
                    FileSystemNode::_new_file(encoded_file_name, file_extension),
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
