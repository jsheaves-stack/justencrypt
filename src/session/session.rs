use std::{collections::HashMap, error::Error, path::PathBuf};

use rocket::tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct UserManifest {
    pub files: HashMap<String, String>,
}

pub struct AppSession {
    pub user_name: String,
    pub pass_phrase: String,
    pub user_path: PathBuf,
    pub manifest: UserManifest,
}

impl AppSession {
    pub async fn open<'a>(user_name: &String, pass_phrase: &String) -> Result<Box<Self>, String> {
        let user_path = PathBuf::from(format!("./user_data/{}", user_name));

        if user_path.exists() {
            let mut manifest_file = File::open(user_path.join("user.manifest")).await.unwrap();
            let mut reader = BufReader::new(&mut manifest_file);
            let mut contents = String::new();

            reader.read_to_string(&mut contents).await.unwrap();

            let manifest = match serde_json::from_str(&contents) {
                Ok(v) => v,
                Err(e) => panic!("{}", e),
            };

            Ok(Box::new(Self {
                user_name: user_name.to_string(),
                pass_phrase: pass_phrase.to_string(),
                user_path,
                manifest,
            }))
        } else {
            Err(String::from("Failed to find user data."))
        }
    }

    pub async fn update_manifest(self: &mut Self) -> Result<(), Box<dyn Error>> {
        let manifest_file = File::create(&self.user_path.join("user.manifest")).await?;
        let mut writer = BufWriter::new(manifest_file);

        let json = serde_json::to_string(&self.manifest)?;

        writer.write_all(json.as_bytes()).await?;

        writer.flush().await?;

        Ok(())
    }
}
