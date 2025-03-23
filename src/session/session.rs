use std::{env, error::Error, path::PathBuf};

use encryption::FileEncryptionMetadata;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocket::tokio;
use secrecy::SecretString;

use crate::db::{
    db,
    sql::{self, File},
};

pub struct AppSession {
    user_path: PathBuf,
    db_pool: Pool<SqliteConnectionManager>,
}

impl AppSession {
    pub async fn open(
        user_name: &String,
        passphrase: &SecretString,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let user_name = user_name.clone();
        let passphrase = passphrase.clone();

        Ok(tokio::task::spawn_blocking(move || {
            let user_name = user_name.clone();
            let user_data_path = match env::var("JUSTENCRYPT_USER_DATA_PATH") {
                Ok(val) => val,
                Err(_) => String::from("./user_data"),
            };

            let user_path = PathBuf::from(user_data_path).join(user_name.clone());
            let user_db_path = user_path.join(format!("{user_name}.db"));

            let db_pool = db::create_user_db_connection(user_db_path, passphrase.clone());

            Self { user_path, db_pool }
        })
        .await?)
    }

    pub fn get_user_path(&self) -> PathBuf {
        self.user_path.clone()
    }

    pub async fn add_file(
        &mut self,
        file_path: PathBuf,
        encoded_file_name: String,
        metadata: FileEncryptionMetadata,
    ) -> Result<(), Box<dyn Error>> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get().unwrap();

            sql::add_file(
                &db,
                file_path.to_str().unwrap(),
                &encoded_file_name.as_str(),
                metadata.key.unprotected_as_bytes(),
                metadata.buffer_size,
                metadata.salt_size,
                metadata.nonce_size,
                metadata.tag_size,
            )
            .unwrap();
        })
        .await?;

        Ok(())
    }

    pub async fn add_folder(&mut self, folder_path: PathBuf) -> Result<(), Box<dyn Error>> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get().unwrap();

            sql::add_folder(&db, folder_path.to_str().unwrap()).unwrap();
        })
        .await?;

        Ok(())
    }

    pub async fn add_thumbnail(
        &mut self,
        file_path: PathBuf,
        encoded_name: String,
        metadata: FileEncryptionMetadata,
    ) -> Result<(), Box<dyn Error>> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get().unwrap();
            sql::add_thumbnail(
                &db,
                file_path.to_str().unwrap(),
                encoded_name.as_str(),
                metadata.key.unprotected_as_bytes(),
                metadata.buffer_size,
                metadata.nonce_size,
                metadata.salt_size,
                metadata.tag_size,
            )
        })
        .await?
        .unwrap();

        Ok(())
    }

    pub async fn get_folder(&mut self, folder_path: PathBuf) -> Result<Vec<File>, Box<dyn Error>> {
        let db_pool = self.db_pool.clone();
        let folder_path = folder_path.clone();

        Ok(tokio::task::spawn_blocking(move || {
            let db = db_pool.get().unwrap();

            sql::get_folder(&db, folder_path.to_str().unwrap()).unwrap()
        })
        .await?)
    }

    pub async fn get_thumbnail(
        &mut self,
        file_path: PathBuf,
    ) -> Result<FileEncryptionMetadata, Box<dyn Error>> {
        let db_pool = self.db_pool.clone();
        let file_path = file_path.clone();

        Ok(tokio::task::spawn_blocking(move || {
            let db = db_pool.get().unwrap();
            sql::get_thumbnail(&db, file_path.to_str().unwrap()).unwrap()
        })
        .await?)
    }

    pub async fn get_file_encryption_metadata(
        &self,
        file_path: PathBuf,
    ) -> Result<FileEncryptionMetadata, Box<dyn Error>> {
        let db_pool = self.db_pool.clone();

        Ok(tokio::task::spawn_blocking(move || {
            let db = db_pool.get().unwrap();

            sql::get_file(&db, file_path.to_str().unwrap()).unwrap()
        })
        .await?)
    }
}
