use std::{env, path::PathBuf};

use encryption::FileEncryptionMetadata;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocket::tokio;
use secrecy::SecretString;

use crate::{
    db::sqlite::{self, File},
    enums::db_error::DbError,
};

pub struct UserSession {
    user_path: PathBuf,
    db_pool: Pool<SqliteConnectionManager>,
}

impl UserSession {
    pub async fn open(user_name: &str, passphrase: &SecretString) -> Result<Self, DbError> {
        let user_name = user_name.to_owned();
        let passphrase = passphrase.clone();

        tokio::task::spawn_blocking(move || {
            let user_data_path = env::var("JUSTENCRYPT_USER_DATA_PATH")
                .unwrap_or_else(|_| String::from("./user_data"));

            let user_path = PathBuf::from(&user_data_path).join(&user_name);

            if !user_path.exists() {
                return Err(DbError::UserDoesNotExist);
            }

            let user_db_path = user_path.join(format!("{user_name}.db"));

            let db_pool = sqlite::create_user_db_connection(user_db_path, passphrase)?;

            Ok(Self { user_path, db_pool })
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub fn get_user_path(&self) -> PathBuf {
        self.user_path.clone()
    }

    pub async fn add_file(
        &mut self,
        file_path: PathBuf,
        encoded_file_name: String,
        metadata: FileEncryptionMetadata,
    ) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::add_file(
                &db,
                file_path.to_str().ok_or(DbError::InvalidPath)?,
                &encoded_file_name,
                metadata,
            )
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn delete_file(&mut self, file_path: PathBuf) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::delete_file(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn add_folder(&mut self, folder_path: PathBuf) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;
            sqlite::add_folder(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn add_thumbnail(
        &mut self,
        file_path: PathBuf,
        encoded_name: String,
        metadata: FileEncryptionMetadata,
    ) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;
            sqlite::add_thumbnail(
                &db,
                file_path.to_str().ok_or(DbError::InvalidPath)?,
                &encoded_name,
                metadata,
            )
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn get_folder(&mut self, folder_path: PathBuf) -> Result<Vec<File>, DbError> {
        let db_pool = self.db_pool.clone();
        let folder_path = folder_path.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;
            sqlite::get_folder(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn get_thumbnail(
        &mut self,
        file_path: PathBuf,
    ) -> Result<FileEncryptionMetadata, DbError> {
        let db_pool = self.db_pool.clone();
        let file_path = file_path.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;
            sqlite::get_thumbnail(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn get_file_encryption_metadata(
        &self,
        file_path: PathBuf,
    ) -> Result<FileEncryptionMetadata, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;
            sqlite::get_file(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }
}
