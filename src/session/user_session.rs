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
use serde::{Deserialize, Serialize};

pub struct UserSession {
    user_path: PathBuf,
    db_pool: Pool<SqliteConnectionManager>,
}

impl UserSession {
    pub async fn open(user_name: &str, passphrase: &SecretString) -> Result<Self, DbError> {
        // Validate user_name to prevent path traversal
        if user_name.is_empty() || user_name.contains(['/', '\\', '.']) || user_name.len() > 64 {
            return Err(DbError::InvalidInput(
                "Invalid user name format or length.".to_string(),
            ));
        }

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

    pub async fn get_encoded_file_name(&self, file_path: PathBuf) -> Result<String, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::get_encoded_file_name(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn add_file(
        &self,
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

    pub async fn delete_file(&self, file_path: PathBuf) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::delete_file(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn add_folder(&self, folder_path: PathBuf) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::add_folder(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn delete_folder(&self, folder_path: PathBuf) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::delete_folder(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn delete_folder_by_id(&self, folder_id: i32) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::delete_folder_by_id(&db, folder_id)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn delete_file_by_id(&self, file_id: i32) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::delete_file_by_id(&db, file_id)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }

    pub async fn get_folder_id(&self, folder_path: PathBuf) -> Result<Option<i32>, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::get_folder_id(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn get_files_in_folder(&self, folder_id: i32) -> Result<Vec<EncodedFile>, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::get_files_in_folder(&db, folder_id)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn get_child_folders(&self, folder_id: i32) -> Result<Vec<i32>, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::get_child_folders(&db, folder_id)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn get_encoded_thumbnail_file_name_by_file_id(
        &self,
        file_id: i32,
    ) -> Result<Option<String>, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::get_encoded_thumbnail_file_name_by_file_id(&db, file_id)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn add_thumbnail(
        &self,
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

    pub async fn get_folder(&self, folder_path: PathBuf) -> Result<Vec<File>, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::get_folder(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn get_thumbnail(
        &self,
        file_path: PathBuf,
    ) -> Result<FileEncryptionMetadata, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::get_thumbnail(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub async fn get_encoded_thumbnail_file_name(
        &self,
        file_path: PathBuf,
    ) -> Result<Option<String>, DbError> {
        let db_pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::get_encoded_thumbnail_file_name(
                &db,
                file_path.to_str().ok_or(DbError::InvalidPath)?,
            )
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

    pub async fn move_file(
        &self,
        file_path: PathBuf,
        destination_folder: String,
    ) -> Result<(), DbError> {
        let db_pool = self.db_pool.clone();

        let file_path_str = file_path.to_str().ok_or(DbError::InvalidPath)?.to_string();

        tokio::task::spawn_blocking(move || {
            let db = db_pool.get()?;

            sqlite::move_file(&db, &file_path_str, &destination_folder)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct EncodedFile {
    pub id: i32,
    pub encoded_name: String,
}
