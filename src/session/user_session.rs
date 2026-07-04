use crate::{
    db::sqlite::{self, FolderEntry},
    encryption::{chunk_encryptor::ChunkEncryptor, FileEncryptionMetadata},
    enums::db_error::DbError,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocket::tokio::{sync::Mutex, task};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env,
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};

#[derive(Deserialize, Serialize, Debug)]
pub struct EncodedFile {
    pub id: i32,
    pub encoded_name: String,
}

#[derive(Clone)]
pub struct UploadState {
    pub file_path: PathBuf,
    pub encoded_file_name: String,
    pub written_chunks: Arc<Mutex<HashSet<u64>>>,
    pub encryptor: Arc<Mutex<ChunkEncryptor>>,
    pub last_updated: Arc<Mutex<SystemTime>>,
}

pub struct UserSession {
    user_path: PathBuf,
    db_pool: Pool<SqliteConnectionManager>,
    pub username: String,
    pub created_at: SystemTime,
    pub session_id: String,
    pub user_token: SecretString,
    pub active_uploads: Mutex<HashMap<String, UploadState>>,
}

impl UserSession {
    pub async fn open(user_name: &str, passphrase: &SecretString) -> Result<Self, DbError> {
        trace!("Entering UserSession::open for user: '{}'", user_name);
        // Validate user_name to prevent path traversal
        if user_name.is_empty() || user_name.contains(['/', '\\', '.']) || user_name.len() > 64 {
            return Err(DbError::InvalidInput(
                "Invalid user name format or length.".to_string(),
            ));
        }

        let user_name = user_name.to_owned();
        let passphrase = passphrase.clone();
        let user_name_clone = user_name.clone();

        let result = task::spawn_blocking(move || {
            trace!("Inside spawn_blocking for UserSession::open");

            let user_data_path = env::var("JUSTENCRYPT_USER_DATA_PATH")
                .unwrap_or_else(|_| String::from("./user_data"));

            trace!("User data path: {}", user_data_path);

            let user_path = PathBuf::from(&user_data_path).join(&user_name);

            trace!("Constructed user path: {:?}", user_path);

            if !user_path.exists() {
                trace!("User path does not exist.");

                return Err(DbError::UserDoesNotExist);
            }

            let user_db_path = user_path.join(format!("{user_name}.db"));

            trace!("User DB path: {:?}", user_db_path);

            let db_pool = sqlite::create_user_db_connection(user_db_path, passphrase)?;

            trace!("DB connection pool created.");

            Ok(Self {
                user_path,
                db_pool,
                username: user_name_clone,
                created_at: SystemTime::now(),
                session_id: uuid::Uuid::new_v4().hyphenated().to_string(),
                user_token: SecretString::from(uuid::Uuid::new_v4().hyphenated().to_string()),
                active_uploads: Mutex::new(HashMap::new()),
            })
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?;

        trace!("Exiting UserSession::open successfully.");

        result
    }

    async fn with_db<F, R>(&self, f: F) -> Result<R, DbError>
    where
        F: FnOnce(r2d2::PooledConnection<SqliteConnectionManager>) -> Result<R, DbError>
            + Send
            + 'static,
        R: Send + 'static,
    {
        let db_pool = self.db_pool.clone();
        task::spawn_blocking(move || {
            let db = db_pool.get()?;
            f(db)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    }

    pub fn get_user_path(&self) -> PathBuf {
        trace!(
            "Entering and exiting UserSession::get_user_path. Path: {:?}",
            self.user_path
        );

        self.user_path.clone()
    }

    pub async fn get_encoded_file_name(&self, file_path: PathBuf) -> Result<String, DbError> {
        trace!(
            "Entering UserSession::get_encoded_file_name for path: {:?}",
            file_path
        );

        let result = self
            .with_db(move |db| {
                trace!("Inside spawn_blocking for get_encoded_file_name");
                sqlite::get_encoded_file_name(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
            })
            .await?;

        trace!("Exiting UserSession::get_encoded_file_name.");
        Ok(result)
    }

    pub async fn add_file(
        &self,
        file_path: PathBuf,
        encoded_file_name: String,
        metadata: FileEncryptionMetadata,
    ) -> Result<(), DbError> {
        trace!("Entering UserSession::add_file for path: {:?}", file_path);

        self.with_db(move |mut db| {
            trace!("Inside spawn_blocking for add_file");
            sqlite::add_file(
                &mut db,
                file_path.to_str().ok_or(DbError::InvalidPath)?,
                &encoded_file_name,
                metadata,
            )
        })
        .await?;

        trace!("Exiting UserSession::add_file successfully.");

        Ok(())
    }

    pub async fn delete_file(&self, file_path: PathBuf) -> Result<(), DbError> {
        trace!(
            "Entering UserSession::delete_file for path: {:?}",
            file_path
        );

        self.with_db(move |mut db| {
            trace!("Inside spawn_blocking for delete_file");
            sqlite::delete_file(&mut db, file_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await?;

        trace!("Exiting UserSession::delete_file successfully.");

        Ok(())
    }

    pub async fn add_folder(&self, folder_path: PathBuf) -> Result<(), DbError> {
        trace!(
            "Entering UserSession::add_folder for path: {:?}",
            folder_path
        );

        self.with_db(move |mut db| {
            trace!("Inside spawn_blocking for add_folder");
            sqlite::add_folder(&mut db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await?;

        trace!("Exiting UserSession::add_folder successfully.");

        Ok(())
    }

    pub async fn delete_folder(&self, folder_path: PathBuf) -> Result<(), DbError> {
        trace!(
            "Entering UserSession::delete_folder for path: {:?}",
            folder_path
        );

        self.with_db(move |mut db| {
            trace!("Inside spawn_blocking for delete_folder");
            sqlite::delete_folder(&mut db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await?;

        trace!("Exiting UserSession::delete_folder successfully.");

        Ok(())
    }

    pub async fn delete_folder_by_id(&self, folder_id: i32) -> Result<(), DbError> {
        trace!(
            "Entering UserSession::delete_folder_by_id for id: {}",
            folder_id
        );

        self.with_db(move |mut db| {
            trace!("Inside spawn_blocking for delete_folder_by_id");
            sqlite::delete_folder_by_id(&mut db, folder_id)
        })
        .await?;

        trace!("Exiting UserSession::delete_folder_by_id successfully.");

        Ok(())
    }

    pub async fn delete_file_by_id(&self, file_id: i32) -> Result<(), DbError> {
        trace!(
            "Entering UserSession::delete_file_by_id for id: {}",
            file_id
        );

        self.with_db(move |mut db| {
            trace!("Inside spawn_blocking for delete_file_by_id");
            sqlite::delete_file_by_id(&mut db, file_id)
        })
        .await?;

        trace!("Exiting UserSession::delete_file_by_id successfully.");

        Ok(())
    }

    pub async fn get_folder_id(&self, folder_path: PathBuf) -> Result<Option<i32>, DbError> {
        trace!(
            "Entering UserSession::get_folder_id for path: {:?}",
            folder_path
        );

        let result = self
            .with_db(move |db| {
                trace!("Inside spawn_blocking for get_folder_id");
                sqlite::get_folder_id(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
            })
            .await?;

        trace!("Exiting UserSession::get_folder_id.");

        Ok(result)
    }

    pub async fn get_files_in_folder(&self, folder_id: i32) -> Result<Vec<EncodedFile>, DbError> {
        trace!(
            "Entering UserSession::get_files_in_folder for id: {}",
            folder_id
        );

        let result = self
            .with_db(move |db| {
                trace!("Inside spawn_blocking for get_files_in_folder");
                sqlite::get_files_in_folder(&db, folder_id)
            })
            .await?;

        trace!("Exiting UserSession::get_files_in_folder.");

        Ok(result)
    }

    pub async fn get_child_folders(&self, folder_id: i32) -> Result<Vec<i32>, DbError> {
        trace!(
            "Entering UserSession::get_child_folders for id: {}",
            folder_id
        );

        let result = self
            .with_db(move |db| {
                trace!("Inside spawn_blocking for get_child_folders");
                sqlite::get_child_folders(&db, folder_id)
            })
            .await?;

        trace!("Exiting UserSession::get_child_folders.");

        Ok(result)
    }

    pub async fn get_folder(&self, folder_path: PathBuf) -> Result<Vec<FolderEntry>, DbError> {
        trace!(
            "Entering UserSession::get_folder for path: {:?}",
            folder_path
        );

        let result = self
            .with_db(move |db| {
                trace!("Inside spawn_blocking for get_folder");
                sqlite::get_folder(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
            })
            .await?;

        trace!("Exiting UserSession::get_folder.");

        Ok(result)
    }

    pub async fn get_file_encryption_metadata(
        &self,
        file_path: PathBuf,
    ) -> Result<FileEncryptionMetadata, DbError> {
        trace!(
            "Entering UserSession::get_file_encryption_metadata for path: {:?}",
            file_path
        );

        let result = self
            .with_db(move |db| {
                trace!("Inside spawn_blocking for get_file_encryption_metadata");
                sqlite::get_file(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
            })
            .await?;

        trace!("Exiting UserSession::get_file_encryption_metadata.");

        Ok(result)
    }

    pub async fn get_file_decryption_data(
        &self,
        file_path: PathBuf,
    ) -> Result<(String, FileEncryptionMetadata), DbError> {
        trace!(
            "Entering UserSession::get_file_decryption_data for path: {:?}",
            file_path
        );

        let result = self
            .with_db(move |db| {
                trace!("Inside spawn_blocking for get_file_decryption_data");
                sqlite::get_file_decryption_data(
                    &db,
                    file_path.to_str().ok_or(DbError::InvalidPath)?,
                )
            })
            .await?;

        trace!("Exiting UserSession::get_file_decryption_data.");

        Ok(result)
    }

    pub async fn rename_file(
        &self,
        file_path: PathBuf,
        new_file_name: String,
    ) -> Result<(), DbError> {
        trace!(
            "Entering UserSession::rename_file for path: {:?}, new_name: {}",
            file_path,
            new_file_name
        );

        let db_pool = self.db_pool.clone();
        let file_path_str = file_path.to_str().ok_or(DbError::InvalidPath)?.to_string();

        task::spawn_blocking(move || {
            trace!("Inside spawn_blocking for rename_file");
            let mut db = db_pool.get()?;
            sqlite::rename_file(&mut db, &file_path_str, &new_file_name)
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        trace!("Exiting UserSession::rename_file successfully.");

        Ok(())
    }

    pub async fn move_file(
        &self,
        file_path: PathBuf,
        destination_folder: String,
    ) -> Result<(), DbError> {
        trace!(
            "Entering UserSession::move_file for path: {:?}, destination: {}",
            file_path,
            destination_folder
        );

        let file_path_str = file_path.to_str().ok_or(DbError::InvalidPath)?.to_string();

        self.with_db(move |mut db| {
            trace!("Inside spawn_blocking for move_file");
            sqlite::move_file(&mut db, &file_path_str, &destination_folder)
        })
        .await?;

        trace!("Exiting UserSession::move_file successfully.");

        Ok(())
    }
}
