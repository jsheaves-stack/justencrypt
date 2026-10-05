use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use r2d2_sqlite::SqliteConnectionManager;
use rocket::tokio::{
    sync::{mpsc, oneshot, Mutex, RwLock},
    task,
};
use secrecy::SecretString;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    db::sqlite::{self, FolderContent},
    encryption::{chunk_encryptor::ChunkEncryptor, FileEncryptionMetadata, MPSC_CHANNEL_CAPACITY},
    enums::db_error::DbError,
    session::{credentials::is_valid_username, policy::SessionPolicy, user_context::UserContext},
    util::{
        folder_archive::{self, ChannelWriter, FolderArchive},
        time::unix_now_secs,
    },
};

/// A chunked upload in progress.
#[derive(Clone)]
pub struct UploadState {
    pub file_path: PathBuf,
    pub encoded_file_name: String,
    /// Plaintext length of every chunk written so far, by chunk index.
    pub written_chunks: Arc<Mutex<BTreeMap<u64, u32>>>,
    /// Chunk uploads share it (read lock) and run at the same time; finalize
    /// takes it exclusively (write lock), which waits for writes in progress
    /// and keeps new ones out until the file is sealed.
    pub encryptor: Arc<RwLock<ChunkEncryptor>>,
    /// Unix seconds of the last activity. Atomic so it can be read and
    /// refreshed without taking a lock.
    pub last_updated: Arc<AtomicU64>,
}

impl UploadState {
    /// Tracks a new upload to `file_path`, written by `encryptor`.
    pub fn new(file_path: PathBuf, encoded_file_name: String, encryptor: ChunkEncryptor) -> Self {
        Self {
            file_path,
            encoded_file_name,
            written_chunks: Arc::new(Mutex::new(BTreeMap::new())),
            encryptor: Arc::new(RwLock::new(encryptor)),
            last_updated: Arc::new(AtomicU64::new(unix_now_secs())),
        }
    }

    /// Records activity on the upload, which keeps it from going stale.
    pub fn touch(&self) {
        self.last_updated.store(unix_now_secs(), Ordering::Relaxed);
    }

    /// When the upload last saw activity.
    pub fn last_updated(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.last_updated.load(Ordering::Relaxed))
    }

    /// Whether the upload has been idle for longer than `ttl` at `now_secs`.
    fn is_stale(&self, now_secs: u64, ttl: Duration) -> bool {
        now_secs.saturating_sub(self.last_updated.load(Ordering::Relaxed)) > ttl.as_secs()
    }
}

/// A logged-in session: one login of one user.
pub struct UserSession {
    /// The user's database, files and limits, shared with their other
    /// sessions. All blocking work for the user goes through it.
    pub context: UserContext,
    pub username: String,
    pub created_at: SystemTime,
    pub session_id: String,
    pub active_uploads: Mutex<HashMap<String, UploadState>>,
    /// Unix seconds of the last authenticated request. Atomic so every request
    /// can refresh it without taking a lock.
    pub last_seen: AtomicU64,
}

/// A new session token: 256 bits from the OS random number generator, as
/// unpadded base64url (43 characters).
pub fn new_session_token() -> SecretString {
    let mut bytes = [0u8; 32];

    orion::util::secure_rand_bytes(&mut bytes).expect("the OS random number generator failed");

    SecretString::from(URL_SAFE_NO_PAD.encode(bytes))
}

impl UserSession {
    /// Records activity on the session. The value has one-second precision, so
    /// it is only written when the second has changed: a busy session writes
    /// at most once a second, and every other request only reads it.
    pub fn touch(&self) {
        let now = unix_now_secs();

        if self.last_seen.load(Ordering::Relaxed) != now {
            self.last_seen.store(now, Ordering::Relaxed);
        }
    }

    /// Whether the session has been idle, or has existed, longer than the
    /// policy allows at `now_secs`.
    pub fn is_expired(&self, now_secs: u64, policy: &SessionPolicy) -> bool {
        let created_secs = self
            .created_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let idle = now_secs.saturating_sub(self.last_seen.load(Ordering::Relaxed));
        let age = now_secs.saturating_sub(created_secs);

        idle > policy.idle_timeout.as_secs() || age > policy.max_lifetime.as_secs()
    }

    /// Logs `user_name` in: opens their encrypted database with `passphrase`,
    /// or, with `existing_context` from another of their sessions, checks the
    /// password against it and shares it. Fails with `UserDoesNotExist` for an
    /// unknown user and a database error for a wrong password.
    pub async fn open(
        user_name: &str,
        passphrase: &SecretString,
        existing_context: Option<UserContext>,
        config: &AppConfig,
    ) -> Result<Self, DbError> {
        if !is_valid_username(user_name) {
            return Err(DbError::InvalidInput(
                "Invalid user name format or length.".to_string(),
            ));
        }

        let user_name = user_name.to_owned();
        let passphrase = passphrase.clone();
        let user_name_clone = user_name.clone();
        let user_path = config.user_data_path.join(&user_name);
        let db_config = config.db.clone();
        let blocking_limit = config.max_blocking_threads_per_user;

        // Logging in happens before the user is authenticated, so it can't
        // count against the user's limits: anyone who knew a username could
        // then lock that user out by sending failed logins.
        let session = task::spawn_blocking(move || {
            let user_db_path = user_path.join(format!("{user_name}.db"));

            // Accounts are created only through `accounts::create_account`, so
            // a missing database means there is no account. Checking first also
            // keeps SQLite from creating an empty database here.

            if !user_db_path.is_file() {
                trace!("User database does not exist.");

                return Err(DbError::UserDoesNotExist);
            }

            let context = if let Some(context) = existing_context {
                trace!("Using existing database pool.");

                sqlite::verify_user_db_password(&user_db_path, &passphrase, &db_config)?;
                context
            } else {
                trace!("Creating new database pool.");

                let pool = sqlite::create_user_db_connection(user_db_path, passphrase, &db_config)?;

                UserContext::new(pool, user_path, &db_config, blocking_limit)
            };

            trace!("DB connection pool ready.");

            Ok(Self {
                context,
                username: user_name_clone,
                created_at: SystemTime::now(),
                session_id: Uuid::new_v4().hyphenated().to_string(),
                active_uploads: Mutex::new(HashMap::new()),
                last_seen: AtomicU64::new(unix_now_secs()),
            })
        })
        .await
        .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(session)
    }

    /// Runs `f` with one of the user's database connections (see
    /// `UserContext::with_db`).
    async fn with_db<F, R>(&self, f: F) -> Result<R, DbError>
    where
        F: FnOnce(r2d2::PooledConnection<SqliteConnectionManager>) -> Result<R, DbError>
            + Send
            + 'static,
        R: Send + 'static,
    {
        self.context.with_db(f).await
    }

    /// The name of the encrypted file stored for the file at `file_path`.
    #[cfg(test)]
    pub async fn get_encoded_file_name(&self, file_path: PathBuf) -> Result<String, DbError> {
        let result = self
            .with_db(move |db| {
                sqlite::get_encoded_file_name(&db, file_path.to_str().ok_or(DbError::InvalidPath)?)
            })
            .await?;

        Ok(result)
    }

    /// Records an upload in progress, so its partial file can be found and
    /// removed if the upload is never finished.
    pub async fn add_active_upload_db(
        &self,
        upload_id: String,
        encoded_file_name: String,
        file_path: String,
    ) -> Result<(), DbError> {
        let session_id = self.session_id.clone();
        self.with_db(move |db| {
            sqlite::add_active_upload(&db, &upload_id, &session_id, &encoded_file_name, &file_path)
        })
        .await
    }

    /// Removes the record of an upload that has finished or been abandoned.
    pub async fn remove_active_upload_db(&self, upload_id: String) -> Result<(), DbError> {
        self.with_db(move |db| sqlite::remove_active_upload(&db, &upload_id))
            .await
    }

    /// Deletes an upload's partial file and its tracking row. A partial file
    /// that is already gone is not an error.
    pub async fn abort_upload(&self, upload_id: &str, encoded_file_name: &str) {
        if let Err(e) = self.context.remove_upload_part(encoded_file_name).await {
            if e.kind() != io::ErrorKind::NotFound {
                warn!(
                    "Failed to remove partial file for upload {}: {}",
                    upload_id, e
                );
            }
        }

        if let Err(e) = self.remove_active_upload_db(upload_id.to_owned()).await {
            warn!(
                "Failed to remove upload {} from the database: {}",
                upload_id, e
            );
        }
    }

    /// Aborts every upload that has been idle for longer than `ttl`. Stale
    /// entries are taken out of the map under one short lock; the file and DB
    /// cleanup happens afterwards with no lock held.
    pub async fn sweep_stale_uploads(&self, ttl: Duration) {
        let now = unix_now_secs();
        let mut stale = Vec::new();

        {
            let mut uploads = self.active_uploads.lock().await;

            uploads.retain(|upload_id, state| {
                if state.is_stale(now, ttl) {
                    stale.push((upload_id.clone(), state.encoded_file_name.clone()));

                    false
                } else {
                    true
                }
            });
        }

        for (upload_id, encoded_file_name) in stale {
            info!("Removing stale upload {}", upload_id);

            self.abort_upload(&upload_id, &encoded_file_name).await;
        }
    }

    /// The encoded names of every blob the database refers to: those of stored
    /// files, and those of uploads still in progress (in any session).
    pub async fn referenced_blob_names(
        &self,
    ) -> Result<(HashSet<String>, HashSet<String>), DbError> {
        self.with_db(|db| {
            let files = sqlite::get_all_encoded_names(&db)?.into_iter().collect();
            let uploads = sqlite::get_all_active_uploads(&db)?
                .into_iter()
                .map(|(_, _, encoded_file_name)| encoded_file_name)
                .collect();

            Ok((files, uploads))
        })
        .await
    }

    /// Aborts the uploads recorded for sessions not in `active_session_ids`,
    /// which ended without cleaning up after themselves (a crash, for example).
    pub async fn cleanup_orphaned_uploads(
        &self,
        active_session_ids: HashSet<String>,
    ) -> Result<(), DbError> {
        let active_uploads_db = self
            .with_db(|db| sqlite::get_all_active_uploads(&db))
            .await?;

        for (upload_id, session_id, encoded_file_name) in active_uploads_db {
            if active_session_ids.contains(&session_id) {
                continue;
            }

            self.abort_upload(&upload_id, &encoded_file_name).await;
        }

        Ok(())
    }

    /// Aborts every upload this session has in progress.
    pub async fn cleanup_own_uploads(&self) -> Result<(), DbError> {
        let active_uploads_db = self
            .with_db(|db| sqlite::get_all_active_uploads(&db))
            .await?;

        for (upload_id, session_id, encoded_file_name) in active_uploads_db {
            if session_id != self.session_id {
                continue;
            }

            self.abort_upload(&upload_id, &encoded_file_name).await;
        }

        Ok(())
    }

    /// Stores a file and returns the encoded name of the blob it replaced, if
    /// any. The caller owns deleting that blob.
    pub async fn add_file(
        &self,
        file_path: PathBuf,
        encoded_file_name: String,
        metadata: FileEncryptionMetadata,
    ) -> Result<Option<String>, DbError> {
        let replaced = self
            .with_db(move |mut db| {
                sqlite::add_file(
                    &mut db,
                    file_path.to_str().ok_or(DbError::InvalidPath)?,
                    &encoded_file_name,
                    metadata,
                )
            })
            .await?;

        Ok(replaced)
    }

    /// Deletes a file and returns the encoded name of its blob, or `None` if
    /// there was no such file. The caller owns deleting that blob.
    pub async fn delete_file(&self, file_path: PathBuf) -> Result<Option<String>, DbError> {
        let deleted = self
            .with_db(move |mut db| {
                sqlite::delete_file(&mut db, file_path.to_str().ok_or(DbError::InvalidPath)?)
            })
            .await?;

        Ok(deleted)
    }

    /// Deletes a folder and everything under it, and returns the encoded names
    /// of the blobs that belonged to the deleted files. The caller owns
    /// deleting those blobs.
    pub async fn delete_folder_tree(&self, folder_path: PathBuf) -> Result<Vec<String>, DbError> {
        self.with_db(move |mut db| {
            sqlite::delete_folder_tree(&mut db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await
    }

    /// Creates the folder at `folder_path`, and any missing parent folders.
    pub async fn add_folder(&self, folder_path: PathBuf) -> Result<(), DbError> {
        self.with_db(move |mut db| {
            sqlite::add_folder(&mut db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
        })
        .await?;

        Ok(())
    }

    /// Renames and/or moves a folder in one transaction.
    pub async fn update_folder(
        &self,
        folder_path: PathBuf,
        new_name: Option<String>,
        destination: Option<String>,
    ) -> Result<(), DbError> {
        self.with_db(move |mut db| {
            sqlite::update_folder(
                &mut db,
                folder_path.to_str().ok_or(DbError::InvalidPath)?,
                new_name.as_deref(),
                destination.as_deref(),
            )
        })
        .await
    }

    /// Renames and/or moves a file in one transaction.
    pub async fn update_file(
        &self,
        file_path: PathBuf,
        new_name: Option<String>,
        destination: Option<String>,
    ) -> Result<(), DbError> {
        self.with_db(move |mut db| {
            sqlite::update_file(
                &mut db,
                file_path.to_str().ok_or(DbError::InvalidPath)?,
                new_name.as_deref(),
                destination.as_deref(),
            )
        })
        .await
    }

    /// The id of the folder at `folder_path`, if it exists.
    #[cfg(test)]
    pub async fn get_folder_id(&self, folder_path: PathBuf) -> Result<Option<i32>, DbError> {
        let result = self
            .with_db(move |db| {
                sqlite::get_folder_id(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
            })
            .await?;

        Ok(result)
    }

    /// The files and folders directly inside the folder at `folder_path`.
    pub async fn get_folder(&self, folder_path: PathBuf) -> Result<Vec<FolderContent>, DbError> {
        let result = self
            .with_db(move |db| {
                sqlite::get_folder(&db, folder_path.to_str().ok_or(DbError::InvalidPath)?)
            })
            .await?;

        Ok(result)
    }

    /// Starts streaming a folder, with everything below it, as a TAR archive.
    /// Returns once the archive's length is known; its bytes then arrive on
    /// the returned channel as fast as the client reads them. `hold` (the
    /// download's permits) is kept until the archive is finished, the client
    /// goes away, or the client reads nothing for `stall_timeout`.
    pub async fn stream_folder_archive<H: Send + 'static>(
        &self,
        folder_path: PathBuf,
        hold: H,
        stall_timeout: Duration,
    ) -> Result<FolderArchive, DbError> {
        let folder_path = folder_path.to_str().ok_or(DbError::InvalidPath)?.to_owned();
        let connection = self.context.reserve_connection().await?;
        let context = self.context.clone();
        let username = self.username.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (tx, rx) = mpsc::channel(MPSC_CHANNEL_CAPACITY);
        let out = ChannelWriter::new(tx, stall_timeout);

        // The producer occupies one of the user's blocking threads, and one
        // of their connections, for as long as the download runs.
        self.context
            .start_blocking(move || {
                let _held = (hold, connection);

                folder_archive::produce(&context, &folder_path, &username, ready_tx, out);
            })
            .await?;

        let (len, file_name) = ready_rx
            .await
            .map_err(|e| DbError::ThreadJoinError(e.to_string()))??;

        Ok(FolderArchive { rx, len, file_name })
    }

    /// The name of the encrypted file stored for the file at `file_path`, with
    /// its key and size.
    pub async fn get_file_decryption_data(
        &self,
        file_path: PathBuf,
    ) -> Result<(String, FileEncryptionMetadata), DbError> {
        let result = self
            .with_db(move |db| {
                sqlite::get_file_decryption_data(
                    &db,
                    file_path.to_str().ok_or(DbError::InvalidPath)?,
                )
            })
            .await?;

        Ok(result)
    }
}
