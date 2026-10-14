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
use secrecy::SecretString;
use tokio::{
    sync::{Mutex, RwLock},
    task,
};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    db::sqlite,
    encryption::chunk_encryptor::ChunkEncryptor,
    enums::db_error::DbError,
    session::policy::SessionPolicy,
    storage::user_context::UserContext,
    util::{names::is_valid_username, time::unix_now_secs},
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

        if let Err(e) = self
            .context
            .remove_active_upload(upload_id.to_owned())
            .await
        {
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

    /// Aborts the uploads recorded for sessions not in `active_session_ids`,
    /// which ended without cleaning up after themselves (a crash, for example).
    pub async fn cleanup_orphaned_uploads(
        &self,
        active_session_ids: HashSet<String>,
    ) -> Result<(), DbError> {
        let active_uploads_db = self.context.recorded_uploads().await?;

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
        let active_uploads_db = self.context.recorded_uploads().await?;

        for (upload_id, session_id, encoded_file_name) in active_uploads_db {
            if session_id != self.session_id {
                continue;
            }

            self.abort_upload(&upload_id, &encoded_file_name).await;
        }

        Ok(())
    }
}
