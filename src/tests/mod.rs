mod client;
mod test_admin;
mod test_chunked_upload;
mod test_config;
mod test_cors;
mod test_credentials;
mod test_db_files;
mod test_db_folder_delete;
mod test_db_folder_move;
mod test_encryption;
mod test_encryption_integrity;
mod test_entry_names;
mod test_file;
mod test_file_delete_patch;
mod test_folder;
mod test_folder_delete;
mod test_folder_download;
mod test_folder_patch;
mod test_http_behavior;
mod test_orphans;
mod test_range;
mod test_response_headers;
mod test_session;
mod test_session_store;
mod test_tar;
mod test_thumbnail;
mod test_user_context;
mod test_user_isolation;
mod test_user_storage;
mod test_web;

use std::{env, fs, path::PathBuf, str::FromStr, sync::Arc};

pub use axum::http::StatusCode;
pub use client::{TestClient, TestResponse};
pub use cookie::Cookie;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use secrecy::SecretString;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    app::App,
    config::{AppConfig, DbConfig},
    db::migrations::get_migrations,
    enums::service_error::ServiceError,
    service::accounts::create_account_storage,
    session::{
        orphans::OrphanScanner, policy::SessionPolicy, store::SessionStore,
        user_session::UserSession,
    },
    storage::user_context::UserContext,
};

pub type Db = PooledConnection<SqliteConnectionManager>;

// An in-memory database with every migration applied. The pool holds a single
// connection so the same in-memory database stays alive for the whole test.
pub fn migrated_db() -> Db {
    let mut db = Pool::builder()
        .max_size(1)
        .build(SqliteConnectionManager::memory())
        .unwrap()
        .get()
        .unwrap();

    get_migrations().to_latest(&mut db).unwrap();

    db
}

// A user context whose files live in `dir`, for tests of file storage and
// encryption. Its database pool is never used.
pub fn storage_context(dir: &std::path::Path) -> UserContext {
    let pool = Pool::builder()
        .max_size(1)
        .build_unchecked(SqliteConnectionManager::memory());

    UserContext::new(pool, dir.to_path_buf(), &DbConfig::default(), None)
}

pub struct TestUser {
    pub name: String,
    pub path: PathBuf,
}

impl Drop for TestUser {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub async fn setup_app() -> (Arc<App>, TestUser) {
    setup_app_with_config(|_| {}).await
}

// Lets a test change the config its application is built with.
pub async fn setup_app_with_config(configure: impl FnOnce(&mut AppConfig)) -> (Arc<App>, TestUser) {
    build_test_app(configure, SessionPolicy::default(), false, 1)
}

pub async fn setup_app_with_session_policy(session_policy: SessionPolicy) -> (Arc<App>, TestUser) {
    setup_app_with_options(session_policy, false, 1).await
}

pub async fn setup_app_with_options(
    session_policy: SessionPolicy,
    orphan_scan_enabled: bool,
    thumbnail_permits: usize,
) -> (Arc<App>, TestUser) {
    build_test_app(
        |_| {},
        session_policy,
        orphan_scan_enabled,
        thumbnail_permits,
    )
}

// Users are created under the system temp directory, and the fixed secret
// key lets tests also run as release builds, which require one.
pub fn test_config() -> AppConfig {
    let mut config = AppConfig {
        user_data_path: env::temp_dir(),
        ..AppConfig::default()
    };

    config.http.secret_key =
        Some(SecretString::from_str("BlN4QMqM8+wmRLPNRn10X/ZwmM58tEcCOgeY8cuMsB8=").unwrap());

    config
}

fn build_test_app(
    configure: impl FnOnce(&mut AppConfig),
    session_policy: SessionPolicy,
    orphan_scan_enabled: bool,
    thumbnail_permits: usize,
) -> (Arc<App>, TestUser) {
    let temp_user = Uuid::new_v4().to_string();
    let temp_dir = env::temp_dir().join(&temp_user);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    let user = TestUser {
        name: temp_user,
        path: temp_dir,
    };

    let mut config = test_config();
    config.orphan_scan_enabled = orphan_scan_enabled;
    configure(&mut config);

    let app = App {
        config: Arc::new(config.clone()),
        sessions: Arc::new(SessionStore::new(session_policy)),
        orphan_scanner: OrphanScanner::new(orphan_scan_enabled),
        thumbnail_semaphore: Arc::new(Semaphore::new(thumbnail_permits)),
        download_semaphore: config
            .max_active_downloads
            .map(|limit| Arc::new(Semaphore::new(limit.get()))),
    };

    (Arc::new(app), user)
}

// Gives a test's application its own upload limits, so limit behavior can be
// tested with small sizes without touching process-wide env vars.
pub fn upload_limits(file: u64, file_chunk: u64) -> impl FnOnce(&mut AppConfig) {
    move |config| {
        config.limits.file = ubyte::ByteUnit::Byte(file);
        config.limits.file_chunk = ubyte::ByteUnit::Byte(file_chunk);
    }
}

pub async fn create_test_session(state: &App, temp_user: String) -> (String, Cookie<'static>) {
    let user_token = Uuid::new_v4().to_string();
    let passphrase = SecretString::from_str("test_password").unwrap();

    // Tests use a weak password, so this skips the strength check that
    // `accounts::create_account` applies. The account may already exist when a
    // test logs in more than once.

    match create_account_storage(&temp_user, &passphrase, &state.config).await {
        Ok(()) | Err(ServiceError::AccountAlreadyExists) => {},

        Err(e) => panic!("Failed to create test account: {}", e),
    }

    let user_session = match UserSession::open(&temp_user, &passphrase, None, &state.config).await {
        Ok(session) => Arc::new(session),
        Err(e) => panic!("Failed to open user session: {}", e),
    };

    let session_id = user_session.session_id.clone();

    state.sessions.insert(&user_token, user_session).await;

    let cookie = Cookie::new("sid", user_token);

    (session_id, cookie)
}

// Every file under the user's directory except the user's own database files,
// i.e. encrypted blobs, partial uploads and cached thumbnails.
pub fn stored_files(user_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();

            if path.is_dir() {
                walk(&path, depth + 1, out);
            } else if depth > 0 {
                out.push(path);
            }
        }
    }

    let mut out = Vec::new();
    walk(user_dir, 0, &mut out);

    out
}
