mod test_admin;
mod test_chunked_upload;
mod test_config;
mod test_credentials;
mod test_db_files;
mod test_db_folder_delete;
mod test_db_folder_move;
mod test_encryption;
mod test_file;
mod test_file_delete_patch;
mod test_folder;
mod test_folder_delete;
mod test_folder_patch;
mod test_orphans;
mod test_session;
mod test_session_store;
mod test_thumbnail;

use std::{env, fs, path::PathBuf, str::FromStr, sync::Arc};

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rocket::{custom, http::Cookie, tokio::sync::Semaphore, Build, Orbit, Rocket};
use secrecy::SecretString;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    db::migrations::get_migrations,
    enums::request_error::RequestError,
    session::{
        accounts::create_account_storage, orphans::OrphanScanner, policy::SessionPolicy,
        store::SessionStore, user_session::UserSession,
    },
    AppState,
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

pub struct TestUser {
    pub name: String,
    pub path: PathBuf,
}

impl Drop for TestUser {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub async fn setup_rocket() -> (Rocket<Build>, TestUser) {
    setup_rocket_with_config(|_| {}).await
}

// Lets a test change the config its Rocket instance is built with.
pub async fn setup_rocket_with_config(
    configure: impl FnOnce(&mut AppConfig),
) -> (Rocket<Build>, TestUser) {
    build_test_rocket(configure, SessionPolicy::default(), false, 1)
}

pub async fn setup_rocket_with_session_policy(
    session_policy: SessionPolicy,
) -> (Rocket<Build>, TestUser) {
    setup_rocket_with_options(session_policy, false, 1).await
}

pub async fn setup_rocket_with_options(
    session_policy: SessionPolicy,
    orphan_scan_enabled: bool,
    thumbnail_permits: usize,
) -> (Rocket<Build>, TestUser) {
    build_test_rocket(
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

    config.server.secret_key =
        Some(SecretString::from_str("BlN4QMqM8+wmRLPNRn10X/ZwmM58tEcCOgeY8cuMsB8=").unwrap());

    config
}

fn build_test_rocket(
    configure: impl FnOnce(&mut AppConfig),
    session_policy: SessionPolicy,
    orphan_scan_enabled: bool,
    thumbnail_permits: usize,
) -> (Rocket<Build>, TestUser) {
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

    let state = AppState {
        config: Arc::new(config.clone()),
        sessions: Arc::new(SessionStore::new(session_policy)),
        orphan_scanner: OrphanScanner::new(orphan_scan_enabled),
        thumbnail_semaphore: Arc::new(Semaphore::new(thumbnail_permits)),
    };

    let rocket = custom(config.rocket_figment()).manage(state);

    (rocket, user)
}

// Gives a test's Rocket instance its own upload limits, so limit behavior can
// be tested with small sizes without touching process-wide env vars.
pub fn with_upload_limits(rocket: Rocket<Build>, file: u64, file_chunk: u64) -> Rocket<Build> {
    let figment = rocket
        .figment()
        .clone()
        .merge(("limits.file", file))
        .merge(("limits.file-chunk", file_chunk));

    rocket.configure(figment)
}

pub async fn create_test_session(
    rocket: &Rocket<Orbit>,
    temp_user: String,
) -> (String, Cookie<'static>) {
    let user_token = Uuid::new_v4().to_string();
    let passphrase = SecretString::from_str("test_password").unwrap();
    let state = rocket.state::<AppState>().unwrap();

    // Tests use a weak password, so this skips the strength check that
    // `accounts::create_account` applies. The account may already exist when a
    // test logs in more than once.
    match create_account_storage(&temp_user, &passphrase, &state.config).await {
        Ok(()) | Err(RequestError::AccountAlreadyExists) => {},
        Err(e) => panic!("Failed to create test account: {}", e),
    }

    let user_session = match UserSession::open(&temp_user, &passphrase, None, &state.config).await {
        Ok(session) => Arc::new(session),
        Err(e) => panic!("Failed to open user session: {}", e),
    };

    let session_id = user_session.session_id.clone();

    state
        .sessions
        .insert(user_token.clone(), user_session)
        .await;

    let cookie = Cookie::build(("sid", user_token)).build();

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
