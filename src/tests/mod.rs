mod test_admin;
mod test_chunked_upload;
mod test_encryption;
mod test_file;
mod test_file_delete_patch;
mod test_folder;
mod test_folder_delete;
mod test_folder_patch;
mod test_session;
mod test_thumbnail;

use std::{env, fs, path::PathBuf, str::FromStr, sync::Arc};

use rocket::{custom, http::Cookie, tokio::sync::Semaphore, Build, Orbit, Rocket};
use secrecy::SecretString;
use uuid::Uuid;

use crate::{
    get_app_config,
    session::{store::SessionStore, user_session::UserSession},
    AppState,
};

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
    dotenv::dotenv().ok();

    let temp_user = Uuid::new_v4().to_string();
    let temp_dir = env::temp_dir().join(&temp_user);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    let user = TestUser {
        name: temp_user,
        path: temp_dir,
    };

    env::set_var(
        "JUSTENCRYPT_ROCKET_SECRET_KEY",
        "BlN4QMqM8+wmRLPNRn10X/ZwmM58tEcCOgeY8cuMsB8=",
    );

    env::set_var(
        "JUSTENCRYPT_USER_DATA_PATH",
        env::temp_dir().to_str().unwrap(),
    );

    let state = AppState {
        sessions: SessionStore::default(),
        thumbnail_semaphore: Arc::new(Semaphore::new(1)),
    };

    let app_config = get_app_config();

    let rocket = custom(app_config).manage(state);

    (rocket, user)
}

pub async fn create_test_session(
    rocket: &Rocket<Orbit>,
    temp_user: String,
) -> (String, Cookie<'static>) {
    let user_token = Uuid::new_v4().to_string();
    let passphrase = SecretString::from_str("test_password").unwrap();

    let user_session = match UserSession::open(&temp_user, &passphrase, None).await {
        Ok(session) => Arc::new(session),
        Err(e) => panic!("Failed to open user session: {}", e),
    };

    let session_id = user_session.session_id.clone();

    let state = rocket.state::<AppState>().unwrap();

    state
        .sessions
        .insert(user_token.clone(), user_session)
        .await;

    let cookie = Cookie::build(("sid", user_token)).build();

    (session_id, cookie)
}
