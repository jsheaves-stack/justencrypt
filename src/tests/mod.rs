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

use crate::{get_app_config, session::user_session::UserSession, AppState};
use rocket::{
    http::Cookie,
    tokio::sync::{RwLock, Semaphore},
    Build, Orbit, Rocket,
};
use secrecy::SecretString;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use uuid::Uuid;

pub struct TestUser {
    pub name: String,
    pub path: std::path::PathBuf,
}

impl Drop for TestUser {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub async fn setup_rocket() -> (Rocket<Build>, TestUser) {
    dotenv::dotenv().ok();

    let temp_user = Uuid::new_v4().to_string();
    let temp_dir = std::env::temp_dir().join(&temp_user);
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    let user = TestUser {
        name: temp_user,
        path: temp_dir,
    };

    std::env::set_var(
        "JUSTENCRYPT_ROCKET_SECRET_KEY",
        "BlN4QMqM8+wmRLPNRn10X/ZwmM58tEcCOgeY8cuMsB8=",
    );

    std::env::set_var(
        "JUSTENCRYPT_USER_DATA_PATH",
        std::env::temp_dir().to_str().unwrap(),
    );

    let state = AppState {
        sessions_by_id: RwLock::new(HashMap::new()),
        token_to_id: RwLock::new(HashMap::new()),
        thumbnail_semaphore: Arc::new(Semaphore::new(1)),
    };

    let app_config = get_app_config();

    let rocket = rocket::custom(app_config).manage(state);

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
        .sessions_by_id
        .write()
        .await
        .insert(session_id.clone(), user_session);
    state
        .token_to_id
        .write()
        .await
        .insert(user_token.clone(), session_id.clone());

    let cookie = Cookie::build(("sid", user_token)).build();

    (session_id, cookie)
}
