use std::{path::PathBuf, str::FromStr};

use encryption::FileEncryptor;
use rocket::{
    http::CookieJar,
    serde::json::Json,
    tokio::fs::{self},
    State,
};
use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    session::session::{FileSystemNode, UserManifest},
    AppState,
};

#[get("/manifest")]
pub async fn get_user_manifest(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Option<Json<UserManifest>> {
    let active_sessions = state.active_sessions.read().await;

    let cookie = cookies
        .get_private("session_id")
        .expect("Couldn't find a session id");

    let session = active_sessions
        .get(cookie.value())
        .expect("Could not find an active session for this session id");

    Some(Json(session.manifest.clone()))
}

#[derive(Deserialize)]
pub struct CreateUser {
    passphrase: String,
}

#[post("/create/<user_name..>", format = "json", data = "<reqbody>")]
pub async fn create_user(user_name: PathBuf, reqbody: Json<CreateUser>) -> Option<()> {
    let user_path = PathBuf::from("./user_data/").join(user_name);

    if !user_path.exists() {
        fs::create_dir(&user_path).await.unwrap();

        let manifest = UserManifest {
            files: FileSystemNode::default(),
        };

        let json = serde_json::to_string(&manifest).unwrap();

        let mut encryptor = FileEncryptor::new(
            &user_path.join("user.manifest"),
            &SecretString::from_str(&reqbody.passphrase).unwrap(),
        )
        .await
        .unwrap();

        encryptor.encrypt_file(json.as_bytes()).await.unwrap();

        Some(())
    } else {
        panic!("Profile already exists")
    }
}
