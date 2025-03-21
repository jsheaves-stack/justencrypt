use std::{env, path::PathBuf, str::FromStr};

use encryption::{file_encryptor::FileEncryptor, Auth};
use rocket::{
    http::CookieJar,
    serde::json::Json,
    tokio::fs::{self},
    State,
};
use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    session::session::{FileSystemNode, UserManifest},
    AppState,
};

#[options("/manifest")]
pub fn manifest_options() -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[get("/manifest")]
pub async fn get_user_manifest(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<Json<UserManifest>, RequestError> {
    let active_sessions = state.active_sessions.read().await;

    // Retrieve the user's session based on the "session_id" cookie.
    let cookie = match cookies.get_private("session_id") {
        Some(c) => c,
        None => return Err(RequestError::MissingSessionId),
    };

    let session = match active_sessions.get(cookie.value()) {
        Some(s) => s,
        None => return Err(RequestError::MissingActiveSession),
    };

    Ok(Json(session.manifest.clone()))
}

#[derive(Deserialize)]
pub struct CreateUser {
    username: String,
    password: String,
}

#[options("/create")]
pub fn create_user_options() -> Result<RequestSuccess, RequestError> {
    Ok(RequestSuccess::NoContent)
}

#[put("/create", format = "json", data = "<reqbody>")]
pub async fn create_user(reqbody: Json<CreateUser>) -> Result<RequestSuccess, RequestError> {
    let user_data = match env::var("JUSTENCRYPT_USER_DATA_PATH") {
        Ok(val) => val,
        Err(_) => String::from("./user_data"),
    };

    let user_data_path = PathBuf::from("./user_data/");

    if !user_data_path.exists() {
        match fs::create_dir(&user_data).await {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to create user_data directory: {}", e);
                return Err(RequestError::FailedToWriteData);
            }
        };
    }

    let user_path = user_data_path.join(&reqbody.username);

    if !user_path.exists() {
        match fs::create_dir(&user_path).await {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to create user directory: {}", e);
                return Err(RequestError::FailedToWriteData);
            }
        }

        let manifest = UserManifest {
            files: FileSystemNode::default(),
        };

        let json = match serde_json::to_string(&manifest) {
            Ok(j) => j,
            Err(e) => {
                error!("Failed to parse user manifest: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

        let mut encryptor = match FileEncryptor::new(
            &user_path.join("user.manifest"),
            Auth::Passphrase(SecretString::from_str(&reqbody.password).unwrap()),
        )
        .await
        {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to create stream encryptor for manifest file: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

        match encryptor.encrypt_file(json.as_bytes()).await {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to encrypt user manifest: {}", e);
                return Err(RequestError::FailedToProcessData);
            }
        };

        Ok(RequestSuccess::NoContent)
    } else {
        Err(RequestError::UserAlreadyExists)
    }
}
