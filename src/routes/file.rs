use crate::encryption::stream_decryptor::StreamDecryptor;
use crate::encryption::stream_encryptor::StreamEncryptor;
use crate::encryption::{NONCE_SIZE, SALT_SIZE};
use crate::util::sharded_path::{get_sharded_path, remove_sharded_path};
use crate::util::unrestricted_path::UnrestrictedPath;
use crate::{
    enums::{request_error::RequestError, request_success::RequestSuccess},
    web::forwarding_guards::AuthenticatedSession,
};
use rocket::serde::{json::Json, Deserialize};
use rocket::tokio::sync::mpsc;
use rocket::{
    data::ByteUnit,
    delete, get, options, patch, put,
    response::stream::ByteStream,
    tokio::{self, fs::File, io::BufReader},
    Data,
};
use uuid::Uuid;

const STREAM_LIMIT: usize = 50 * (1000 * (1000 * 1000)); // 50 Gigabyte

const MPSC_CHANNEL_CAPACITY: usize = 2;

#[options("/<file_path..>")]
pub fn file_options(file_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /file{}]", file_path);
    Ok(RequestSuccess::NoContent)
}

#[put("/<file_path..>", data = "<reqdata>")]
pub async fn put_file(
    file_path: UnrestrictedPath, // The path where the file should be stored, extracted from the URL.
    reqdata: Data<'_>,           // The raw data of the file being uploaded.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PUT /file{}]", file_path);

    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();
    let encoded_file_name = Uuid::new_v4().to_string();
    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;

    trace!(
        "Generated encoded_file_name: {} for path: {:?}",
        encoded_file_name,
        encoded_file_path
    );

    let mut encryptor = match StreamEncryptor::new(encoded_file_path).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create StreamEncryptor: {}", e);
            return Err(RequestError::FailedToAddFile);
        }
    };

    trace!("StreamEncryptor created.");

    let metadata = encryptor.get_file_encryption_metadata();
    let file_path_buf = file_path.to_path_buf();

    match session
        .add_file(file_path_buf, encoded_file_name, metadata)
        .await
    {
        Ok(_) => {
            trace!("File metadata added to DB successfully.");
            drop(session)
        }
        Err(e) => {
            error!("Failed to add file to db: {}", e);
            return Err(RequestError::FailedToAddFile);
        }
    };

    let mut data_stream = reqdata.open(ByteUnit::from(STREAM_LIMIT));

    match encryptor
        .encrypt_source_to_encryptor(&mut data_stream)
        .await
    {
        Ok(_) => {
            trace!("Exiting route [PUT /file{}] successfully.", file_path);
            Ok(RequestSuccess::Created)
        }
        Err(e) => {
            error!("encrypt_source_to_encryptor failed: {}", e);
            Err(RequestError::FailedToAddFile)
        }
    }
}

#[derive(Deserialize)]
pub struct PatchFileRequest {
    parent_folder_path: Option<String>,
    file_name: Option<String>,
}

#[patch("/<file_path..>", data = "<patch_file_request>")]
pub async fn patch_file(
    file_path: UnrestrictedPath,
    patch_file_request: Json<PatchFileRequest>,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PATCH /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let updates = patch_file_request.into_inner();

    if let Some(parent_folder_path) = updates.parent_folder_path {
        trace!(
            "Attempting to move file to new parent folder: {}",
            parent_folder_path
        );
        match session
            .move_file(file_path_buf.clone(), parent_folder_path)
            .await
        {
            Ok(_) => trace!("File moved successfully."),
            Err(e) => {
                error!("Failed to move file: {}", e);
                return Err(RequestError::FailedToMoveFile);
            }
        }
    };

    if let Some(new_file_name) = updates.file_name {
        trace!("Attempting to rename file to: {}", new_file_name);
        match session.rename_file(file_path_buf, new_file_name).await {
            Ok(_) => trace!("File renamed successfully."),
            Err(e) => {
                error!("Failed to rename file: {}", e);
                return Err(RequestError::FailedToRenameFile);
            }
        }
    };

    drop(session);

    trace!("Exiting route [PATCH /file{}] successfully.", file_path);

    Ok(RequestSuccess::NoContent)
}

#[get("/<file_path..>")]
pub async fn get_file(
    file_path: UnrestrictedPath, // The name/path of the file being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<ByteStream![Vec<u8>], RequestError> {
    trace!("Entering route [GET /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();

    let encoded_file_name = match session.get_encoded_file_name(file_path.to_path_buf()).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to get encoded file name from db: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    trace!("Retrieved encoded_file_name: {}", encoded_file_name);

    let encoded_file_path = get_sharded_path(user_path, &encoded_file_name).await;

    trace!("Constructed encoded_file_path: {:?}", encoded_file_path);

    let metadata = match session.get_file_encryption_metadata(file_path_buf).await {
        Ok(m) => {
            trace!("Successfully retrieved file encryption metadata.");
            drop(session);
            m
        }
        Err(e) => {
            error!("Failed to get file encryption metadata for file: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    // Initialize the stream decryptor for the requested file.
    let mut decryptor = match StreamDecryptor::new(encoded_file_path, metadata).await {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to create StreamDecryptor: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    trace!("StreamDecryptor created.");

    // Open the encrypted file.
    let input_file = match File::open(decryptor.get_file_path()).await {
        Ok(i) => i,
        Err(e) => {
            error!("Failed to open file: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };

    trace!("Encrypted file opened for reading.");

    let mut reader = BufReader::new(input_file);
    let offset = (SALT_SIZE + NONCE_SIZE) as u64;

    // Create an unbounded channel for streaming decrypted file chunks.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MPSC_CHANNEL_CAPACITY);

    trace!("MPSC channel created for file download.");

    // Spawn an async task to read, decrypt, and send file chunks.
    tokio::spawn(async move {
        decryptor
            .decrypt_stream_to_channel(&mut reader, tx, offset)
            .await
    });

    // Stream the decrypted file chunks as they become available.
    trace!("Returning ByteStream to client.");

    Ok(ByteStream! {
        while let Some(chunk) = rx.recv().await {
            yield chunk;
        }
    })
}

#[delete("/<file_path..>")]
pub async fn delete_file(
    file_path: UnrestrictedPath, // The name/path of the file being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [DELETE /file{}]", file_path);

    let file_path_buf = file_path.to_path_buf();
    let session = auth.session.read().await;
    let user_path = session.get_user_path().clone();

    let encoded_file_name = match session.get_encoded_file_name(file_path.to_path_buf()).await {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to get encoded file name from db: {}", e);
            return Err(RequestError::FailedToProcessData);
        }
    };
    trace!("Retrieved encoded_file_name: {}", encoded_file_name);

    let encoded_file_path = get_sharded_path(user_path.clone(), &encoded_file_name).await;

    trace!("Constructed encoded_file_path: {:?}", encoded_file_path);

    match session.delete_file(file_path_buf).await {
        Ok(_) => {
            trace!("File metadata deleted from DB successfully.");
            drop(session)
        }
        Err(e) => {
            error!("Failed to delete file from db: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    match remove_sharded_path(&user_path, &encoded_file_path).await {
        Ok(_) => trace!("Physical file deleted successfully."),
        Err(e) => {
            error!("Failed to delete file: {}", e);
            return Err(RequestError::FailedToRemoveFile);
        }
    };

    trace!("Exiting route [DELETE /file{}] successfully.", file_path);

    Ok(RequestSuccess::NoContent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{get_app_config, session::user_session::UserSession, AppState};
    use rocket::{
        http::{Cookie, Status},
        local::asynchronous::Client,
        tokio::sync::{RwLock, Semaphore},
        Build, Orbit, Rocket,
    };
    use secrecy::SecretString;
    use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};
    use uuid::Uuid;

    async fn setup() -> (Rocket<Build>, PathBuf, String) {
        dotenv::dotenv().ok();

        let temp_user = Uuid::new_v4().to_string();
        let temp_dir = std::env::temp_dir().join(temp_user.clone());

        tokio::fs::create_dir_all(&temp_dir)
            .await
            .expect("Failed to create temp dir");

        std::env::set_var(
            "JUSTENCRYPT_ROCKET_SECRET_KEY",
            "BlN4QMqM8+wmRLPNRn10X/ZwmM58tEcCOgeY8cuMsB8=",
        );

        std::env::set_var("JUSTENCRYPT_USER_DATA_PATH", "/tmp/");

        let state = AppState {
            active_sessions: RwLock::new(HashMap::new()),
            thumbnail_semaphore: Arc::new(Semaphore::new(1)),
        };

        let app_config = get_app_config();

        let rocket = rocket::custom(app_config).manage(state).mount(
            "/file",
            routes![put_file, get_file, delete_file, file_options, patch_file],
        );

        (rocket, temp_dir, temp_user)
    }

    async fn cleanup(temp_dir: PathBuf) {
        tokio::fs::remove_dir_all(temp_dir)
            .await
            .expect("Failed to remove temp dir");
    }

    async fn create_test_session(
        rocket: &Rocket<Orbit>,
        temp_user: String,
    ) -> (String, Cookie<'static>) {
        // fs::create_dir("./user_data/test_user").unwrap();
        let session_id = Uuid::new_v4().to_string();
        let passphrase = SecretString::from_str("test_password").unwrap();

        let user_session = match UserSession::open(&temp_user, &passphrase).await {
            Ok(session) => Arc::new(RwLock::new(session)),
            Err(e) => panic!("Failed to open user session: {}", e),
        };

        let state = rocket.state::<AppState>().unwrap();

        state
            .active_sessions
            .write()
            .await
            .insert(session_id.clone(), user_session);

        let cookie = Cookie::build(("session_id", session_id.clone())).build();

        (session_id, cookie)
    }

    #[rocket::async_test]
    async fn test_put_file() {
        let (rocket, temp_dir, temp_user) = setup().await;

        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let file_path = "test_file.txt";
        let file_content = "Hello, world!";

        let response = client
            .put(format!("/file/{}", file_path))
            .private_cookie(cookie)
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = session_guard.get(&session_id).unwrap().clone();
        let session = session.read().await;

        let file_entry = Some(
            session
                .get_encoded_file_name(file_path.into())
                .await
                .unwrap(),
        );

        assert!(file_entry.is_some());

        let encoded_file_name = file_entry.map(|f| f).unwrap();
        let sharded_path =
            get_sharded_path(session.get_user_path().clone(), &encoded_file_name).await;

        assert!(tokio::fs::metadata(sharded_path).await.is_ok());

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_get_file() {
        let (rocket, temp_dir, temp_user) = setup().await;

        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let file_path = "test_file.txt";
        let file_content = "Hello, world!";

        let response = client
            .put(format!("/file/{}", file_path))
            .private_cookie(cookie.clone())
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let response = client
            .get(format!("/file/{}", file_path))
            .private_cookie(cookie)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();

        assert_eq!(body, file_content);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = match session_guard.get(&session_id) {
            Some(session) => session,
            None => panic!("Session not found"),
        };

        let session = session.read().await;

        let file_entry = Some(
            session
                .get_encoded_file_name(file_path.into())
                .await
                .unwrap(),
        );

        assert!(file_entry.is_some());

        let encoded_file_name = file_entry.map(|f| f).unwrap();
        let sharded_path =
            get_sharded_path(session.get_user_path().clone(), &encoded_file_name).await;

        assert!(tokio::fs::metadata(sharded_path).await.is_ok());

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_put_file_no_auth() {
        let (rocket, temp_dir, _) = setup().await;
        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let file_path = "test_file.txt";
        let file_content = "Hello, world!";

        let response = client
            .put(format!("/file/{}", file_path))
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Unauthorized);

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_put_file_empty_content() {
        let (rocket, temp_dir, temp_user) = setup().await;
        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let file_path = "test_file.txt";
        let file_content = "";

        let response = client
            .put(format!("/file/{}", file_path))
            .private_cookie(cookie)
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = session_guard.get(&session_id).unwrap().clone();
        let session = session.read().await;

        let file_entry = Some(
            session
                .get_encoded_file_name(file_path.into())
                .await
                .unwrap(),
        );

        assert!(file_entry.is_some());

        let encoded_file_name = file_entry.map(|f| f).unwrap();
        let sharded_path =
            get_sharded_path(session.get_user_path().clone(), &encoded_file_name).await;

        assert!(tokio::fs::metadata(sharded_path).await.is_ok());

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_put_file_large_content() {
        let (rocket, temp_dir, temp_user) = setup().await;
        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let file_path = "test_file.txt";
        let file_content = "A".repeat(64 * 1024 * 1024); // 64MB

        let response = client
            .put(format!("/file/{}", file_path))
            .private_cookie(cookie)
            .body(file_content)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = session_guard.get(&session_id).unwrap().clone();
        let session = session.read().await;

        let file_entry = Some(
            session
                .get_encoded_file_name(file_path.into())
                .await
                .unwrap(),
        );

        assert!(file_entry.is_some());

        cleanup(temp_dir).await;
    }
}
