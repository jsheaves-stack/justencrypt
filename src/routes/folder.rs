use crate::{
    db::sqlite::FolderEntry,
    enums::{request_error::RequestError, request_success::RequestSuccess},
    util::{
        sharded_path::{get_sharded_path, remove_sharded_path},
        unrestricted_path::UnrestrictedPath,
    },
    web::forwarding_guards::AuthenticatedSession,
};
use rocket::{delete, get, options, put, serde::json::Json};

#[options("/<folder_path..>")]
pub fn folder_options(folder_path: UnrestrictedPath) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [OPTIONS /folder{}]", folder_path);
    Ok(RequestSuccess::NoContent)
}

#[get("/<folder_path..>")]
pub async fn get_folder(
    folder_path: UnrestrictedPath, // The name/path of the folder being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<Json<Vec<FolderEntry>>, RequestError> {
    trace!("Entering route [GET /folder{}]", folder_path);

    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.read().await;

    let folder_contents = match session.get_folder(folder_path_buf).await {
        Ok(f) => {
            trace!("Successfully retrieved folder contents.");
            drop(session);
            f
        }
        Err(e) => {
            error!("Failed to get folder contents from db: {}", e);
            return Err(RequestError::FailedToReadFolderContents);
        }
    };

    trace!("Exiting route [GET /folder{}] successfully.", folder_path);

    Ok(Json(folder_contents))
}

#[put("/<folder_path..>")]
pub async fn create_folder(
    folder_path: UnrestrictedPath, // The name/path of the folder being requested, extracted from the URL.
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [PUT /folder{}]", folder_path);

    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.read().await;

    match session.add_folder(folder_path_buf).await {
        Ok(_) => {
            trace!("Successfully added folder to db.");
            drop(session)
        }
        Err(e) => {
            error!("Failed to add folder to db: {}", e);
            return Err(RequestError::FailedToCreateFolder);
        }
    }

    trace!("Exiting route [PUT /folder{}] successfully.", folder_path);

    Ok(RequestSuccess::Created)
}

#[delete("/<folder_path..>")]
pub async fn delete_folder(
    folder_path: UnrestrictedPath,
    auth: AuthenticatedSession,
) -> Result<RequestSuccess, RequestError> {
    trace!("Entering route [DELETE /folder{}]", folder_path);

    let folder_path_buf = folder_path.to_path_buf();
    let session = auth.session.write().await;

    let folder_id = match session.get_folder_id(folder_path_buf.clone()).await {
        Ok(Some(id)) => {
            trace!("Found root folder to delete with ID: {}", id);
            id
        }
        Ok(None) => {
            trace!("Folder to delete not found in db.");
            return Err(RequestError::FailedToRemoveFile);
        }
        Err(e) => {
            error!("Failed to get folder id from db: {}", e);
            return Err(RequestError::FailedToCreateFolder);
        }
    };

    let user_path = session.get_user_path().clone();
    let mut folder_stack: Vec<i32> = vec![folder_id];
    let mut folders_to_delete: Vec<i32> = Vec::new();

    trace!("Starting recursive delete from folder ID: {}", folder_id);

    while let Some(current_folder_id) = folder_stack.pop() {
        trace!("Processing folder ID: {}", current_folder_id);
        folders_to_delete.push(current_folder_id);

        let files = match session.get_files_in_folder(current_folder_id).await {
            Ok(files) => files,
            Err(e) => {
                error!("Failed to get files in folder: {}", e);
                return Err(RequestError::FailedToReadFolderContents);
            }
        };

        trace!(
            "Found {} files in folder ID {}",
            files.len(),
            current_folder_id
        );

        for file in files {
            trace!(
                "Deleting file with ID: {}, encoded_name: {}",
                file.id,
                file.encoded_name
            );

            let encoded_file_path = get_sharded_path(user_path.clone(), &file.encoded_name).await;

            // Remove thumbnail if it exists
            if let Ok(Some(encoded_thumbnail_file_name)) = session
                .get_encoded_thumbnail_file_name_by_file_id(file.id)
                .await
            {
                trace!("Found thumbnail to delete: {}", encoded_thumbnail_file_name);

                let encoded_thumbnail_file_path = get_sharded_path(
                    user_path.clone().join(".cache"),
                    &encoded_thumbnail_file_name,
                )
                .await;

                if encoded_thumbnail_file_path.exists() {
                    if let Err(e) =
                        remove_sharded_path(&user_path, &encoded_thumbnail_file_path).await
                    {
                        error!("Failed to delete thumbnail file: {}", e);
                    }
                }
            }

            if let Err(e) = remove_sharded_path(&user_path, &encoded_file_path).await {
                error!("Failed to delete file: {}", e);
            }

            if let Err(e) = session.delete_file_by_id(file.id).await {
                error!("Failed to delete file by id: {}", e);
            }
        }

        let child_folder_ids = match session.get_child_folders(current_folder_id).await {
            Ok(child_folders) => child_folders,
            Err(e) => {
                error!("Failed to get child folders: {}", e);
                return Err(RequestError::FailedToReadFolderContents);
            }
        };
        trace!(
            "Found {} child folders in folder ID {}",
            child_folder_ids.len(),
            current_folder_id
        );

        for child_folder_id in child_folder_ids {
            folder_stack.push(child_folder_id);
        }
    }

    for current_folder_id in folders_to_delete.into_iter().rev() {
        if current_folder_id != folder_id {
            trace!("Deleting folder metadata for ID: {}", current_folder_id);

            if let Err(e) = session.delete_folder_by_id(current_folder_id).await {
                error!("Failed to delete folder by id: {}", e);
            }
        }
    }

    trace!(
        "Deleting root folder metadata for path: {:?}",
        folder_path_buf
    );

    if let Err(e) = session.delete_folder(folder_path_buf).await {
        error!("Failed to delete folder: {}", e);
        return Err(RequestError::FailedToRemoveFile);
    }

    drop(session);

    trace!(
        "Exiting route [DELETE /folder{}] successfully.",
        folder_path
    );

    Ok(RequestSuccess::NoContent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{get_app_config, session::user_session::UserSession, AppState};
    use rocket::{
        http::{Cookie, Status},
        local::asynchronous::Client,
        tokio::{
            self,
            sync::{RwLock, Semaphore},
        },
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
            "/folder",
            routes![create_folder, get_folder, delete_folder, folder_options],
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
    async fn test_create_folder() {
        let (rocket, temp_dir, temp_user) = setup().await;

        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (session_id, cookie) = create_test_session(client.rocket(), temp_user).await;

        let folder_path = "test_folder";

        let response = client
            .put(format!("/folder/{}", folder_path))
            .private_cookie(cookie)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let state = client.rocket().state::<AppState>().unwrap();
        let session_guard = state.active_sessions.read().await;
        let session = session_guard.get(&session_id).unwrap().clone();
        let session = session.read().await;

        let folder_id = session
            .get_folder_id(folder_path.into())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(2, folder_id);

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_get_folder() {
        let (rocket, temp_dir, temp_user) = setup().await;

        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let (_, cookie) = create_test_session(client.rocket(), temp_user).await;

        let folder_path = "test_folder";

        let response = client
            .put(format!("/folder/{}", folder_path))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let response = client
            .get(format!("/folder/{}", folder_path))
            .private_cookie(cookie)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        cleanup(temp_dir).await;
    }

    #[rocket::async_test]
    async fn test_create_folder_no_auth() {
        let (rocket, temp_dir, _) = setup().await;
        let client = Client::tracked(rocket)
            .await
            .expect("Failed to create client");

        let folder_path = "test_folder";

        let response = client
            .put(format!("/folder/{}", folder_path))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Unauthorized);

        cleanup(temp_dir).await;
    }
}
