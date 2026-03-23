use super::*;
use crate::{
    routes::{
        file::{delete_file, file_options, get_file, patch_file, put_file},
        folder::{create_folder, get_folder},
    },
    util::sharded_path::get_sharded_path,
    AppState,
};
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    routes, tokio,
};

#[rocket::async_test]
async fn test_delete_file_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let file_path = "to_be_deleted.txt";
    let file_content = "Hello, world!";

    // Create the file first
    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    // Get internal paths to verify deletion later
    let state = client.rocket().state::<AppState>().unwrap();
    let session_guard = state.sessions_by_id.read().await;
    let session_lock = session_guard.get(&session_id).unwrap().clone();
    let session = session_lock.read().await;

    let encoded_file_name = session
        .get_encoded_file_name(file_path.into())
        .await
        .unwrap();
    let sharded_path = get_sharded_path(session.get_user_path().clone(), &encoded_file_name).await;
    assert!(tokio::fs::metadata(&sharded_path).await.is_ok());

    drop(session);
    drop(session_guard);

    // Delete the file
    let response = client
        .delete(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);

    // Verify it's gone from disk
    assert!(tokio::fs::metadata(&sharded_path).await.is_err());

    // Verify it's gone from DB
    let session_guard = state.sessions_by_id.read().await;
    let session_lock = session_guard.get(&session_id).unwrap().clone();
    let session = session_lock.read().await;
    let db_lookup = session.get_encoded_file_name(file_path.into()).await;
    assert!(db_lookup.is_err());
}

#[rocket::async_test]
async fn test_patch_file_rename() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let original_name = "original.txt";
    let new_name = "renamed.txt";

    // Create the file
    client
        .put(format!("/file/{}", original_name))
        .private_cookie(cookie.clone())
        .body("content")
        .dispatch()
        .await;

    // Rename the file
    let patch_payload = format!(r#"{{"file_name": "{}"}}"#, new_name);
    let response = client
        .patch(format!("/file/{}", original_name))
        .private_cookie(cookie.clone())
        .header(ContentType::JSON)
        .body(patch_payload)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);

    // Try fetching with new name
    let response = client
        .get(format!("/file/{}", new_name))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    // Old name should fail
    let response = client
        .get(format!("/file/{}", original_name))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_ne!(response.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_patch_file_move() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount(
            "/file",
            routes![put_file, get_file, delete_file, file_options, patch_file],
        )
        .mount("/folder", routes![create_folder, get_folder]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    // Create a file in root
    let file_name = "to_move.txt";
    client
        .put(format!("/file/{}", file_name))
        .private_cookie(cookie.clone())
        .body("content")
        .dispatch()
        .await;

    // Create target folder
    let folder_name = "target_folder";
    client
        .put(format!("/folder/{}", folder_name))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    // Move file
    let patch_payload = format!(r#"{{"parent_folder_path": "{}"}}"#, folder_name);
    let response = client
        .patch(format!("/file/{}", file_name))
        .private_cookie(cookie.clone())
        .header(ContentType::JSON)
        .body(patch_payload)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);

    // Verify it's in the new folder
    let response = client
        .get(format!("/file/{}/{}", folder_name, file_name))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_get_file_not_found() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![get_file]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .get("/file/does_not_exist.txt")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}
