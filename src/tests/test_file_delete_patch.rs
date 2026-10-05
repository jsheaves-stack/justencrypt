use rocket::{
    async_test,
    http::{ContentType, Cookie, Status},
    local::asynchronous::Client,
    routes, tokio,
};

use super::*;
use crate::{
    routes::{
        file::{delete_file, file_options, get_file, patch_file, put_file},
        folder::{create_folder, get_folder},
    },
    AppState,
};

#[async_test]
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
    let session = state.sessions.get_by_id(&session_id).await.unwrap();

    let encoded_file_name = session
        .get_encoded_file_name(file_path.into())
        .await
        .unwrap();
    let sharded_path = session.context.blob_path(&encoded_file_name);
    assert!(tokio::fs::metadata(&sharded_path).await.is_ok());

    drop(session);

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
    let session = state.sessions.get_by_id(&session_id).await.unwrap();
    let db_lookup = session.get_encoded_file_name(file_path.into()).await;
    assert!(db_lookup.is_err());
}

#[async_test]
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

#[async_test]
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

#[async_test]
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

async fn patch_client() -> (Client, Cookie<'static>, TestUser) {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/file", routes![put_file, get_file, patch_file])
        .mount("/folder", routes![get_folder]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    (client, cookie, test_user)
}

async fn put(client: &Client, cookie: &Cookie<'static>, path: &str, body: &str) {
    let response = client
        .put(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .body(body)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);
}

async fn patch(client: &Client, cookie: &Cookie<'static>, path: &str, body: &str) -> Status {
    client
        .patch(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .header(ContentType::JSON)
        .body(body)
        .dispatch()
        .await
        .status()
}

async fn get(client: &Client, cookie: &Cookie<'static>, path: &str) -> (Status, String) {
    let response = client
        .get(path.to_string())
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    let status = response.status();

    (status, response.into_string().await.unwrap_or_default())
}

#[async_test]
async fn test_patch_missing_file_is_not_found_and_creates_nothing() {
    let (client, cookie, _test_user) = patch_client().await;

    assert_eq!(
        patch(&client, &cookie, "ghost.txt", r#"{"file_name": "z.txt"}"#).await,
        Status::NotFound
    );
    assert_eq!(
        patch(
            &client,
            &cookie,
            "ghost.txt",
            r#"{"parent_folder_path": "auto/created/dir"}"#
        )
        .await,
        Status::NotFound
    );
    assert_eq!(
        get(&client, &cookie, "/folder/auto").await.0,
        Status::NotFound
    );
}

#[async_test]
async fn test_patch_file_onto_an_existing_name_is_a_conflict() {
    let (client, cookie, _test_user) = patch_client().await;
    put(&client, &cookie, "x.txt", "x").await;
    put(&client, &cookie, "y.txt", "y").await;
    put(&client, &cookie, "dir/x.txt", "dir-x").await;

    assert_eq!(
        patch(&client, &cookie, "x.txt", r#"{"file_name": "y.txt"}"#).await,
        Status::Conflict
    );
    assert_eq!(
        patch(
            &client,
            &cookie,
            "x.txt",
            r#"{"parent_folder_path": "dir"}"#
        )
        .await,
        Status::Conflict
    );

    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (Status::Ok, "x".into())
    );
    assert_eq!(
        get(&client, &cookie, "/file/y.txt").await,
        (Status::Ok, "y".into())
    );
    assert_eq!(
        get(&client, &cookie, "/file/dir/x.txt").await,
        (Status::Ok, "dir-x".into())
    );
}

#[async_test]
async fn test_patch_file_rejects_invalid_names() {
    let (client, cookie, _test_user) = patch_client().await;
    put(&client, &cookie, "x.txt", "x").await;
    let too_long = "n".repeat(256);

    for name in [
        "",
        ".",
        "..",
        "evil/name.txt",
        "evil\\name.txt",
        "nul\u{0}name",
        "line\nbreak",
        too_long.as_str(),
    ] {
        let body = serde_json::json!({ "file_name": name }).to_string();

        assert_eq!(
            patch(&client, &cookie, "x.txt", &body).await,
            Status::BadRequest,
            "name {:?}",
            name
        );
    }

    let body = serde_json::json!({ "parent_folder_path": "ok/bad\u{0}dir" }).to_string();
    assert_eq!(
        patch(&client, &cookie, "x.txt", &body).await,
        Status::BadRequest
    );
    assert_eq!(
        get(&client, &cookie, "/folder/ok").await.0,
        Status::NotFound
    );

    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (Status::Ok, "x".into())
    );
}

// Rename and move happen together or not at all.
#[async_test]
async fn test_patch_file_rename_and_move_is_all_or_nothing() {
    let (client, cookie, _test_user) = patch_client().await;
    put(&client, &cookie, "x.txt", "x").await;
    put(&client, &cookie, "dir/z.txt", "z").await;

    let status = patch(
        &client,
        &cookie,
        "x.txt",
        r#"{"file_name": "z.txt", "parent_folder_path": "dir"}"#,
    )
    .await;

    assert_eq!(status, Status::Conflict);
    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (Status::Ok, "x".into())
    );
    assert_eq!(
        get(&client, &cookie, "/file/z.txt").await.0,
        Status::NotFound
    );

    let status = patch(
        &client,
        &cookie,
        "x.txt",
        r#"{"file_name": "moved.txt", "parent_folder_path": "new/dir"}"#,
    )
    .await;

    assert_eq!(status, Status::NoContent);
    assert_eq!(
        get(&client, &cookie, "/file/new/dir/moved.txt").await,
        (Status::Ok, "x".into())
    );
    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await.0,
        Status::NotFound
    );
}

#[async_test]
async fn test_patch_file_with_nothing_to_change_is_rejected() {
    let (client, cookie, _test_user) = patch_client().await;
    put(&client, &cookie, "x.txt", "x").await;

    assert_eq!(
        patch(&client, &cookie, "x.txt", "{}").await,
        Status::BadRequest
    );

    let unknown_field = patch(&client, &cookie, "x.txt", r#"{"filename": "typo.txt"}"#).await;
    assert!(
        unknown_field.code >= 400 && unknown_field.code < 500,
        "unknown field got {}",
        unknown_field
    );
    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (Status::Ok, "x".into())
    );
}

#[async_test]
async fn test_patch_file_to_its_own_name_is_a_no_op() {
    let (client, cookie, _test_user) = patch_client().await;
    put(&client, &cookie, "x.txt", "x").await;

    assert_eq!(
        patch(&client, &cookie, "x.txt", r#"{"file_name": "x.txt"}"#).await,
        Status::NoContent
    );
    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (Status::Ok, "x".into())
    );
}
