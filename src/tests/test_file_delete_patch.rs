use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_file_success() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "to_be_deleted.txt";
    let file_content = "Hello, world!";

    // Create the file first
    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Get internal paths to verify deletion later
    let state = client.app();
    let session = state.sessions.get_by_id(&session_id).await.unwrap();

    let encoded_file_name = session
        .context
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

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify it's gone from disk
    assert!(tokio::fs::metadata(&sharded_path).await.is_err());

    // Verify it's gone from DB
    let session = state.sessions.get_by_id(&session_id).await.unwrap();
    let db_lookup = session
        .context
        .get_encoded_file_name(file_path.into())
        .await;
    assert!(db_lookup.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_file_rename() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

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
        .header("Content-Type", "application/json")
        .body(patch_payload)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Try fetching with new name
    let response = client
        .get(format!("/file/{}", new_name))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    // Old name should fail
    let response = client
        .get(format!("/file/{}", original_name))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_ne!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_file_move() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

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
        .header("Content-Type", "application/json")
        .body(patch_payload)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify it's in the new folder
    let response = client
        .get(format!("/file/{}/{}", folder_name, file_name))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_not_found() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .get("/file/does_not_exist.txt")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

async fn patch_client() -> (TestClient, Cookie<'static>, TestUser) {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    (client, cookie, test_user)
}

async fn put(client: &TestClient, cookie: &Cookie<'static>, path: &str, body: &str) {
    let response = client
        .put(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .body(body)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn patch(
    client: &TestClient,
    cookie: &Cookie<'static>,
    path: &str,
    body: &str,
) -> StatusCode {
    client
        .patch(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .header("Content-Type", "application/json")
        .body(body)
        .dispatch()
        .await
        .status()
}

async fn get(client: &TestClient, cookie: &Cookie<'static>, path: &str) -> (StatusCode, String) {
    let response = client
        .get(path.to_string())
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    let status = response.status();

    (status, response.into_string().await.unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_missing_file_is_not_found_and_creates_nothing() {
    let (client, cookie, _test_user) = patch_client().await;

    assert_eq!(
        patch(&client, &cookie, "ghost.txt", r#"{"file_name": "z.txt"}"#).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        patch(
            &client,
            &cookie,
            "ghost.txt",
            r#"{"parent_folder_path": "auto/created/dir"}"#
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&client, &cookie, "/folder/auto").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_file_onto_an_existing_name_is_a_conflict() {
    let (client, cookie, _test_user) = patch_client().await;
    put(&client, &cookie, "x.txt", "x").await;
    put(&client, &cookie, "y.txt", "y").await;
    put(&client, &cookie, "dir/x.txt", "dir-x").await;

    assert_eq!(
        patch(&client, &cookie, "x.txt", r#"{"file_name": "y.txt"}"#).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        patch(
            &client,
            &cookie,
            "x.txt",
            r#"{"parent_folder_path": "dir"}"#
        )
        .await,
        StatusCode::CONFLICT
    );

    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (StatusCode::OK, "x".into())
    );
    assert_eq!(
        get(&client, &cookie, "/file/y.txt").await,
        (StatusCode::OK, "y".into())
    );
    assert_eq!(
        get(&client, &cookie, "/file/dir/x.txt").await,
        (StatusCode::OK, "dir-x".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
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
            StatusCode::BAD_REQUEST,
            "name {:?}",
            name
        );
    }

    let body = serde_json::json!({ "parent_folder_path": "ok/bad\u{0}dir" }).to_string();
    assert_eq!(
        patch(&client, &cookie, "x.txt", &body).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&client, &cookie, "/folder/ok").await.0,
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (StatusCode::OK, "x".into())
    );
}

// Rename and move happen together or not at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
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

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (StatusCode::OK, "x".into())
    );
    assert_eq!(
        get(&client, &cookie, "/file/z.txt").await.0,
        StatusCode::NOT_FOUND
    );

    let status = patch(
        &client,
        &cookie,
        "x.txt",
        r#"{"file_name": "moved.txt", "parent_folder_path": "new/dir"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        get(&client, &cookie, "/file/new/dir/moved.txt").await,
        (StatusCode::OK, "x".into())
    );
    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_file_with_nothing_to_change_is_rejected() {
    let (client, cookie, _test_user) = patch_client().await;
    put(&client, &cookie, "x.txt", "x").await;

    assert_eq!(
        patch(&client, &cookie, "x.txt", "{}").await,
        StatusCode::BAD_REQUEST
    );

    let unknown_field = patch(&client, &cookie, "x.txt", r#"{"filename": "typo.txt"}"#).await;
    assert!(
        unknown_field.is_client_error(),
        "unknown field got {}",
        unknown_field
    );
    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (StatusCode::OK, "x".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_file_to_its_own_name_is_a_no_op() {
    let (client, cookie, _test_user) = patch_client().await;
    put(&client, &cookie, "x.txt", "x").await;

    assert_eq!(
        patch(&client, &cookie, "x.txt", r#"{"file_name": "x.txt"}"#).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        get(&client, &cookie, "/file/x.txt").await,
        (StatusCode::OK, "x".into())
    );
}
