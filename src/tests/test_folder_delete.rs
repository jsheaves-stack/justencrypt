use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_folder_success() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let parent_folder = "parent_folder";
    let child_folder = format!("{}/child_folder", parent_folder);

    // Create folders
    client
        .put(format!("/folder/{}", parent_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    client
        .put(format!("/folder/{}", child_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    // Create a file inside the child folder
    let file_path = format!("{}/test.txt", child_folder);
    client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body("test content")
        .dispatch()
        .await;

    // Delete the root parent folder (should recursively delete everything)
    let response = client
        .delete(format!("/folder/{}", parent_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify folder is gone
    let session = client.app().sessions.get_by_id(&session_id).await.unwrap();

    // The DB query should fail because the folder doesn't exist
    let lookup_result = session.context.get_folder_id(parent_folder.into()).await;
    assert!(lookup_result.is_err() || lookup_result.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_folder_not_found() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .delete("/folder/does_not_exist")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

async fn put_text(client: &TestClient, cookie: &Cookie<'static>, path: &str) {
    let response = client
        .put(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .body("content")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

// M7: deleting the root used to delete every file and folder first, then fail
// on the root itself, wiping the account and still returning 500.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_root_folder_is_rejected_and_deletes_nothing() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    put_text(&client, &cookie, "top.txt").await;
    put_text(&client, &cookie, "docs/nested/deep.txt").await;
    let blobs_before = stored_files(&test_user.path).len();

    for root in ["/folder/", "/folder"] {
        let response = client
            .delete(root)
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "DELETE {}",
            root
        );
    }

    for path in ["top.txt", "docs/nested/deep.txt"] {
        let response = client
            .get(format!("/file/{}", path))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::OK, "{} should survive", path);
    }

    assert_eq!(stored_files(&test_user.path).len(), blobs_before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_folder_tree_removes_every_file_and_leaves_siblings() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    put_text(&client, &cookie, "doomed/a.txt").await;
    put_text(&client, &cookie, "doomed/sub/b.txt").await;
    put_text(&client, &cookie, "doomed/sub/deeper/c.txt").await;
    put_text(&client, &cookie, "kept/d.txt").await;
    put_text(&client, &cookie, "e.txt").await;

    let response = client
        .delete("/folder/doomed")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(stored_files(&test_user.path).len(), 2);

    for (path, expected) in [
        ("/folder/doomed", StatusCode::NOT_FOUND),
        ("/folder/doomed/sub", StatusCode::NOT_FOUND),
        ("/file/doomed/sub/b.txt", StatusCode::NOT_FOUND),
        ("/file/kept/d.txt", StatusCode::OK),
        ("/file/e.txt", StatusCode::OK),
    ] {
        let response = client
            .get(path)
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), expected, "GET {}", path);
    }

    // The deleted folder is gone from the root listing; its sibling isn't.
    let response = client
        .get("/folder/")
        .private_cookie(cookie)
        .dispatch()
        .await;
    let listing: serde_json::Value = response.into_json().await.unwrap();
    let names: Vec<&str> = listing
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["file_name"].as_str().unwrap())
        .collect();

    assert!(!names.contains(&"doomed"), "listing: {:?}", names);
    assert!(names.contains(&"kept"), "listing: {:?}", names);
}
