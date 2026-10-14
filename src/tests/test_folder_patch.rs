use std::time::Duration;

use tokio::time::timeout;

use super::*;
use crate::web::routes::folder::PatchFolderData;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_folder_rename() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let folder_path = "old_folder";
    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let patch_data = PatchFolderData {
        folder_name: Some("new_folder".to_string()),
        parent_folder_path: None,
    };

    let response = client
        .patch(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .json(&patch_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let get_response = client
        .get("/folder/new_folder")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(get_response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_folder_move() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let folder_path = "source_folder";
    let dest_path = "dest_folder";

    client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    client
        .put(format!("/folder/{}", dest_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    let patch_data = PatchFolderData {
        folder_name: None,
        parent_folder_path: Some(dest_path.to_string()),
    };

    let response = client
        .patch(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .json(&patch_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let get_response = client
        .get(format!("/folder/{}/{}", dest_path, folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(get_response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_folder_move_into_self_fails() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let folder_path = "source_folder";

    client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    let patch_data = PatchFolderData {
        folder_name: None,
        parent_folder_path: Some(format!("{}/child", folder_path)),
    };

    let response = client
        .patch(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .json(&patch_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// A folder-cycle regression used to hang the request forever, and the stuck
// blocking thread would then wedge the whole test binary. If that ever happens
// again, fail loudly by exiting instead.
async fn move_folder_or_exit(
    client: &TestClient,
    cookie: &Cookie<'static>,
    folder: &str,
    destination: &str,
) -> TestResponse {
    let request = client
        .patch(format!("/folder/{}", folder))
        .private_cookie(cookie.clone())
        .json(&PatchFolderData {
            folder_name: None,
            parent_folder_path: Some(destination.to_string()),
        });

    match timeout(Duration::from_secs(5), request.dispatch()).await {
        Ok(response) => response,
        Err(_) => {
            eprintln!(
                "PATCH /folder/{} hung for destination '{}'",
                folder, destination
            );

            std::process::exit(1);
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_folder_move_into_own_subtree_is_rejected_for_every_path_spelling() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .put("/folder/a/b/c")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    for destination in [
        "a/b",
        "a/b/c",
        "a/./b/c",
        "a/b/../b/c",
        "a//b/c",
        "./a/b/c",
        "/a/b/c",
        "a/b/c/",
    ] {
        let response = move_folder_or_exit(&client, &cookie, "a/b", destination).await;

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "destination '{}'",
            destination
        );
    }

    let response = client
        .get("/folder/a/b/c")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_rejected_folder_move_does_not_leave_new_folders_behind() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    client
        .put("/folder/a/b")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    // Resolves to a/b/new, so the move is a cycle, but only after the missing
    // destination folder has been created.
    let response = move_folder_or_exit(&client, &cookie, "a/b", "a//b/new").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = client
        .get("/folder/a/b/new")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_folder_move_creates_a_missing_destination() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    client
        .put("/folder/a/b")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    let response = move_folder_or_exit(&client, &cookie, "a/b", "x/y").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let moved = client
        .get("/folder/x/y/b")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(moved.status(), StatusCode::OK);

    let old = client
        .get("/folder/a/b")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(old.status(), StatusCode::NOT_FOUND);
}

async fn folder_client() -> (TestClient, Cookie<'static>, TestUser) {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    (client, cookie, test_user)
}

async fn make_folder(client: &TestClient, cookie: &Cookie<'static>, path: &str) {
    let response = client
        .put(format!("/folder/{}", path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn patch_raw(
    client: &TestClient,
    cookie: &Cookie<'static>,
    path: &str,
    body: &str,
) -> StatusCode {
    client
        .patch(format!("/folder/{}", path))
        .private_cookie(cookie.clone())
        .header("Content-Type", "application/json")
        .body(body)
        .dispatch()
        .await
        .status()
}

async fn folder_exists(client: &TestClient, cookie: &Cookie<'static>, path: &str) -> bool {
    client
        .get(format!("/folder/{}", path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await
        .status()
        == StatusCode::OK
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_missing_folder_is_not_found_and_creates_nothing() {
    let (client, cookie, _test_user) = folder_client().await;

    assert_eq!(
        patch_raw(&client, &cookie, "ghost", r#"{"folder_name": "z"}"#).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        patch_raw(
            &client,
            &cookie,
            "ghost",
            r#"{"parent_folder_path": "auto/dir"}"#
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert!(!folder_exists(&client, &cookie, "auto").await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_folder_onto_an_existing_name_is_a_conflict() {
    let (client, cookie, _test_user) = folder_client().await;
    make_folder(&client, &cookie, "a").await;
    make_folder(&client, &cookie, "b").await;
    make_folder(&client, &cookie, "dest/a").await;

    assert_eq!(
        patch_raw(&client, &cookie, "a", r#"{"folder_name": "b"}"#).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        patch_raw(&client, &cookie, "a", r#"{"parent_folder_path": "dest"}"#).await,
        StatusCode::CONFLICT
    );
    // Rename and move together: nothing changes when the move collides.
    assert_eq!(
        patch_raw(
            &client,
            &cookie,
            "b",
            r#"{"folder_name": "a", "parent_folder_path": "dest"}"#
        )
        .await,
        StatusCode::CONFLICT
    );

    for path in ["a", "b", "dest/a"] {
        assert!(
            folder_exists(&client, &cookie, path).await,
            "{} should remain",
            path
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_patch_folder_rejects_invalid_names() {
    let (client, cookie, _test_user) = folder_client().await;
    make_folder(&client, &cookie, "a").await;

    for name in ["", ".", "..", "x/y", "x\\y", "nul\u{0}", &"n".repeat(256)] {
        let body = serde_json::json!({ "folder_name": name }).to_string();

        assert_eq!(
            patch_raw(&client, &cookie, "a", &body).await,
            StatusCode::BAD_REQUEST,
            "name {:?}",
            name
        );
    }

    assert_eq!(
        patch_raw(&client, &cookie, "a", "{}").await,
        StatusCode::BAD_REQUEST
    );
    assert!(folder_exists(&client, &cookie, "a").await);
}
