use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use uuid::Uuid;

use super::*;
use crate::{
    session::{orphans::remove_orphaned_files, policy::SessionPolicy},
    util::sharded_path::sharded_path,
};

// Creates `path` and its directories.
fn stored_file(path: &Path) -> PathBuf {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"x").unwrap();

    path.to_path_buf()
}

fn sharded(base: PathBuf, name: &str) -> PathBuf {
    sharded_path(base, name)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_remove_orphaned_files_removes_only_unreferenced_files() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    let session = client.app().sessions.get_by_id(&session_id).await.unwrap();

    let response = client
        .put("/file/kept.txt")
        .private_cookie(cookie)
        .body("content")
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let user = test_user.path.clone();
    let cache = user.join(".cache");
    let referenced = session
        .context
        .get_encoded_file_name("kept.txt".into())
        .await
        .unwrap();

    let in_progress = Uuid::new_v4().to_string();
    session
        .context
        .add_active_upload(
            in_progress.clone(),
            session.session_id.clone(),
            in_progress.clone(),
            "upload.bin".into(),
        )
        .await
        .unwrap();

    let kept = [
        sharded(user.clone(), &referenced),
        stored_file(&sharded(cache.clone(), &referenced)),
        stored_file(&sharded(user.clone(), &in_progress).with_extension("part")),
        // Not named like anything the server creates.
        stored_file(&user.join("ab").join("notes.txt")),
        // Directly in the user's directory, next to the database.
        stored_file(&user.join(Uuid::new_v4().to_string())),
    ];
    let removed = [
        stored_file(&sharded(user.clone(), &Uuid::new_v4().to_string())),
        stored_file(&sharded(cache.clone(), &Uuid::new_v4().to_string())),
        // A thumbnail temp file left behind by a crash.
        stored_file(
            &sharded(cache.clone(), &referenced).with_file_name(format!("{}.part", Uuid::new_v4())),
        ),
        stored_file(&sharded(user.clone(), &Uuid::new_v4().to_string()).with_extension("part")),
    ];

    let count = remove_orphaned_files(&session).await.unwrap();

    assert_eq!(count, removed.len());

    for path in &kept {
        assert!(path.exists(), "{:?} should have been kept", path);
    }

    for path in &removed {
        assert!(!path.exists(), "{:?} should have been removed", path);
    }
}

// Logs in, then gives the background scan a moment to finish.
async fn log_in_and_wait(client: &TestClient, username: &str) {
    let response = client
        .post("/session")
        .header("Content-Type", "application/json")
        .body(serde_json::json!({ "username": username, "password": "test_password" }).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_every_login_scans_for_orphans_only_when_enabled() {
    for enabled in [false, true] {
        let (app, test_user) = setup_app_with_options(SessionPolicy::default(), enabled, 1).await;
        let client = TestClient::new(app);

        // Sets up the account.
        let _ = create_test_session(client.app(), test_user.name.clone()).await;

        let first = stored_file(&sharded(
            test_user.path.clone(),
            &Uuid::new_v4().to_string(),
        ));

        log_in_and_wait(&client, &test_user.name).await;

        assert_eq!(first.exists(), !enabled, "scan enabled: {}", enabled);

        // A later login scans again.
        let second = stored_file(&sharded(
            test_user.path.clone(),
            &Uuid::new_v4().to_string(),
        ));

        log_in_and_wait(&client, &test_user.name).await;

        assert_eq!(second.exists(), !enabled, "scan enabled: {}", enabled);
    }
}
