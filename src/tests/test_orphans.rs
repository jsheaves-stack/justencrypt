use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use rocket::{
    async_test,
    http::{ContentType, Status},
    local::asynchronous::Client,
    routes,
};
use uuid::Uuid;

use super::*;
use crate::{
    routes::{file::put_file, session::create_session},
    session::{
        orphans::{is_enabled_value, remove_orphaned_files},
        policy::SessionPolicy,
    },
    util::sharded_path::get_sharded_path,
    AppState,
};

// Creates `path` and its directories.
fn stored_file(path: &Path) -> PathBuf {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"x").unwrap();

    path.to_path_buf()
}

async fn sharded(base: PathBuf, name: &str) -> PathBuf {
    get_sharded_path(base, &name.to_string()).await
}

#[async_test]
async fn test_remove_orphaned_files_removes_only_unreferenced_files() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![put_file]);
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    let session = client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions
        .get_by_id(&session_id)
        .await
        .unwrap();

    let response = client
        .put("/file/kept.txt")
        .private_cookie(cookie)
        .body("content")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    let user = test_user.path.clone();
    let cache = user.join(".cache");
    let referenced = session
        .get_encoded_file_name("kept.txt".into())
        .await
        .unwrap();

    let in_progress = Uuid::new_v4().to_string();
    session
        .add_active_upload_db(
            in_progress.clone(),
            in_progress.clone(),
            "upload.bin".into(),
        )
        .await
        .unwrap();

    let kept = [
        sharded(user.clone(), &referenced).await,
        stored_file(&sharded(cache.clone(), &referenced).await),
        stored_file(
            &sharded(user.clone(), &in_progress)
                .await
                .with_extension("part"),
        ),
        // Not named like anything the server creates.
        stored_file(&user.join("ab").join("notes.txt")),
        // Directly in the user's directory, next to the database.
        stored_file(&user.join(Uuid::new_v4().to_string())),
    ];
    let removed = [
        stored_file(&sharded(user.clone(), &Uuid::new_v4().to_string()).await),
        stored_file(&sharded(cache.clone(), &Uuid::new_v4().to_string()).await),
        stored_file(
            &sharded(user.clone(), &Uuid::new_v4().to_string())
                .await
                .with_extension("part"),
        ),
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

#[test]
fn test_orphan_scan_is_off_unless_explicitly_enabled() {
    for value in [
        None,
        Some(""),
        Some("false"),
        Some("0"),
        Some("no"),
        Some("nonsense"),
    ] {
        assert!(!is_enabled_value(value), "{:?}", value);
    }

    for value in [Some("true"), Some("TRUE"), Some("1"), Some(" yes ")] {
        assert!(is_enabled_value(value), "{:?}", value);
    }
}

// Logs in, then gives the background scan a moment to finish.
async fn log_in_and_wait(client: &Client, username: &str) {
    let response = client
        .post("/session")
        .header(ContentType::JSON)
        .body(serde_json::json!({ "username": username, "password": "test_password" }).to_string())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    rocket::tokio::time::sleep(Duration::from_millis(500)).await;
}

#[async_test]
async fn test_every_login_scans_for_orphans_only_when_enabled() {
    for enabled in [false, true] {
        let (rocket, test_user) =
            setup_rocket_with_options(SessionPolicy::default(), enabled).await;
        let rocket = rocket.mount("/session", routes![create_session]);
        let client = Client::tracked(rocket)
            .await
            .expect("valid rocket instance");

        // Sets up the account.
        let _ = create_test_session(client.rocket(), test_user.name.clone()).await;

        let first =
            stored_file(&sharded(test_user.path.clone(), &Uuid::new_v4().to_string()).await);

        log_in_and_wait(&client, &test_user.name).await;

        assert_eq!(first.exists(), !enabled, "scan enabled: {}", enabled);

        // A later login scans again.
        let second =
            stored_file(&sharded(test_user.path.clone(), &Uuid::new_v4().to_string()).await);

        log_in_and_wait(&client, &test_user.name).await;

        assert_eq!(second.exists(), !enabled, "scan enabled: {}", enabled);
    }
}
