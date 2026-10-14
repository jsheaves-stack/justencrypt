// Files and folders created by upload or `PUT /folder` must follow the same
// naming rule as renames and moves (`util::names::is_valid_entry_name`), so
// every entry that can be created can also be renamed.

use super::*;
use crate::{
    db::sqlite, encryption::FileEncryptionMetadata, enums::db_error::DbError,
    util::names::is_valid_entry_path,
};

// URL-encoded paths whose file or folder name breaks the rule: a control
// character, a backslash, and a 256-byte name.
fn invalid_paths() -> Vec<String> {
    vec![
        "bad%01name.txt".to_string(),
        "dir%5Cfile.txt".to_string(),
        format!("docs/{}", "n".repeat(256)),
        format!("{}/file.txt", "d".repeat(256)),
    ]
}

async fn names_client() -> (TestClient, Cookie<'static>, TestUser) {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    (client, cookie, test_user)
}

async fn assert_bad_request(response: TestResponse, path: &str) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    assert!(
        response
            .into_string()
            .await
            .unwrap()
            .contains("1-255 bytes"),
        "{path}"
    );
}

#[test]
fn test_is_valid_entry_path() {
    for path in ["a.txt", "docs/a.txt", "/docs//a.txt/", "./docs/a.txt", ""] {
        assert!(is_valid_entry_path(path), "{path:?} should be valid");
    }

    for path in [
        "bad\u{1}name.txt",
        "dir\\file.txt",
        "docs/bad\nname",
        &format!("docs/{}", "n".repeat(256)),
    ] {
        assert!(!is_valid_entry_path(path), "{path:?} should be invalid");
    }
}

#[test]
fn test_db_create_functions_reject_invalid_names() {
    let mut db = migrated_db();

    for path in ["bad\u{1}name.txt", "dir\\file.txt", "docs/bad\nname.txt"] {
        let file = sqlite::add_file(&mut db, path, "blob", FileEncryptionMetadata::new());
        let folder = sqlite::add_folder(&mut db, path);

        assert!(
            matches!(file, Err(DbError::InvalidInput(_))),
            "{path:?}: {file:?}"
        );
        assert!(
            matches!(folder, Err(DbError::InvalidInput(_))),
            "{path:?}: {folder:?}"
        );
    }

    // Nothing was created, not even the parent folder of the last path.
    assert!(matches!(
        sqlite::get_folder(&db, "docs"),
        Err(DbError::NotFound)
    ));
}

// These used to be created with a 201.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_put_file_rejects_invalid_names() {
    let (client, cookie, test_user) = names_client().await;

    for path in invalid_paths() {
        let response = client
            .put(format!("/file/{path}"))
            .private_cookie(cookie.clone())
            .body("data")
            .dispatch()
            .await;

        assert_bad_request(response, &path).await;
    }

    // Nothing was stored, and no blob or partial upload was left behind.
    assert!(stored_files(&test_user.path).is_empty());

    let longest = format!("/file/{}", "n".repeat(255));
    let response = client
        .put(&longest)
        .private_cookie(cookie)
        .body("data")
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

// These used to be created with a 201.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_folder_rejects_invalid_names() {
    let (client, cookie, _test_user) = names_client().await;

    for path in invalid_paths() {
        let response = client
            .put(format!("/folder/{path}"))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_bad_request(response, &path).await;
    }

    let response = client
        .get("/folder/")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.into_string().await.unwrap(), "[]");

    let longest = format!("/folder/{}", "d".repeat(255));
    let response = client.put(&longest).private_cookie(cookie).dispatch().await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

// A bad name is reported before the client uploads any chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_init_upload_rejects_invalid_names() {
    let (client, cookie, test_user) = names_client().await;

    for path in invalid_paths() {
        let response = client
            .post(format!("/upload/initiate/{path}"))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_bad_request(response, &path).await;
    }

    let state = client.app();
    let session = state.sessions.snapshot().await.pop().unwrap();

    assert!(session.active_uploads.lock().await.is_empty());
    assert!(
        sqlite::get_all_active_uploads(&session.context.pool().get().unwrap())
            .unwrap()
            .is_empty()
    );
    assert!(stored_files(&test_user.path).is_empty());
}

// Entries created before names were checked on upload stay reachable: only
// creating an entry checks its name.
#[test]
fn test_existing_entries_with_invalid_names_can_still_be_read() {
    let db = migrated_db();

    db.execute(
        "INSERT INTO files (parent_folder_id, name, encoded_name, key) VALUES (1, ?1, 'old-blob', x'00')",
        ["bad\u{1}name.txt"],
    )
    .unwrap();

    assert_eq!(
        sqlite::get_encoded_file_name(&db, "bad\u{1}name.txt").unwrap(),
        "old-blob"
    );
}
