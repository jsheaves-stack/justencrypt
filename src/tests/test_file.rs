use std::{num::NonZeroU64, time::Duration};

use super::*;
use crate::db::sqlite;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_put_file() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "test_file.txt";
    let file_content = "Hello, world!";

    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let state = client.app();
    let session = state.sessions.get_by_id(&session_id).await.unwrap();

    let encoded_file_name = session
        .context
        .get_encoded_file_name(file_path.into())
        .await
        .unwrap();

    let sharded_path = session.context.blob_path(&encoded_file_name);

    assert!(tokio::fs::metadata(sharded_path).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "test_file.txt";
    let file_content = "Hello, world!";

    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_string().await.unwrap();

    assert_eq!(body, file_content);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_put_file_no_auth() {
    let (app, _test_user) = setup_app().await;
    let client = TestClient::new(app);

    let file_path = "test_file.txt";
    let file_content = "Hello, world!";

    let response = client
        .put(format!("/file/{}", file_path))
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_put_file_empty_content() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);

    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "test_file.txt";
    let file_content = "";

    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_range_first_chunk() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "range_test.txt";
    let file_content = "A".repeat(128 * 1024); // 128KB (2 chunks)
    client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(&file_content)
        .dispatch()
        .await;

    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .header("Range", "bytes=0-99")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers().get_one("Content-Range").unwrap(),
        "bytes 0-99/131072"
    );
    assert_eq!(response.into_string().await.unwrap(), "A".repeat(100));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_range_cross_chunks() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "range_test_cross.txt";
    let chunk_size = 64 * 1024;
    let mut file_content = vec![0u8; chunk_size * 2];
    for (i, byte) in file_content.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(&file_content)
        .dispatch()
        .await;

    let start = chunk_size - 10;
    let end = chunk_size + 10;
    let range_header = format!("bytes={}-{}", start, end);

    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .header("Range", range_header)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let body = response.into_bytes().await.unwrap();
    assert_eq!(body.len(), 21);
    assert_eq!(body, file_content[start..=end]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_range_last_byte() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "last_byte.txt";
    let file_content = "Hello World";
    client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;

    let last_index = file_content.len() - 1;
    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .header("Range", format!("bytes={}-{}", last_index, last_index))
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.into_string().await.unwrap(), "d");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_range_no_end() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "no_end.txt";
    let file_content = "0123456789";
    client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;

    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .header("Range", "bytes=5-")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.into_string().await.unwrap(), "56789");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_range_invalid() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "invalid_range.txt";
    client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body("test")
        .dispatch()
        .await;

    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .header("Range", "bytes=10-5")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_put_file_over_the_file_limit_is_rejected_and_leaves_nothing_behind() {
    let (app, test_user) = setup_app_with_config(upload_limits(1000, 1 << 30)).await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .put("/file/too-big.bin")
        .private_cookie(cookie.clone())
        .body(vec![b'A'; 1001])
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let response = client
        .get("/file/too-big.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        stored_files(&test_user.path),
        Vec::<std::path::PathBuf>::new()
    );

    let session = client.app().sessions.get_by_id(&session_id).await.unwrap();
    let db = session.context.pool().get().unwrap();

    assert!(sqlite::get_all_active_uploads(&db).unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_put_file_at_the_file_limit_is_stored_in_full() {
    let (app, test_user) = setup_app_with_config(upload_limits(1000, 1 << 30)).await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .put("/file/exact.bin")
        .private_cookie(cookie.clone())
        .body(vec![b'A'; 1000])
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let response = client
        .get("/file/exact.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.into_bytes().await.unwrap(), vec![b'A'; 1000]);
}

// The returned `TestUser` must be kept alive: dropping it deletes the user's
// data directory.
async fn download_client() -> (TestClient, Cookie<'static>, TestUser) {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    (client, cookie, test_user)
}

async fn upload(client: &TestClient, cookie: &Cookie<'static>, path: &str, body: Vec<u8>) {
    let response = client
        .put(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .body(body)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_empty_file() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "empty.txt", Vec::new()).await;

    let response = client
        .get("/file/empty.txt")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get_one("Content-Length"), Some("0"));
    assert_eq!(response.headers().get_one("Content-Range"), None);
    assert!(response.into_bytes().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_empty_file_with_a_range_is_not_satisfiable() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "empty.txt", Vec::new()).await;

    let response = client
        .get("/file/empty.txt")
        .private_cookie(cookie)
        .header("Range", "bytes=0-")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response.headers().get_one("Content-Range"),
        Some("bytes */0")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_full_file_has_exact_length_and_no_content_range() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "full.bin", vec![b'A'; 70_000]).await;

    let response = client
        .get("/file/full.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get_one("Content-Length"), Some("70000"));
    assert_eq!(response.headers().get_one("Content-Range"), None);
    assert_eq!(response.into_bytes().await.unwrap().len(), 70_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_range_past_the_end_reports_the_file_size() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "short.txt", b"test".to_vec()).await;

    let response = client
        .get("/file/short.txt")
        .private_cookie(cookie)
        .header("Range", "bytes=10-20")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response.headers().get_one("Content-Range"),
        Some("bytes */4")
    );
}

// Encrypted blobs only: `stored_files` without the thumbnail cache.
fn stored_blobs(user_dir: &std::path::Path) -> Vec<String> {
    let cache_dir = user_dir.join(".cache");

    stored_files(user_dir)
        .into_iter()
        .filter(|path| !path.starts_with(&cache_dir))
        .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
        .collect()
}

async fn overwrite(
    client: &TestClient,
    cookie: &Cookie<'static>,
    path: &str,
    fill: u8,
) -> StatusCode {
    client
        .put(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .body(vec![fill; 256 * 1024])
        .dispatch()
        .await
        .status()
}

// M2 regression: concurrent overwrites of one path used to each delete the
// same old blob, leaving all but one of the new blobs unreferenced forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_concurrent_overwrites_leave_exactly_one_blob() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    let session = client.app().sessions.get_by_id(&session_id).await.unwrap();

    upload(&client, &cookie, "shared.bin", vec![b'0'; 10]).await;

    for round in 0..10 {
        let (a, b, c, d) = tokio::join!(
            overwrite(&client, &cookie, "shared.bin", b'A'),
            overwrite(&client, &cookie, "shared.bin", b'B'),
            overwrite(&client, &cookie, "shared.bin", b'C'),
            overwrite(&client, &cookie, "shared.bin", b'D'),
        );

        assert_eq!([a, b, c, d], [StatusCode::CREATED; 4], "round {}", round);

        let referenced = session
            .context
            .get_encoded_file_name("shared.bin".into())
            .await
            .unwrap();

        assert_eq!(
            stored_blobs(&test_user.path),
            vec![referenced],
            "round {}: blobs on disk should be exactly the one the database references",
            round
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_missing_file_is_not_found() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    upload(&client, &cookie, "docs/real.txt", b"x".to_vec()).await;

    for path in ["docs/missing.txt", "no/such/folder/missing.txt"] {
        let response = client
            .delete(format!("/file/{}", path))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {}", path);
    }
}

// The database is the source of truth: once the row is gone the file is gone,
// even if its blob had already disappeared from disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_file_succeeds_when_the_blob_is_already_missing() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    upload(&client, &cookie, "vanished.txt", b"x".to_vec()).await;

    for blob in stored_files(&test_user.path) {
        fs::remove_file(blob).unwrap();
    }

    let response = client
        .delete("/file/vanished.txt")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .get("/file/vanished.txt")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// M11f: the last N bytes of a file.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_suffix_range() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "digits.txt", b"0123456789".to_vec()).await;

    let response = client
        .get("/file/digits.txt")
        .private_cookie(cookie)
        .header("Range", "bytes=-3")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers().get_one("Content-Range"),
        Some("bytes 7-9/10")
    );
    assert_eq!(response.into_string().await.unwrap(), "789");
}

// M11f: a multi-range request gets the whole file.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_multiple_ranges_sends_the_whole_file() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "digits.txt", b"0123456789".to_vec()).await;

    let response = client
        .get("/file/digits.txt")
        .private_cookie(cookie)
        .header("Range", "bytes=0-1,5-6")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get_one("Content-Range"), None);
    assert_eq!(response.into_string().await.unwrap(), "0123456789");
}

// A client that stops reading is cut off after the stall timeout, short of
// the Content-Length, instead of holding the download open forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_is_abandoned_when_the_client_stops_reading() {
    let (app, test_user) = setup_app_with_config(|config| {
        config.download_stall_timeout_seconds = NonZeroU64::new(1).unwrap();
    })
    .await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();

    upload(&client, &cookie, "big.bin", data.clone()).await;

    let response = client
        .get("/file/big.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    // Nothing reads the body while the timeout runs out.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let body = response.into_bytes().await.unwrap();

    assert!(body.len() < data.len(), "{}", body.len());
    assert_eq!(body, &data[..body.len()]);
}

// The encrypted file is opened before the response starts, so one that is
// missing is reported as an error instead of a body cut short.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_file_with_a_missing_blob_is_an_error() {
    let (client, cookie, _test_user) = download_client().await;

    upload(&client, &cookie, "gone.bin", vec![7u8; 1000]).await;

    let state = client.app();
    let session = state.sessions.snapshot().await.pop().unwrap();
    let encoded_name = session
        .context
        .get_encoded_file_name("gone.bin".into())
        .await
        .unwrap();

    std::fs::remove_file(session.context.blob_path(&encoded_name)).unwrap();

    let response = client
        .get("/file/gone.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
