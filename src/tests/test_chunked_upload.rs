use std::{
    num::NonZeroUsize,
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::time::timeout;

use super::*;
use crate::{
    app::App, db::sqlite, encryption::CHUNK_SIZE, session::user_session::UserSession,
    web::routes::upload::InitUploadResponse,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_chunked_upload_success() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "chunked_test.txt";

    // 1. Initialize
    let response = client
        .post(format!("/upload/initiate/{}", file_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let init_res: InitUploadResponse = response.into_json().await.unwrap();
    let upload_id = init_res.upload_id;

    // 2. Upload Chunks
    let chunk1 = "A".repeat(CHUNK_SIZE);
    let chunk2 = "B".repeat(CHUNK_SIZE / 2);

    let response = client
        .put(format!("/upload/chunk/{}?offset=0", upload_id))
        .private_cookie(cookie.clone())
        .body(&chunk1)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .put(format!("/upload/chunk/{}?offset={}", upload_id, CHUNK_SIZE))
        .private_cookie(cookie.clone())
        .body(&chunk2)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 3. Finalize
    let total_size = (CHUNK_SIZE + CHUNK_SIZE / 2) as u64;
    let response = client
        .post(format!(
            "/upload/finalize/{}?total_size={}",
            upload_id, total_size
        ))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // 4. Verify Download
    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_string().await.unwrap();
    assert_eq!(body, format!("{}{}", chunk1, chunk2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_chunked_upload_missing_chunks() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let file_path = "missing_chunk_test.txt";

    // 1. Initialize
    let response = client
        .post(format!("/upload/initiate/{}", file_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    let init_res: InitUploadResponse = response.into_json().await.unwrap();
    let upload_id = init_res.upload_id;

    // 2. Upload only second chunk
    let chunk2 = "B".repeat(CHUNK_SIZE);
    let response = client
        .put(format!("/upload/chunk/{}?offset={}", upload_id, CHUNK_SIZE))
        .private_cookie(cookie.clone())
        .body(&chunk2)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 3. Finalize (should fail)
    let total_size = (CHUNK_SIZE * 2) as u64;
    let response = client
        .post(format!(
            "/upload/finalize/{}?total_size={}",
            upload_id, total_size
        ))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error_msg = response.into_string().await.unwrap();
    assert!(error_msg.contains("Missing chunks: [0]"));

    // 4. Upload missing first chunk
    let chunk1 = "A".repeat(CHUNK_SIZE);
    let response = client
        .put(format!("/upload/chunk/{}?offset=0", upload_id))
        .private_cookie(cookie.clone())
        .body(&chunk1)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 5. Finalize again (should succeed)
    let response = client
        .post(format!(
            "/upload/finalize/{}?total_size={}",
            upload_id, total_size
        ))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_chunked_upload_unauthorized() {
    let (app, _test_user) = setup_app().await;

    let client = TestClient::new(app);

    let response = client
        .post("/upload/initiate/unauthorized.txt")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_chunked_upload_invalid_offset() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .post("/upload/initiate/invalid_offset.txt")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    let init_res: InitUploadResponse = response.into_json().await.unwrap();
    let upload_id = init_res.upload_id;

    let response = client
        .put(format!("/upload/chunk/{}?offset=100", upload_id))
        .private_cookie(cookie)
        .body("data")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_chunked_upload_not_found() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .put("/upload/chunk/non-existent-id?offset=0")
        .private_cookie(cookie)
        .body("data")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// Pretends an upload was last touched `age` ago.
async fn backdate_upload(session: &UserSession, upload_id: &str, age: Duration) {
    let uploads = session.active_uploads.lock().await;
    let state = uploads.get(upload_id).expect("upload should be active");
    let last_updated = SystemTime::now() - age;

    state.last_updated.store(
        last_updated.duration_since(UNIX_EPOCH).unwrap().as_secs(),
        Ordering::Relaxed,
    );
}

async fn part_path_of(session: &UserSession, upload_id: &str) -> std::path::PathBuf {
    let encoded_file_name = session
        .active_uploads
        .lock()
        .await
        .get(upload_id)
        .expect("upload should be active")
        .encoded_file_name
        .clone();

    session.context.upload_part_path(&encoded_file_name)
}

fn active_upload_rows(session: &UserSession) -> Vec<String> {
    let db = session.context.pool().get().unwrap();

    sqlite::get_all_active_uploads(&db)
        .unwrap()
        .into_iter()
        .map(|(upload_id, _, _)| upload_id)
        .collect()
}

async fn initiate(client: &TestClient, cookie: &Cookie<'static>, name: &str) -> String {
    let response = timeout(
        Duration::from_secs(5),
        client
            .post(format!("/upload/initiate/{}", name))
            .private_cookie(cookie.clone())
            .dispatch(),
    )
    .await
    .expect("init_upload hung (deadlock)");

    assert_eq!(response.status(), StatusCode::OK);

    response
        .into_json::<InitUploadResponse>()
        .await
        .unwrap()
        .upload_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_init_upload_reclaims_stale_upload_instead_of_hanging() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    let session = client.app().sessions.get_by_id(&session_id).await.unwrap();

    let stale_id = initiate(&client, &cookie, "stale.txt").await;
    let fresh_id = initiate(&client, &cookie, "fresh.txt").await;
    let stale_part = part_path_of(&session, &stale_id).await;
    let fresh_part = part_path_of(&session, &fresh_id).await;
    backdate_upload(&session, &stale_id, Duration::from_secs(25 * 60 * 60)).await;

    assert!(stale_part.exists());
    assert!(active_upload_rows(&session).contains(&stale_id));

    let new_id = initiate(&client, &cookie, "c.txt").await;

    assert!(!stale_part.exists(), "stale .part file should be removed");
    assert!(!active_upload_rows(&session).contains(&stale_id));
    assert!(fresh_part.exists(), "fresh upload must be left alone");

    let uploads = session.active_uploads.lock().await;

    assert!(!uploads.contains_key(&stale_id));
    assert!(uploads.contains_key(&fresh_id));
    assert!(uploads.contains_key(&new_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_stale_uploads_do_not_count_against_the_upload_limit() {
    let (app, test_user) =
        setup_app_with_config(|config| config.max_active_uploads = NonZeroUsize::new(2)).await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    let session = client.app().sessions.get_by_id(&session_id).await.unwrap();

    let stale_id = initiate(&client, &cookie, "stale.txt").await;
    let kept_id = initiate(&client, &cookie, "kept.txt").await;
    backdate_upload(&session, &stale_id, Duration::from_secs(25 * 60 * 60)).await;

    // The session is at its limit, but only because of the stale upload.
    let new_id = initiate(&client, &cookie, "replacement.txt").await;

    {
        let uploads = session.active_uploads.lock().await;

        assert_eq!(uploads.len(), 2);
        assert!(uploads.contains_key(&kept_id));
        assert!(uploads.contains_key(&new_id));
    }

    // The limit is still enforced, and a rejected request leaves nothing behind.
    let response = client
        .post("/upload/initiate/one-too-many.txt")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(active_upload_rows(&session).len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_sweep_stale_uploads_uses_the_given_ttl() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    let session = client.app().sessions.get_by_id(&session_id).await.unwrap();

    let old_id = initiate(&client, &cookie, "old.txt").await;
    let recent_id = initiate(&client, &cookie, "recent.txt").await;
    let old_part = part_path_of(&session, &old_id).await;
    let recent_part = part_path_of(&session, &recent_id).await;
    backdate_upload(&session, &old_id, Duration::from_secs(120)).await;
    backdate_upload(&session, &recent_id, Duration::from_secs(10)).await;

    session.sweep_stale_uploads(Duration::from_secs(60)).await;

    let uploads = session.active_uploads.lock().await;

    assert!(!uploads.contains_key(&old_id));
    assert!(uploads.contains_key(&recent_id));
    assert!(!old_part.exists());
    assert!(recent_part.exists());
    assert_eq!(active_upload_rows(&session), vec![recent_id]);
}

async fn upload_client(app: Arc<App>, test_user: &TestUser) -> (TestClient, Cookie<'static>) {
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    (client, cookie)
}

async fn put_chunk(
    client: &TestClient,
    cookie: &Cookie<'static>,
    upload_id: &str,
    offset: u64,
    body: Vec<u8>,
) -> StatusCode {
    client
        .put(format!("/upload/chunk/{}?offset={}", upload_id, offset))
        .private_cookie(cookie.clone())
        .body(body)
        .dispatch()
        .await
        .status()
}

async fn finalize(
    client: &TestClient,
    cookie: &Cookie<'static>,
    upload_id: &str,
    total_size: u64,
) -> (StatusCode, String) {
    let response = client
        .post(format!(
            "/upload/finalize/{}?total_size={}",
            upload_id, total_size
        ))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    let status = response.status();

    (status, response.into_string().await.unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_finalize_rejects_a_huge_total_size_quickly() {
    let (app, test_user) = setup_app().await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "huge.bin").await;

    for total_size in [1u64 << 40, u64::MAX] {
        let started = std::time::Instant::now();
        let (status, body) = finalize(&client, &cookie, &upload_id, total_size).await;

        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "total_size {}",
            total_size
        );
        assert!(body.len() < 2048, "response body was {} bytes", body.len());
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_finalize_caps_the_list_of_missing_chunks() {
    let (app, test_user) = setup_app().await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "sparse.bin").await;

    let (status, body) = finalize(&client, &cookie, &upload_id, 200 * CHUNK_SIZE as u64).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("Missing chunks: [0, 1, 2,"), "body: {}", body);
    assert!(body.contains("(and 100 more)"), "body: {}", body);
    assert!(body.len() < 2048, "response body was {} bytes", body.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_finalize_rejects_a_total_size_that_does_not_match_the_data() {
    let (app, test_user) = setup_app().await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "small.txt").await;

    assert_eq!(
        put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; 10]).await,
        StatusCode::NO_CONTENT
    );

    for claimed in [CHUNK_SIZE as u64, 11, 9, 0] {
        let (status, body) = finalize(&client, &cookie, &upload_id, claimed).await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "claimed {}: {}",
            claimed,
            body
        );
    }

    // The upload is still active, so the client can finalize with the real size.
    let (status, _) = finalize(&client, &cookie, &upload_id, 10).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_finalize_rejects_a_short_chunk_in_the_middle_of_the_file() {
    let (app, test_user) = setup_app().await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "holey.bin").await;

    put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; 10]).await;
    put_chunk(
        &client,
        &cookie,
        &upload_id,
        CHUNK_SIZE as u64,
        vec![b'B'; CHUNK_SIZE],
    )
    .await;

    let (status, _) = finalize(&client, &cookie, &upload_id, 2 * CHUNK_SIZE as u64).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reuploading_a_shorter_last_chunk_downloads_correctly() {
    let (app, test_user) = setup_app().await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "retried.bin").await;

    put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; CHUNK_SIZE]).await;
    put_chunk(
        &client,
        &cookie,
        &upload_id,
        CHUNK_SIZE as u64,
        vec![b'B'; CHUNK_SIZE],
    )
    .await;
    // The client retries the last chunk, and this time it is shorter.
    put_chunk(
        &client,
        &cookie,
        &upload_id,
        CHUNK_SIZE as u64,
        vec![b'C'; 100],
    )
    .await;

    let (status, body) = finalize(&client, &cookie, &upload_id, CHUNK_SIZE as u64 + 100).await;
    assert_eq!(status, StatusCode::CREATED, "{}", body);

    let response = client
        .get("/file/retried.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_bytes().await.unwrap();
    let mut expected = vec![b'A'; CHUNK_SIZE];
    expected.extend(vec![b'C'; 100]);

    assert_eq!(body.len(), expected.len());
    assert!(body == expected, "downloaded content does not match");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_empty_chunked_upload_can_be_finalized() {
    let (app, test_user) = setup_app().await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "empty.bin").await;

    let (status, body) = finalize(&client, &cookie, &upload_id, 0).await;

    assert_eq!(status, StatusCode::CREATED, "{}", body);

    let response = client
        .get("/file/empty.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get_one("Content-Length"), Some("0"));
    assert!(response.into_bytes().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_chunk_request_over_the_chunk_limit_is_rejected() {
    let (app, test_user) =
        setup_app_with_config(upload_limits(1 << 30, 2 * CHUNK_SIZE as u64)).await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "big-request.bin").await;

    let at_limit = put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; 2 * CHUNK_SIZE]).await;
    assert_eq!(at_limit, StatusCode::NO_CONTENT);

    let over_limit = put_chunk(
        &client,
        &cookie,
        &upload_id,
        0,
        vec![b'A'; 2 * CHUNK_SIZE + 1],
    )
    .await;
    assert_eq!(over_limit, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_chunks_past_the_file_limit_are_rejected() {
    let (app, test_user) =
        setup_app_with_config(upload_limits(2 * CHUNK_SIZE as u64, 1 << 30)).await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "past-the-end.bin").await;

    // Starts inside the limit, but runs past it.
    let straddling = put_chunk(
        &client,
        &cookie,
        &upload_id,
        CHUNK_SIZE as u64,
        vec![b'A'; CHUNK_SIZE + 1],
    )
    .await;
    assert_eq!(straddling, StatusCode::PAYLOAD_TOO_LARGE);

    // Starts exactly at the limit.
    let at_the_end = put_chunk(
        &client,
        &cookie,
        &upload_id,
        2 * CHUNK_SIZE as u64,
        vec![b'A'; 1],
    )
    .await;
    assert_eq!(at_the_end, StatusCode::PAYLOAD_TOO_LARGE);

    // Filling the file exactly up to the limit is fine.
    let exact = put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; 2 * CHUNK_SIZE]).await;
    assert_eq!(exact, StatusCode::NO_CONTENT);

    let (status, body) = finalize(&client, &cookie, &upload_id, 2 * CHUNK_SIZE as u64).await;
    assert_eq!(status, StatusCode::CREATED, "{}", body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_finalize_rejects_a_total_size_over_the_file_limit() {
    let (app, test_user) = setup_app_with_config(upload_limits(1000, 1 << 30)).await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "claimed-too-big.bin").await;

    let (status, _) = finalize(&client, &cookie, &upload_id, 1001).await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

// M7: a finalize whose database write fails must not leave the upload's
// tracking row (or its data) behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_failed_finalize_leaves_no_upload_behind() {
    let (app, test_user) = setup_app().await;
    let (client, cookie) = upload_client(app, &test_user).await;
    let upload_id = initiate(&client, &cookie, "doomed.bin").await;
    put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; 10]).await;

    // Make every insert into `files` fail, in this test's own database.
    let state = client.app();
    let session = state.sessions.snapshot().await.pop().unwrap();
    session
        .context
        .pool()
        .get()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_file_insert BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();

    let (status, _) = finalize(&client, &cookie, &upload_id, 10).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(active_upload_rows(&session).is_empty());
    assert_eq!(
        stored_files(&test_user.path),
        Vec::<std::path::PathBuf>::new()
    );
}
