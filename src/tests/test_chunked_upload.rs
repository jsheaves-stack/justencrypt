use std::{
    env,
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rocket::{
    async_test,
    http::{Cookie, Status},
    local::asynchronous::Client,
    routes,
    tokio::time::timeout,
    Build, Rocket,
};

use super::*;
use crate::{
    db::sqlite,
    encryption::CHUNK_SIZE,
    routes::file::{finalize_upload, get_file, init_upload, upload_chunk, InitUploadResponse},
    session::user_session::UserSession,
    util::sharded_path::get_sharded_path,
    AppState,
};

#[async_test]
async fn test_chunked_upload_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![init_upload, upload_chunk, finalize_upload, get_file],
    );

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let file_path = "chunked_test.txt";

    // 1. Initialize
    let response = client
        .post(format!("/file/upload/initiate/{}", file_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let init_res: InitUploadResponse = response.into_json().await.unwrap();
    let upload_id = init_res.upload_id;

    // 2. Upload Chunks
    let chunk1 = "A".repeat(CHUNK_SIZE);
    let chunk2 = "B".repeat(CHUNK_SIZE / 2);

    let response = client
        .put(format!("/file/upload/chunk/{}?offset=0", upload_id))
        .private_cookie(cookie.clone())
        .body(&chunk1)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);

    let response = client
        .put(format!(
            "/file/upload/chunk/{}?offset={}",
            upload_id, CHUNK_SIZE
        ))
        .private_cookie(cookie.clone())
        .body(&chunk2)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);

    // 3. Finalize
    let total_size = (CHUNK_SIZE + CHUNK_SIZE / 2) as u64;
    let response = client
        .post(format!(
            "/file/upload/finalize/{}?total_size={}",
            upload_id, total_size
        ))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    // 4. Verify Download
    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert_eq!(body, format!("{}{}", chunk1, chunk2));
}

#[async_test]
async fn test_chunked_upload_missing_chunks() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![init_upload, upload_chunk, finalize_upload]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let file_path = "missing_chunk_test.txt";

    // 1. Initialize
    let response = client
        .post(format!("/file/upload/initiate/{}", file_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    let init_res: InitUploadResponse = response.into_json().await.unwrap();
    let upload_id = init_res.upload_id;

    // 2. Upload only second chunk
    let chunk2 = "B".repeat(CHUNK_SIZE);
    let response = client
        .put(format!(
            "/file/upload/chunk/{}?offset={}",
            upload_id, CHUNK_SIZE
        ))
        .private_cookie(cookie.clone())
        .body(&chunk2)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);

    // 3. Finalize (should fail)
    let total_size = (CHUNK_SIZE * 2) as u64;
    let response = client
        .post(format!(
            "/file/upload/finalize/{}?total_size={}",
            upload_id, total_size
        ))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    let error_msg = response.into_string().await.unwrap();
    assert!(error_msg.contains("Missing chunks: [0]"));

    // 4. Upload missing first chunk
    let chunk1 = "A".repeat(CHUNK_SIZE);
    let response = client
        .put(format!("/file/upload/chunk/{}?offset=0", upload_id))
        .private_cookie(cookie.clone())
        .body(&chunk1)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NoContent);

    // 5. Finalize again (should succeed)
    let response = client
        .post(format!(
            "/file/upload/finalize/{}?total_size={}",
            upload_id, total_size
        ))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);
}

#[async_test]
async fn test_chunked_upload_unauthorized() {
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![init_upload, upload_chunk, finalize_upload]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let response = client
        .post("/file/upload/initiate/unauthorized.txt")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[async_test]
async fn test_chunked_upload_invalid_offset() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![init_upload, upload_chunk, finalize_upload]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .post("/file/upload/initiate/invalid_offset.txt")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    let init_res: InitUploadResponse = response.into_json().await.unwrap();
    let upload_id = init_res.upload_id;

    let response = client
        .put(format!("/file/upload/chunk/{}?offset=100", upload_id))
        .private_cookie(cookie)
        .body("data")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}

#[async_test]
async fn test_chunked_upload_not_found() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![init_upload, upload_chunk, finalize_upload]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .put("/file/upload/chunk/non-existent-id?offset=0")
        .private_cookie(cookie)
        .body("data")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
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

    get_sharded_path(session.get_user_path(), &encoded_file_name)
        .await
        .with_extension("part")
}

fn active_upload_rows(session: &UserSession) -> Vec<String> {
    let db = session.db_pool.get().unwrap();

    sqlite::get_all_active_uploads(&db)
        .unwrap()
        .into_iter()
        .map(|(upload_id, _, _)| upload_id)
        .collect()
}

async fn initiate(client: &Client, cookie: &rocket::http::Cookie<'static>, name: &str) -> String {
    let response = timeout(
        Duration::from_secs(5),
        client
            .post(format!("/file/upload/initiate/{}", name))
            .private_cookie(cookie.clone())
            .dispatch(),
    )
    .await
    .expect("init_upload hung (deadlock)");

    assert_eq!(response.status(), Status::Ok);

    response
        .into_json::<InitUploadResponse>()
        .await
        .unwrap()
        .upload_id
}

#[async_test]
async fn test_init_upload_reclaims_stale_upload_instead_of_hanging() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![init_upload]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    let session = client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions
        .get_by_id(&session_id)
        .await
        .unwrap();

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

struct EnvVarGuard(&'static str);

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        env::remove_var(self.0);
    }
}

// The limit is process-wide, so it is set to 2: no other test keeps more than
// two uploads active in one session, which keeps them unaffected while this
// runs.
#[async_test]
async fn test_stale_uploads_do_not_count_against_the_upload_limit() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![init_upload]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    let session = client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions
        .get_by_id(&session_id)
        .await
        .unwrap();

    env::set_var("JUSTENCRYPT_MAX_ACTIVE_UPLOADS", "2");
    let _restore = EnvVarGuard("JUSTENCRYPT_MAX_ACTIVE_UPLOADS");

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
        .post("/file/upload/initiate/one-too-many.txt")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::TooManyRequests);
    assert_eq!(active_upload_rows(&session).len(), 2);
}

#[async_test]
async fn test_sweep_stale_uploads_uses_the_given_ttl() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![init_upload]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    let session = client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions
        .get_by_id(&session_id)
        .await
        .unwrap();

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

async fn upload_client(rocket: Rocket<Build>, test_user: &TestUser) -> (Client, Cookie<'static>) {
    let rocket = rocket.mount(
        "/file",
        routes![init_upload, upload_chunk, finalize_upload, get_file],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    (client, cookie)
}

async fn put_chunk(
    client: &Client,
    cookie: &Cookie<'static>,
    upload_id: &str,
    offset: u64,
    body: Vec<u8>,
) -> Status {
    client
        .put(format!(
            "/file/upload/chunk/{}?offset={}",
            upload_id, offset
        ))
        .private_cookie(cookie.clone())
        .body(body)
        .dispatch()
        .await
        .status()
}

async fn finalize(
    client: &Client,
    cookie: &Cookie<'static>,
    upload_id: &str,
    total_size: u64,
) -> (Status, String) {
    let response = client
        .post(format!(
            "/file/upload/finalize/{}?total_size={}",
            upload_id, total_size
        ))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    let status = response.status();

    (status, response.into_string().await.unwrap_or_default())
}

#[async_test]
async fn test_finalize_rejects_a_huge_total_size_quickly() {
    let (rocket, test_user) = setup_rocket().await;
    let (client, cookie) = upload_client(rocket, &test_user).await;
    let upload_id = initiate(&client, &cookie, "huge.bin").await;

    for total_size in [1u64 << 40, u64::MAX] {
        let started = std::time::Instant::now();
        let (status, body) = finalize(&client, &cookie, &upload_id, total_size).await;

        assert_eq!(status, Status::PayloadTooLarge, "total_size {}", total_size);
        assert!(body.len() < 2048, "response body was {} bytes", body.len());
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}

#[async_test]
async fn test_finalize_caps_the_list_of_missing_chunks() {
    let (rocket, test_user) = setup_rocket().await;
    let (client, cookie) = upload_client(rocket, &test_user).await;
    let upload_id = initiate(&client, &cookie, "sparse.bin").await;

    let (status, body) = finalize(&client, &cookie, &upload_id, 200 * CHUNK_SIZE as u64).await;

    assert_eq!(status, Status::BadRequest);
    assert!(body.contains("Missing chunks: [0, 1, 2,"), "body: {}", body);
    assert!(body.contains("(and 100 more)"), "body: {}", body);
    assert!(body.len() < 2048, "response body was {} bytes", body.len());
}

#[async_test]
async fn test_finalize_rejects_a_total_size_that_does_not_match_the_data() {
    let (rocket, test_user) = setup_rocket().await;
    let (client, cookie) = upload_client(rocket, &test_user).await;
    let upload_id = initiate(&client, &cookie, "small.txt").await;

    assert_eq!(
        put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; 10]).await,
        Status::NoContent
    );

    for claimed in [CHUNK_SIZE as u64, 11, 9, 0] {
        let (status, body) = finalize(&client, &cookie, &upload_id, claimed).await;

        assert_eq!(status, Status::BadRequest, "claimed {}: {}", claimed, body);
    }

    // The upload is still active, so the client can finalize with the real size.
    let (status, _) = finalize(&client, &cookie, &upload_id, 10).await;
    assert_eq!(status, Status::Created);
}

#[async_test]
async fn test_finalize_rejects_a_short_chunk_in_the_middle_of_the_file() {
    let (rocket, test_user) = setup_rocket().await;
    let (client, cookie) = upload_client(rocket, &test_user).await;
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

    assert_eq!(status, Status::BadRequest);
}

#[async_test]
async fn test_reuploading_a_shorter_last_chunk_downloads_correctly() {
    let (rocket, test_user) = setup_rocket().await;
    let (client, cookie) = upload_client(rocket, &test_user).await;
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
    assert_eq!(status, Status::Created, "{}", body);

    let response = client
        .get("/file/retried.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    let body = response.into_bytes().await.unwrap();
    let mut expected = vec![b'A'; CHUNK_SIZE];
    expected.extend(vec![b'C'; 100]);

    assert_eq!(body.len(), expected.len());
    assert!(body == expected, "downloaded content does not match");
}

#[async_test]
async fn test_empty_chunked_upload_can_be_finalized() {
    let (rocket, test_user) = setup_rocket().await;
    let (client, cookie) = upload_client(rocket, &test_user).await;
    let upload_id = initiate(&client, &cookie, "empty.bin").await;

    let (status, body) = finalize(&client, &cookie, &upload_id, 0).await;

    assert_eq!(status, Status::Created, "{}", body);

    let response = client
        .get("/file/empty.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.headers().get_one("Content-Length"), Some("0"));
    assert!(response.into_bytes().await.unwrap().is_empty());
}

#[async_test]
async fn test_chunk_request_over_the_chunk_limit_is_rejected() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = with_upload_limits(rocket, 1 << 30, 2 * CHUNK_SIZE as u64);
    let (client, cookie) = upload_client(rocket, &test_user).await;
    let upload_id = initiate(&client, &cookie, "big-request.bin").await;

    let at_limit = put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; 2 * CHUNK_SIZE]).await;
    assert_eq!(at_limit, Status::NoContent);

    let over_limit = put_chunk(
        &client,
        &cookie,
        &upload_id,
        0,
        vec![b'A'; 2 * CHUNK_SIZE + 1],
    )
    .await;
    assert_eq!(over_limit, Status::PayloadTooLarge);
}

#[async_test]
async fn test_chunks_past_the_file_limit_are_rejected() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = with_upload_limits(rocket, 2 * CHUNK_SIZE as u64, 1 << 30);
    let (client, cookie) = upload_client(rocket, &test_user).await;
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
    assert_eq!(straddling, Status::PayloadTooLarge);

    // Starts exactly at the limit.
    let at_the_end = put_chunk(
        &client,
        &cookie,
        &upload_id,
        2 * CHUNK_SIZE as u64,
        vec![b'A'; 1],
    )
    .await;
    assert_eq!(at_the_end, Status::PayloadTooLarge);

    // Filling the file exactly up to the limit is fine.
    let exact = put_chunk(&client, &cookie, &upload_id, 0, vec![b'A'; 2 * CHUNK_SIZE]).await;
    assert_eq!(exact, Status::NoContent);

    let (status, body) = finalize(&client, &cookie, &upload_id, 2 * CHUNK_SIZE as u64).await;
    assert_eq!(status, Status::Created, "{}", body);
}

#[async_test]
async fn test_finalize_rejects_a_total_size_over_the_file_limit() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = with_upload_limits(rocket, 1000, 1 << 30);
    let (client, cookie) = upload_client(rocket, &test_user).await;
    let upload_id = initiate(&client, &cookie, "claimed-too-big.bin").await;

    let (status, _) = finalize(&client, &cookie, &upload_id, 1001).await;

    assert_eq!(status, Status::PayloadTooLarge);
}
