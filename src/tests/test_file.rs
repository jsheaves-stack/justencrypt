use rocket::{
    async_test,
    http::{Cookie, Header, Status},
    local::asynchronous::Client,
    routes, tokio,
};

use super::*;
use crate::{
    db::sqlite,
    routes::file::{delete_file, file_options, get_file, patch_file, put_file},
    util::sharded_path::get_sharded_path,
    AppState,
};

#[async_test]
async fn test_put_file() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let file_path = "test_file.txt";
    let file_content = "Hello, world!";

    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    let state = client.rocket().state::<AppState>().unwrap();
    let session = state.sessions.get_by_id(&session_id).await.unwrap();

    let encoded_file_name = session
        .get_encoded_file_name(file_path.into())
        .await
        .unwrap();

    let sharded_path = get_sharded_path(session.get_user_path().clone(), &encoded_file_name).await;

    assert!(tokio::fs::metadata(sharded_path).await.is_ok());
}

#[async_test]
async fn test_get_file() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let file_path = "test_file.txt";
    let file_content = "Hello, world!";

    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    let response = client
        .get(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    let body = response.into_string().await.unwrap();

    assert_eq!(body, file_content);
}

#[async_test]
async fn test_put_file_no_auth() {
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let file_path = "test_file.txt";
    let file_content = "Hello, world!";

    let response = client
        .put(format!("/file/{}", file_path))
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[async_test]
async fn test_put_file_empty_content() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let file_path = "test_file.txt";
    let file_content = "";

    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);
}

#[async_test]
async fn test_get_file_range_first_chunk() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

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
        .header(Header::new("Range", "bytes=0-99"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::PartialContent);
    assert_eq!(
        response.headers().get_one("Content-Range").unwrap(),
        "bytes 0-99/131072"
    );
    assert_eq!(response.into_string().await.unwrap(), "A".repeat(100));
}

#[async_test]
async fn test_get_file_range_cross_chunks() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

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
        .header(Header::new("Range", range_header))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::PartialContent);
    let body = response.into_bytes().await.unwrap();
    assert_eq!(body.len(), 21);
    assert_eq!(body, file_content[start..=end]);
}

#[async_test]
async fn test_get_file_range_last_byte() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

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
        .header(Header::new(
            "Range",
            format!("bytes={}-{}", last_index, last_index),
        ))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::PartialContent);
    assert_eq!(response.into_string().await.unwrap(), "d");
}

#[async_test]
async fn test_get_file_range_no_end() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

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
        .header(Header::new("Range", "bytes=5-"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::PartialContent);
    assert_eq!(response.into_string().await.unwrap(), "56789");
}

#[async_test]
async fn test_get_file_range_invalid() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/file",
        routes![put_file, get_file, delete_file, file_options, patch_file],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

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
        .header(Header::new("Range", "bytes=10-5"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::RangeNotSatisfiable);
}

// Every file under the user's directory except the user's own database files,
// i.e. encrypted blobs, partial uploads and cached thumbnails.
fn stored_files(user_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();

            if path.is_dir() {
                walk(&path, depth + 1, out);
            } else if depth > 0 {
                out.push(path);
            }
        }
    }

    let mut out = Vec::new();
    walk(user_dir, 0, &mut out);

    out
}

#[async_test]
async fn test_put_file_over_the_file_limit_is_rejected_and_leaves_nothing_behind() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = with_upload_limits(rocket, 1000, 1 << 30);
    let rocket = rocket.mount("/file", routes![put_file, get_file]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .put("/file/too-big.bin")
        .private_cookie(cookie.clone())
        .body(vec![b'A'; 1001])
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::PayloadTooLarge);

    let response = client
        .get("/file/too-big.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
    assert_eq!(
        stored_files(&test_user.path),
        Vec::<std::path::PathBuf>::new()
    );

    let session = client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions
        .get_by_id(&session_id)
        .await
        .unwrap();
    let db = session.db_pool.get().unwrap();

    assert!(sqlite::get_all_active_uploads(&db).unwrap().is_empty());
}

#[async_test]
async fn test_put_file_at_the_file_limit_is_stored_in_full() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = with_upload_limits(rocket, 1000, 1 << 30);
    let rocket = rocket.mount("/file", routes![put_file, get_file]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .put("/file/exact.bin")
        .private_cookie(cookie.clone())
        .body(vec![b'A'; 1000])
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    let response = client
        .get("/file/exact.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_bytes().await.unwrap(), vec![b'A'; 1000]);
}

// The returned `TestUser` must be kept alive: dropping it deletes the user's
// data directory.
async fn download_client() -> (Client, Cookie<'static>, TestUser) {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![put_file, get_file]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    (client, cookie, test_user)
}

async fn upload(client: &Client, cookie: &Cookie<'static>, path: &str, body: Vec<u8>) {
    let response = client
        .put(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .body(body)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);
}

#[async_test]
async fn test_get_empty_file() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "empty.txt", Vec::new()).await;

    let response = client
        .get("/file/empty.txt")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.headers().get_one("Content-Length"), Some("0"));
    assert_eq!(response.headers().get_one("Content-Range"), None);
    assert!(response.into_bytes().await.unwrap().is_empty());
}

#[async_test]
async fn test_get_empty_file_with_a_range_is_not_satisfiable() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "empty.txt", Vec::new()).await;

    let response = client
        .get("/file/empty.txt")
        .private_cookie(cookie)
        .header(Header::new("Range", "bytes=0-"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::RangeNotSatisfiable);
    assert_eq!(
        response.headers().get_one("Content-Range"),
        Some("bytes */0")
    );
}

#[async_test]
async fn test_get_full_file_has_exact_length_and_no_content_range() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "full.bin", vec![b'A'; 70_000]).await;

    let response = client
        .get("/file/full.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.headers().get_one("Content-Length"), Some("70000"));
    assert_eq!(response.headers().get_one("Content-Range"), None);
    assert_eq!(response.into_bytes().await.unwrap().len(), 70_000);
}

#[async_test]
async fn test_get_file_range_past_the_end_reports_the_file_size() {
    let (client, cookie, _test_user) = download_client().await;
    upload(&client, &cookie, "short.txt", b"test".to_vec()).await;

    let response = client
        .get("/file/short.txt")
        .private_cookie(cookie)
        .header(Header::new("Range", "bytes=10-20"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::RangeNotSatisfiable);
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

async fn overwrite(client: &Client, cookie: &Cookie<'static>, path: &str, fill: u8) -> Status {
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
#[async_test]
async fn test_concurrent_overwrites_leave_exactly_one_blob() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![put_file, get_file]);
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

    upload(&client, &cookie, "shared.bin", vec![b'0'; 10]).await;

    for round in 0..10 {
        let (a, b, c, d) = tokio::join!(
            overwrite(&client, &cookie, "shared.bin", b'A'),
            overwrite(&client, &cookie, "shared.bin", b'B'),
            overwrite(&client, &cookie, "shared.bin", b'C'),
            overwrite(&client, &cookie, "shared.bin", b'D'),
        );

        assert_eq!([a, b, c, d], [Status::Created; 4], "round {}", round);

        let referenced = session
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

#[async_test]
async fn test_delete_missing_file_is_not_found() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![put_file, delete_file]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    upload(&client, &cookie, "docs/real.txt", b"x".to_vec()).await;

    for path in ["docs/missing.txt", "no/such/folder/missing.txt"] {
        let response = client
            .delete(format!("/file/{}", path))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NotFound, "path {}", path);
    }
}

// The database is the source of truth: once the row is gone the file is gone,
// even if its blob had already disappeared from disk.
#[async_test]
async fn test_delete_file_succeeds_when_the_blob_is_already_missing() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/file", routes![put_file, get_file, delete_file]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    upload(&client, &cookie, "vanished.txt", b"x".to_vec()).await;

    for blob in stored_files(&test_user.path) {
        fs::remove_file(blob).unwrap();
    }

    let response = client
        .delete("/file/vanished.txt")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);

    let response = client
        .get("/file/vanished.txt")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}
