use super::*;
use crate::{
    encryption::CHUNK_SIZE,
    routes::file::{finalize_upload, get_file, init_upload, upload_chunk, InitUploadResponse},
};
use rocket::{http::Status, local::asynchronous::Client, routes};

#[rocket::async_test]
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

#[rocket::async_test]
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

#[rocket::async_test]
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

#[rocket::async_test]
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

    assert_eq!(response.status(), Status::InternalServerError); // encrypt_stream_at_offset returns Err which becomes InternalServerError
}

#[rocket::async_test]
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
