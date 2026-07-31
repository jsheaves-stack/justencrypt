use super::*;
use crate::{
    routes::file::{delete_file, file_options, get_file, patch_file, put_file},
    util::sharded_path::get_sharded_path,
    AppState,
};
use rocket::{async_test, http::Status, local::asynchronous::Client, routes, tokio};

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
    let session_guard = state.sessions_by_id.read().await;
    let session_lock = session_guard.get(&session_id).unwrap().clone();
    let session = session_lock.clone();

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
        .header(rocket::http::Header::new("Range", "bytes=0-99"))
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
        .header(rocket::http::Header::new("Range", range_header))
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
        .header(rocket::http::Header::new(
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
        .header(rocket::http::Header::new("Range", "bytes=5-"))
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
        .header(rocket::http::Header::new("Range", "bytes=10-5"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::RangeNotSatisfiable);
}
