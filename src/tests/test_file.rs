use super::*;
use crate::{
    routes::file::{delete_file, file_options, get_file, patch_file, put_file},
    util::sharded_path::get_sharded_path,
    AppState,
};
use rocket::{http::Status, local::asynchronous::Client, routes, tokio};

#[rocket::async_test]
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
    let session = session_lock.read().await;

    let file_entry = Some(
        session
            .get_encoded_file_name(file_path.into())
            .await
            .unwrap(),
    );

    assert!(file_entry.is_some());

    let encoded_file_name = file_entry.unwrap();
    let sharded_path =
        get_sharded_path(session.get_user_path().clone(), &encoded_file_name).await;

    assert!(tokio::fs::metadata(sharded_path).await.is_ok());
}

#[rocket::async_test]
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

#[rocket::async_test]
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

#[rocket::async_test]
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

#[rocket::async_test]
async fn test_put_file_large_content() {
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
    let file_content = "A".repeat(64 * 1024 * 1024); // 64MB

    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .body(file_content)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);
}
