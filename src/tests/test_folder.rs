use super::*;
use crate::{
    routes::folder::{create_folder, delete_folder, folder_options, get_folder},
    AppState,
};
use rocket::{http::Status, local::asynchronous::Client, routes};

#[rocket::async_test]
async fn test_create_folder() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/folder",
        routes![create_folder, get_folder, delete_folder, folder_options],
    );

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    let state = client.rocket().state::<AppState>().unwrap();
    let session_guard = state.sessions_by_id.read().await;
    let session_lock = session_guard.get(&session_id).unwrap().clone();
    let session = session_lock.read().await;

    let folder_id = session
        .get_folder_id(folder_path.into())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(2, folder_id); // Assuming 1 is root
}

#[rocket::async_test]
async fn test_get_folder() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/folder",
        routes![create_folder, get_folder, delete_folder, folder_options],
    );

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    let response = client
        .get(format!("/folder/{}", folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_create_folder_no_auth() {
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/folder",
        routes![create_folder, get_folder, delete_folder, folder_options],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}
