use super::*;
use crate::{
    routes::session::{create_session, destroy_session, session_options},
};
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    routes,
};

#[rocket::async_test]
async fn test_create_session_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/session",
        routes![create_session, session_options],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    // Initialize the user DB with the test password
    let _ = create_test_session(client.rocket(), test_user.name.clone()).await;

    let login_data = format!(
        r#"{{"username": "{}", "password": "test_password"}}"#,
        test_user.name
    );

    let response = client
        .post("/session")
        .header(ContentType::JSON)
        .body(login_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);
    let cookies = response.cookies();
    assert!(cookies.iter().any(|c| c.name() == "__Host-id"));
}

#[rocket::async_test]
async fn test_create_session_invalid_password() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/session",
        routes![create_session, session_options],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    // Initialize the user DB with the test password
    let _ = create_test_session(client.rocket(), test_user.name.clone()).await;

    let login_data = format!(
        r#"{{"username": "{}", "password": "wrong_password"}}"#,
        test_user.name
    );

    let response = client
        .post("/session")
        .header(ContentType::JSON)
        .body(login_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_destroy_session_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/session",
        routes![destroy_session, session_options],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .delete("/session")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);
}

#[rocket::async_test]
async fn test_destroy_session_no_auth() {
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/session",
        routes![destroy_session, session_options],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    let response = client.delete("/session").dispatch().await;

    assert_eq!(response.status(), Status::Unauthorized);
}
