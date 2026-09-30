use rocket::{
    async_test,
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
    routes,
};

use super::*;
use crate::routes::{
    admin::{
        admin_options, create_user, create_user_options, delete_session, delete_session_options,
        get_session, CreateUser,
    },
    session::create_session,
};

#[async_test]
async fn test_delete_session_success() {
    let test_api_key = "super_secret_test_key";
    let (rocket, test_user) = setup_rocket_with_admin_key(test_api_key).await;
    let rocket = rocket.mount(
        "/admin",
        routes![
            get_session,
            admin_options,
            delete_session,
            delete_session_options
        ],
    );

    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    // Create a user session
    let (session_id, _cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    // Verify session exists
    let req = client
        .get("/admin/session")
        .header(Header::new("X-Admin-Api-Key", test_api_key));
    let response = req.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert!(body.contains(&session_id));

    // Delete the session
    let req = client
        .delete(format!("/admin/session/{}", session_id))
        .header(Header::new("X-Admin-Api-Key", test_api_key));
    let response = req.dispatch().await;
    assert_eq!(response.status(), Status::NoContent);

    // Verify session is gone
    let req = client
        .get("/admin/session")
        .header(Header::new("X-Admin-Api-Key", test_api_key));
    let response = req.dispatch().await;
    let body = response.into_string().await.unwrap();
    assert!(!body.contains(&session_id));
}

#[async_test]
async fn test_get_session_with_valid_key() {
    let test_api_key = "super_secret_test_key";
    let (rocket, _test_user) = setup_rocket_with_admin_key(test_api_key).await;
    let rocket = rocket.mount("/admin", routes![get_session, admin_options]);

    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    let req = client
        .get("/admin/session")
        .header(Header::new("X-Admin-Api-Key", test_api_key));
    let response = req.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert_eq!(body, "[]");
}

#[async_test]
async fn test_get_session_with_invalid_key() {
    let test_api_key = "super_secret_test_key";
    let (rocket, _test_user) = setup_rocket_with_admin_key(test_api_key).await;
    let rocket = rocket.mount("/admin", routes![get_session, admin_options]);

    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    let req = client
        .get("/admin/session")
        .header(Header::new("X-Admin-Api-Key", "wrong_key"));
    let response = req.dispatch().await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[async_test]
async fn test_get_session_missing_key() {
    let test_api_key = "super_secret_test_key";
    let (rocket, _test_user) = setup_rocket_with_admin_key(test_api_key).await;
    let rocket = rocket.mount("/admin", routes![get_session, admin_options]);

    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    let req = client.get("/admin/session");
    let response = req.dispatch().await;

    assert_eq!(response.status(), Status::Unauthorized);
}

const ADMIN_KEY: &str = "super_secret_test_key";

async fn setup_rocket_with_admin_key(key: &str) -> (Rocket<Build>, TestUser) {
    setup_rocket_with_config(|config| {
        config.admin_api_key = Some(SecretString::from_str(key).unwrap())
    })
    .await
}
const STRONG_PASSWORD: &str = "correct-Horse-battery-staple-91!";

async fn admin_client() -> (Client, TestUser) {
    let (rocket, test_user) = setup_rocket_with_admin_key(ADMIN_KEY).await;
    let rocket = rocket
        .mount("/admin", routes![create_user, create_user_options])
        .mount("/session", routes![create_session]);

    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    (client, test_user)
}

// A username whose data directory is removed when the guard is dropped.
fn fresh_user() -> TestUser {
    let name = uuid::Uuid::new_v4().to_string();

    TestUser {
        path: std::env::temp_dir().join(&name),
        name,
    }
}

async fn post_user(client: &Client, username: &str, password: &str, key: Option<&str>) -> Status {
    let mut request = client.post("/admin/users").json(&CreateUser {
        username: username.to_string(),
        password: password.to_string(),
    });

    if let Some(key) = key {
        request = request.header(Header::new("X-Admin-Api-Key", key.to_string()));
    }

    request.dispatch().await.status()
}

async fn login_status(client: &Client, username: &str, password: &str) -> Status {
    client
        .post("/session")
        .header(ContentType::JSON)
        .body(serde_json::json!({ "username": username, "password": password }).to_string())
        .dispatch()
        .await
        .status()
}

#[async_test]
async fn test_create_user_then_log_in() {
    let (client, _test_user) = admin_client().await;
    let user = fresh_user();

    // Logging in before the account exists fails, and doesn't create it.
    assert_eq!(
        login_status(&client, &user.name, STRONG_PASSWORD).await,
        Status::Unauthorized
    );

    assert_eq!(
        post_user(&client, &user.name, STRONG_PASSWORD, Some(ADMIN_KEY)).await,
        Status::Created
    );
    assert!(user.path.join(format!("{}.db", user.name)).is_file());

    assert_eq!(
        login_status(&client, &user.name, STRONG_PASSWORD).await,
        Status::Created
    );
    assert_eq!(
        login_status(&client, &user.name, "correct-Horse-battery-staple-92!").await,
        Status::Unauthorized
    );
}

#[async_test]
async fn test_create_user_that_already_exists_is_a_conflict() {
    let (client, _test_user) = admin_client().await;
    let user = fresh_user();

    assert_eq!(
        post_user(&client, &user.name, STRONG_PASSWORD, Some(ADMIN_KEY)).await,
        Status::Created
    );
    assert_eq!(
        post_user(
            &client,
            &user.name,
            "another-Strong-passphrase-77!",
            Some(ADMIN_KEY)
        )
        .await,
        Status::Conflict
    );

    // The original password still works.
    assert_eq!(
        login_status(&client, &user.name, STRONG_PASSWORD).await,
        Status::Created
    );
}

// A directory without a database (how accounts used to be prepared for their
// first login) can still be set up.
#[async_test]
async fn test_create_user_in_an_existing_empty_directory() {
    let (client, test_user) = admin_client().await;

    assert!(test_user.path.is_dir());
    assert_eq!(
        post_user(&client, &test_user.name, STRONG_PASSWORD, Some(ADMIN_KEY)).await,
        Status::Created
    );
    assert_eq!(
        login_status(&client, &test_user.name, STRONG_PASSWORD).await,
        Status::Created
    );
}

#[async_test]
async fn test_create_user_rejects_weak_passwords_and_bad_usernames() {
    let (client, _test_user) = admin_client().await;
    let user = fresh_user();

    assert_eq!(
        post_user(&client, &user.name, "password", Some(ADMIN_KEY)).await,
        Status::BadRequest
    );
    assert!(!user.path.join(format!("{}.db", user.name)).exists());

    for username in ["", "../escape", "a/b", "a.b", "a\u{0}b"] {
        assert_eq!(
            post_user(&client, username, STRONG_PASSWORD, Some(ADMIN_KEY)).await,
            Status::BadRequest,
            "username {:?}",
            username
        );
    }
}

#[async_test]
async fn test_create_user_requires_the_admin_key() {
    let (client, _test_user) = admin_client().await;
    let user = fresh_user();

    assert_eq!(
        post_user(&client, &user.name, STRONG_PASSWORD, None).await,
        Status::Unauthorized
    );
    assert_eq!(
        post_user(&client, &user.name, STRONG_PASSWORD, Some("wrong-key")).await,
        Status::Unauthorized
    );
    assert!(!user.path.exists());
}
