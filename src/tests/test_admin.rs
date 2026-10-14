use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_delete_session_success() {
    let test_api_key = "super_secret_test_key";
    let (app, test_user) = setup_app_with_admin_key(test_api_key).await;

    let client = TestClient::new(app);

    // Create a user session
    let (session_id, _cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    // Verify session exists
    let req = client
        .get("/admin/session")
        .header("X-Admin-Api-Key", test_api_key);
    let response = req.dispatch().await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_string().await.unwrap();
    assert!(body.contains(&session_id));

    // Delete the session
    let req = client
        .delete(format!("/admin/session/{}", session_id))
        .header("X-Admin-Api-Key", test_api_key);
    let response = req.dispatch().await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify session is gone
    let req = client
        .get("/admin/session")
        .header("X-Admin-Api-Key", test_api_key);
    let response = req.dispatch().await;
    let body = response.into_string().await.unwrap();
    assert!(!body.contains(&session_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_session_with_valid_key() {
    let test_api_key = "super_secret_test_key";
    let (app, _test_user) = setup_app_with_admin_key(test_api_key).await;

    let client = TestClient::new(app);

    let req = client
        .get("/admin/session")
        .header("X-Admin-Api-Key", test_api_key);
    let response = req.dispatch().await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_string().await.unwrap();
    assert_eq!(body, "[]");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_session_with_invalid_key() {
    let test_api_key = "super_secret_test_key";
    let (app, _test_user) = setup_app_with_admin_key(test_api_key).await;

    let client = TestClient::new(app);

    let req = client
        .get("/admin/session")
        .header("X-Admin-Api-Key", "wrong_key");
    let response = req.dispatch().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_session_missing_key() {
    let test_api_key = "super_secret_test_key";
    let (app, _test_user) = setup_app_with_admin_key(test_api_key).await;

    let client = TestClient::new(app);

    let req = client.get("/admin/session");
    let response = req.dispatch().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

const ADMIN_KEY: &str = "super_secret_test_key";

async fn setup_app_with_admin_key(key: &str) -> (Arc<App>, TestUser) {
    setup_app_with_config(|config| {
        config.admin_api_key = Some(SecretString::from_str(key).unwrap())
    })
    .await
}
const STRONG_PASSWORD: &str = "correct-Horse-battery-staple-91!";

async fn admin_client() -> (TestClient, TestUser) {
    let (app, test_user) = setup_app_with_admin_key(ADMIN_KEY).await;

    let client = TestClient::new(app);

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

async fn post_user(
    client: &TestClient,
    username: &str,
    password: &str,
    key: Option<&str>,
) -> StatusCode {
    let body = serde_json::json!({ "username": username, "password": password });
    let mut request = client
        .post("/admin/users")
        .header("Content-Type", "application/json")
        .body(body.to_string());

    if let Some(key) = key {
        request = request.header("X-Admin-Api-Key", key);
    }

    request.dispatch().await.status()
}

async fn login_status(client: &TestClient, username: &str, password: &str) -> StatusCode {
    client
        .post("/session")
        .header("Content-Type", "application/json")
        .body(serde_json::json!({ "username": username, "password": password }).to_string())
        .dispatch()
        .await
        .status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_user_then_log_in() {
    let (client, _test_user) = admin_client().await;
    let user = fresh_user();

    // Logging in before the account exists fails, and doesn't create it.
    assert_eq!(
        login_status(&client, &user.name, STRONG_PASSWORD).await,
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        post_user(&client, &user.name, STRONG_PASSWORD, Some(ADMIN_KEY)).await,
        StatusCode::CREATED
    );
    assert!(user.path.join(format!("{}.db", user.name)).is_file());

    assert_eq!(
        login_status(&client, &user.name, STRONG_PASSWORD).await,
        StatusCode::CREATED
    );
    assert_eq!(
        login_status(&client, &user.name, "correct-Horse-battery-staple-92!").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_user_that_already_exists_is_a_conflict() {
    let (client, _test_user) = admin_client().await;
    let user = fresh_user();

    assert_eq!(
        post_user(&client, &user.name, STRONG_PASSWORD, Some(ADMIN_KEY)).await,
        StatusCode::CREATED
    );
    assert_eq!(
        post_user(
            &client,
            &user.name,
            "another-Strong-passphrase-77!",
            Some(ADMIN_KEY)
        )
        .await,
        StatusCode::CONFLICT
    );

    // The original password still works.
    assert_eq!(
        login_status(&client, &user.name, STRONG_PASSWORD).await,
        StatusCode::CREATED
    );
}

// A directory without a database (how accounts used to be prepared for their
// first login) can still be set up.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_user_in_an_existing_empty_directory() {
    let (client, test_user) = admin_client().await;

    assert!(test_user.path.is_dir());
    assert_eq!(
        post_user(&client, &test_user.name, STRONG_PASSWORD, Some(ADMIN_KEY)).await,
        StatusCode::CREATED
    );
    assert_eq!(
        login_status(&client, &test_user.name, STRONG_PASSWORD).await,
        StatusCode::CREATED
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_user_rejects_weak_passwords_and_bad_usernames() {
    let (client, _test_user) = admin_client().await;
    let user = fresh_user();

    assert_eq!(
        post_user(&client, &user.name, "password", Some(ADMIN_KEY)).await,
        StatusCode::BAD_REQUEST
    );
    assert!(!user.path.join(format!("{}.db", user.name)).exists());

    for username in ["", "../escape", "a/b", "a.b", "a\u{0}b"] {
        assert_eq!(
            post_user(&client, username, STRONG_PASSWORD, Some(ADMIN_KEY)).await,
            StatusCode::BAD_REQUEST,
            "username {:?}",
            username
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_user_requires_the_admin_key() {
    let (client, _test_user) = admin_client().await;
    let user = fresh_user();

    assert_eq!(
        post_user(&client, &user.name, STRONG_PASSWORD, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_user(&client, &user.name, STRONG_PASSWORD, Some("wrong-key")).await,
        StatusCode::UNAUTHORIZED
    );
    assert!(!user.path.exists());
}

// M11h: the admin preflight routes answered 200 while every other preflight
// route, and the spec, use 204.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_admin_preflight_routes_return_no_content() {
    let (app, _test_user) = setup_app_with_admin_key(ADMIN_KEY).await;
    let client = TestClient::new(app);

    for path in ["/admin/session", "/admin/session/some-id", "/admin/users"] {
        let response = client.options(path).dispatch().await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path}");
    }
}
