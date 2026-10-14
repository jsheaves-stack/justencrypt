use std::time::Duration;

use super::*;
use crate::{
    db::sqlite,
    enums::db_error::DbError,
    session::{policy::SessionPolicy, reaper::SessionReaper},
    web::routes::upload::InitUploadResponse,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_session_success() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);

    // Initialize the user DB with the test password
    let _ = create_test_session(client.app(), test_user.name.clone()).await;

    let login_data = format!(
        r#"{{"username": "{}", "password": "test_password"}}"#,
        test_user.name
    );

    let response = client
        .post("/session")
        .header("Content-Type", "application/json")
        .body(login_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let cookies = response.cookies();
    assert!(cookies.iter().any(|c| c.name() == "sid"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_session_invalid_password() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);

    // Initialize the user DB with the test password
    let _ = create_test_session(client.app(), test_user.name.clone()).await;

    let login_data = format!(
        r#"{{"username": "{}", "password": "wrong_password"}}"#,
        test_user.name
    );

    let response = client
        .post("/session")
        .header("Content-Type", "application/json")
        .body(login_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_destroy_session_success() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);

    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .delete("/session")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_destroy_session_no_auth() {
    let (app, _test_user) = setup_app().await;
    let client = TestClient::new(app);

    let response = client.delete("/session").dispatch().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// Every `.part` file under the user's directory.
fn partial_uploads(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();

    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();

        if path.is_dir() {
            found.extend(partial_uploads(&path));
        } else if path.extension().is_some_and(|ext| ext == "part") {
            found.push(path);
        }
    }

    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_destroy_session_cleans_up_uploads_and_clears_the_cookie() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;
    let session = client.app().sessions.get_by_id(&session_id).await.unwrap();

    let response = client
        .post("/upload/initiate/in-flight.bin")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let _: InitUploadResponse = response.into_json().await.unwrap();
    assert_eq!(partial_uploads(&test_user.path).len(), 1);

    let response = client
        .delete("/session")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let set_cookie: Vec<&str> = response.headers().get("Set-Cookie").collect();
    assert!(
        set_cookie
            .iter()
            .any(|c| c.starts_with("sid=") && (c.contains("Max-Age=0") || c.contains("1970"))),
        "logout should expire the sid cookie, got {:?}",
        set_cookie
    );

    assert_eq!(
        partial_uploads(&test_user.path),
        Vec::<std::path::PathBuf>::new()
    );

    let db = session.context.pool().get().unwrap();
    assert!(sqlite::get_all_active_uploads(&db).unwrap().is_empty());
}

fn short_policy(idle_secs: u64, lifetime_secs: u64) -> SessionPolicy {
    SessionPolicy {
        idle_timeout: Duration::from_secs(idle_secs),
        max_lifetime: Duration::from_secs(lifetime_secs),
        ..SessionPolicy::default()
    }
}

async fn list_root(client: &TestClient, cookie: &Cookie<'static>) -> StatusCode {
    client
        .get("/folder/")
        .private_cookie(cookie.clone())
        .dispatch()
        .await
        .status()
}

async fn session_exists(client: &TestClient, session_id: &str) -> bool {
    client.app().sessions.get_by_id(session_id).await.is_some()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_idle_session_expires() {
    let (app, test_user) = setup_app_with_session_policy(short_policy(1, 3600)).await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    assert_eq!(list_root(&client, &cookie).await, StatusCode::OK);

    tokio::time::sleep(Duration::from_millis(2100)).await;

    assert_eq!(list_root(&client, &cookie).await, StatusCode::UNAUTHORIZED);
    assert!(!session_exists(&client, &session_id).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_activity_keeps_a_session_alive() {
    let (app, test_user) = setup_app_with_session_policy(short_policy(2, 3600)).await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    // Well past the idle timeout in total, but never idle for that long.
    for _ in 0..5 {
        assert_eq!(list_root(&client, &cookie).await, StatusCode::OK);

        tokio::time::sleep(Duration::from_millis(700)).await;
    }

    assert_eq!(list_root(&client, &cookie).await, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_session_expires_at_its_max_lifetime_even_when_active() {
    let (app, test_user) = setup_app_with_session_policy(short_policy(3600, 1)).await;
    let client = TestClient::new(app);
    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(700)).await;
        list_root(&client, &cookie).await;
    }

    assert_eq!(list_root(&client, &cookie).await, StatusCode::UNAUTHORIZED);
    assert!(!session_exists(&client, &session_id).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_enabled_reaper_removes_expired_sessions_without_any_request() {
    let (app, test_user) = setup_app_with_session_policy(short_policy(1, 3600)).await;
    let client = TestClient::new(app);
    let app = client.app();
    SessionReaper::every(1)
        .unwrap()
        .spawn(app.sessions.clone(), app.config.upload_ttl());
    let (session_id, _) = create_test_session(client.app(), test_user.name.clone()).await;

    assert!(session_exists(&client, &session_id).await);

    tokio::time::sleep(Duration::from_millis(3500)).await;

    assert!(!session_exists(&client, &session_id).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_login_cookie_lives_as_long_as_the_session() {
    let (app, test_user) = setup_app_with_session_policy(short_policy(3600, 1234)).await;
    let client = TestClient::new(app);

    // Initialize the user DB with the test password
    let _ = create_test_session(client.app(), test_user.name.clone()).await;

    let response = client
        .post("/session")
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"username": "{}", "password": "test_password"}}"#,
            test_user.name
        ))
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let set_cookie: Vec<&str> = response.headers().get("Set-Cookie").collect();
    assert!(
        set_cookie
            .iter()
            .any(|c| c.starts_with("sid=") && c.contains("Max-Age=1234")),
        "got {:?}",
        set_cookie
    );

    let token = client.cookies().get_private("sid").unwrap();
    assert_eq!(token.value().len(), 43);
}

// With the reaper disabled (the default), logins are what clear out sessions
// that expired and were never used again.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_login_removes_expired_sessions_when_the_reaper_is_disabled() {
    let (app, test_user) = setup_app_with_session_policy(short_policy(1, 3600)).await;
    let client = TestClient::new(app);
    let (abandoned_id, _) = create_test_session(client.app(), test_user.name.clone()).await;

    tokio::time::sleep(Duration::from_millis(2100)).await;

    assert!(session_exists(&client, &abandoned_id).await);

    let response = client
        .post("/session")
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"username": "{}", "password": "test_password"}}"#,
            test_user.name
        ))
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(!session_exists(&client, &abandoned_id).await);
}

async fn login(client: &TestClient, username: &str, password: &str) -> (StatusCode, String) {
    let body = serde_json::json!({ "username": username, "password": password }).to_string();
    let response = client
        .post("/session")
        .header("Content-Type", "application/json")
        .body(body)
        .dispatch()
        .await;
    let status = response.status();

    (status, response.into_string().await.unwrap_or_default())
}

// M4: every failed login looks the same, so a response never reveals whether
// the username exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_failed_logins_are_indistinguishable() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let _ = create_test_session(client.app(), test_user.name.clone()).await;

    // A folder with no database: an account that was never set up.
    let name = uuid::Uuid::new_v4().to_string();
    let never_set_up = TestUser {
        path: std::env::temp_dir().join(&name),
        name,
    };
    fs::create_dir_all(&never_set_up.path).unwrap();

    let unknown = uuid::Uuid::new_v4().to_string();
    let attempts = [
        (test_user.name.as_str(), "wrong_password"),
        (test_user.name.as_str(), "a"),
        (unknown.as_str(), "wrong_password"),
        (unknown.as_str(), "a"),
        (unknown.as_str(), "a-Very-strong-passphrase-9!-horse"),
        (never_set_up.name.as_str(), "a"),
        (
            never_set_up.name.as_str(),
            "a-Very-strong-passphrase-9!-horse",
        ),
    ];

    let (first_status, first_body) = login(&client, attempts[0].0, attempts[0].1).await;
    assert_eq!(first_status, StatusCode::UNAUTHORIZED);

    for (username, password) in attempts {
        let (status, body) = login(&client, username, password).await;

        assert_eq!(
            (status, body.as_str()),
            (first_status, first_body.as_str()),
            "login as {} with {:?}",
            username,
            password
        );
    }

    // Logging in must never create an account.
    assert!(!never_set_up
        .path
        .join(format!("{}.db", never_set_up.name))
        .exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_login_rejects_malformed_credentials_before_touching_the_filesystem() {
    let (app, _test_user) = setup_app().await;
    let client = TestClient::new(app);

    // An absolute-path username used to make the server probe for
    // `<path>.db` anywhere on disk, answering differently if it existed.
    let probe_dir = tempfile::tempdir().unwrap();
    fs::write(probe_dir.path().join("exists.db"), b"").unwrap();
    let existing_probe = probe_dir
        .path()
        .join("exists")
        .to_string_lossy()
        .to_string();
    let missing_probe = probe_dir
        .path()
        .join("missing")
        .to_string_lossy()
        .to_string();
    let too_long = "a".repeat(65);
    let long_password = "p".repeat(1025);

    for (username, password) in [
        (existing_probe.as_str(), "a"),
        (missing_probe.as_str(), "a"),
        ("../x", "a"),
        ("a/b", "a"),
        ("a.b", "a"),
        ("a\\b", "a"),
        ("a\u{0}b", "a"),
        ("a\nb", "a"),
        ("", "a"),
        (too_long.as_str(), "a"),
        ("alice", ""),
        ("alice", long_password.as_str()),
    ] {
        let (status, _) = login(&client, username, password).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "username {:?}", username);
    }
}

// An encrypted user database that has never been migrated, like one created
// before a new migration was added.
fn create_unmigrated_user_db(test_user: &TestUser, password: &str) -> PathBuf {
    let db_path = test_user.path.join(format!("{}.db", test_user.name));
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    conn.pragma_update(None, "key", password).unwrap();
    conn.execute_batch("CREATE TABLE placeholder (x INTEGER);")
        .unwrap();

    db_path
}

// M12: concurrent first logins used to migrate the same database at once, and
// every login but the first failed with a 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_concurrent_first_logins_all_succeed() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);

    create_unmigrated_user_db(&test_user, "test_password");

    let logins = (0..8).map(|_| login(&client, &test_user.name, "test_password"));
    let results = futures_util::future::join_all(logins).await;

    for (status, body) in results {
        assert_eq!(status, StatusCode::CREATED, "body: {}", body);
    }
}

// M12: a failed migration is reported as a migration error rather than being
// disguised as a missing row.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_failed_migration_is_reported_as_a_migration_error() {
    let (_app, test_user) = setup_app().await;
    let db_path = create_unmigrated_user_db(&test_user, "test_password");
    let password = SecretString::from_str("test_password").unwrap();
    let db_config = test_config().db;

    let pool = sqlite::create_user_db_connection(db_path.clone(), password.clone(), &db_config)
        .expect("first migration should succeed");

    // Rewinding the version makes the next open re-run a migration whose
    // objects already exist.
    pool.get()
        .unwrap()
        .pragma_update(None, "user_version", 0)
        .unwrap();
    drop(pool);

    let result = sqlite::create_user_db_connection(db_path, password, &db_config);

    assert!(
        matches!(result, Err(DbError::Migration(_))),
        "unexpected result: {:?}",
        result.err()
    );
}
