use std::time::Duration;

use rocket::{
    async_test,
    http::{ContentType, Cookie, Status},
    local::asynchronous::Client,
    routes,
};

use super::*;
use crate::{
    db::sqlite,
    routes::{
        file::{init_upload, InitUploadResponse},
        folder::get_folder,
        session::{create_session, destroy_session, session_options},
    },
    session::{policy::SessionPolicy, reaper::SessionReaper},
    AppState,
};

#[async_test]
async fn test_create_session_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/session", routes![create_session, session_options]);
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
    assert!(cookies.iter().any(|c| c.name() == "sid"));
}

#[async_test]
async fn test_create_session_invalid_password() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/session", routes![create_session, session_options]);
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

#[async_test]
async fn test_destroy_session_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/session", routes![destroy_session, session_options]);
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

#[async_test]
async fn test_destroy_session_no_auth() {
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount("/session", routes![destroy_session, session_options]);
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    let response = client.delete("/session").dispatch().await;

    assert_eq!(response.status(), Status::Unauthorized);
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

#[async_test]
async fn test_destroy_session_cleans_up_uploads_and_clears_the_cookie() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/session", routes![destroy_session])
        .mount("/file", routes![init_upload]);
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    let session = client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions
        .get_by_id(&session_id)
        .await
        .unwrap();

    let response = client
        .post("/file/upload/initiate/in-flight.bin")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let _: InitUploadResponse = response.into_json().await.unwrap();
    assert_eq!(partial_uploads(&test_user.path).len(), 1);

    let response = client
        .delete("/session")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);

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

    let db = session.db_pool.get().unwrap();
    assert!(sqlite::get_all_active_uploads(&db).unwrap().is_empty());
}

fn short_policy(idle_secs: u64, lifetime_secs: u64) -> SessionPolicy {
    SessionPolicy {
        idle_timeout: Duration::from_secs(idle_secs),
        max_lifetime: Duration::from_secs(lifetime_secs),
        ..SessionPolicy::default()
    }
}

async fn list_root(client: &Client, cookie: &Cookie<'static>) -> Status {
    client
        .get("/folder/")
        .private_cookie(cookie.clone())
        .dispatch()
        .await
        .status()
}

async fn session_exists(client: &Client, session_id: &str) -> bool {
    client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions
        .get_by_id(session_id)
        .await
        .is_some()
}

#[async_test]
async fn test_idle_session_expires() {
    let (rocket, test_user) = setup_rocket_with_session_policy(short_policy(1, 3600)).await;
    let rocket = rocket.mount("/folder", routes![get_folder]);
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    assert_eq!(list_root(&client, &cookie).await, Status::Ok);

    rocket::tokio::time::sleep(Duration::from_millis(2100)).await;

    assert_eq!(list_root(&client, &cookie).await, Status::Unauthorized);
    assert!(!session_exists(&client, &session_id).await);
}

#[async_test]
async fn test_activity_keeps_a_session_alive() {
    let (rocket, test_user) = setup_rocket_with_session_policy(short_policy(2, 3600)).await;
    let rocket = rocket.mount("/folder", routes![get_folder]);
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    // Well past the idle timeout in total, but never idle for that long.
    for _ in 0..5 {
        assert_eq!(list_root(&client, &cookie).await, Status::Ok);

        rocket::tokio::time::sleep(Duration::from_millis(700)).await;
    }

    assert_eq!(list_root(&client, &cookie).await, Status::Ok);
}

#[async_test]
async fn test_session_expires_at_its_max_lifetime_even_when_active() {
    let (rocket, test_user) = setup_rocket_with_session_policy(short_policy(3600, 1)).await;
    let rocket = rocket.mount("/folder", routes![get_folder]);
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    for _ in 0..3 {
        rocket::tokio::time::sleep(Duration::from_millis(700)).await;
        list_root(&client, &cookie).await;
    }

    assert_eq!(list_root(&client, &cookie).await, Status::Unauthorized);
    assert!(!session_exists(&client, &session_id).await);
}

#[async_test]
async fn test_enabled_reaper_removes_expired_sessions_without_any_request() {
    let (rocket, test_user) = setup_rocket_with_session_policy(short_policy(1, 3600)).await;
    let rocket = rocket.attach(SessionReaper::every(1).unwrap());
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");
    let (session_id, _) = create_test_session(client.rocket(), test_user.name.clone()).await;

    assert!(session_exists(&client, &session_id).await);

    rocket::tokio::time::sleep(Duration::from_millis(3500)).await;

    assert!(!session_exists(&client, &session_id).await);
}

#[async_test]
async fn test_login_cookie_lives_as_long_as_the_session() {
    let (rocket, test_user) = setup_rocket_with_session_policy(short_policy(3600, 1234)).await;
    let rocket = rocket.mount("/session", routes![create_session]);
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    // Initialize the user DB with the test password
    let _ = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .post("/session")
        .header(ContentType::JSON)
        .body(format!(
            r#"{{"username": "{}", "password": "test_password"}}"#,
            test_user.name
        ))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

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
#[async_test]
async fn test_login_removes_expired_sessions_when_the_reaper_is_disabled() {
    let (rocket, test_user) = setup_rocket_with_session_policy(short_policy(1, 3600)).await;
    let rocket = rocket.mount("/session", routes![create_session]);
    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");
    let (abandoned_id, _) = create_test_session(client.rocket(), test_user.name.clone()).await;

    rocket::tokio::time::sleep(Duration::from_millis(2100)).await;

    assert!(session_exists(&client, &abandoned_id).await);

    let response = client
        .post("/session")
        .header(ContentType::JSON)
        .body(format!(
            r#"{{"username": "{}", "password": "test_password"}}"#,
            test_user.name
        ))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);
    assert!(!session_exists(&client, &abandoned_id).await);
}
