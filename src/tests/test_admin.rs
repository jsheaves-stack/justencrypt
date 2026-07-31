use super::*;
use crate::routes::admin::{admin_options, delete_session, delete_session_options, get_session};
use rocket::{
    async_test,
    http::{Header, Status},
    local::asynchronous::Client,
    routes,
};

#[async_test]
async fn test_delete_session_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/admin",
        routes![
            get_session,
            admin_options,
            delete_session,
            delete_session_options
        ],
    );
    let test_api_key = "super_secret_test_key";
    std::env::set_var("JUSTENCRYPT_ADMIN_API_KEY", test_api_key);

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
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount("/admin", routes![get_session, admin_options]);
    let test_api_key = "super_secret_test_key";
    std::env::set_var("JUSTENCRYPT_ADMIN_API_KEY", test_api_key);

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
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount("/admin", routes![get_session, admin_options]);
    let test_api_key = "super_secret_test_key";
    std::env::set_var("JUSTENCRYPT_ADMIN_API_KEY", test_api_key);

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
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount("/admin", routes![get_session, admin_options]);
    let test_api_key = "super_secret_test_key";
    std::env::set_var("JUSTENCRYPT_ADMIN_API_KEY", test_api_key);

    let client = Client::tracked(rocket)
        .await
        .expect("valid rocket instance");

    let req = client.get("/admin/session");
    let response = req.dispatch().await;

    assert_eq!(response.status(), Status::Unauthorized);
}
