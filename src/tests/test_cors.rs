use rocket::{
    async_test,
    http::{Header, Status},
    local::asynchronous::{Client, LocalResponse},
    routes, Build, Rocket,
};

use super::*;
use crate::{
    routes::{file::file_options, info::get_server_info},
    web::fairings::Cors,
};

const APP_ORIGIN: &str = "https://app.example.com";

async fn client_with_origin(allow_origin: Option<&str>) -> (Client, TestUser) {
    let (rocket, test_user): (Rocket<Build>, TestUser) = setup_rocket().await;
    let rocket = rocket
        .attach(Cors::new(allow_origin.map(str::to_owned)))
        .mount("/", routes![get_server_info])
        .mount("/file", routes![file_options]);
    let client = Client::tracked(rocket).await.expect("valid rocket");

    (client, test_user)
}

fn header<'a>(response: &'a LocalResponse<'_>, name: &str) -> Option<&'a str> {
    response.headers().get_one(name)
}

fn assert_no_cors_grant(response: &LocalResponse<'_>) {
    assert_eq!(header(response, "Access-Control-Allow-Origin"), None);
    assert_eq!(header(response, "Access-Control-Allow-Credentials"), None);
    assert_eq!(header(response, "Access-Control-Expose-Headers"), None);
}

// M11b: the configured origin gets its CORS headers, echoed back exactly.
#[async_test]
async fn test_cors_allows_the_configured_origin() {
    let (client, _test_user) = client_with_origin(Some(APP_ORIGIN)).await;

    let response = client
        .get("/")
        .header(Header::new("Origin", APP_ORIGIN))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        header(&response, "Access-Control-Allow-Origin"),
        Some(APP_ORIGIN)
    );
    assert_eq!(
        header(&response, "Access-Control-Allow-Credentials"),
        Some("true")
    );
    assert_eq!(
        header(&response, "Access-Control-Expose-Headers"),
        Some("Content-Range, Content-Length, Accept-Ranges, Content-Disposition")
    );
    assert_eq!(header(&response, "Vary"), Some("Origin"));
    // A request header, meaningless in a response.
    assert_eq!(header(&response, "Access-Control-Request-Methods"), None);
    assert_eq!(header(&response, "Allow"), None);
}

// M11b: a preflight from the configured origin is answered by the route's
// own 204, with the methods and headers the browser may use.
#[async_test]
async fn test_cors_answers_preflight_from_the_configured_origin() {
    let (client, _test_user) = client_with_origin(Some(APP_ORIGIN)).await;

    let response = client
        .options("/file/photo.png")
        .header(Header::new("Origin", APP_ORIGIN))
        .header(Header::new("Access-Control-Request-Method", "PUT"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(
        header(&response, "Access-Control-Allow-Origin"),
        Some(APP_ORIGIN)
    );
    assert!(header(&response, "Access-Control-Allow-Methods")
        .unwrap()
        .contains("PUT"));
    assert!(header(&response, "Access-Control-Allow-Headers")
        .unwrap()
        .contains("Content-Type"));
    assert_eq!(header(&response, "Access-Control-Max-Age"), Some("600"));
}

// M11b: credentials used to be allowed for every origin.
#[async_test]
async fn test_cors_ignores_other_origins() {
    let (client, _test_user) = client_with_origin(Some(APP_ORIGIN)).await;

    for origin in [
        "https://evil.example.com",
        "http://app.example.com",
        "https://app.example.com.evil.example",
    ] {
        let response = client
            .options("/file/photo.png")
            .header(Header::new("Origin", origin))
            .header(Header::new("Access-Control-Request-Method", "PUT"))
            .dispatch()
            .await;

        assert_no_cors_grant(&response);
        assert_eq!(header(&response, "Access-Control-Allow-Methods"), None);
        assert_eq!(header(&response, "Vary"), Some("Origin"));
    }

    let no_origin = client.get("/").dispatch().await;
    assert_no_cors_grant(&no_origin);
}

// M11b: with no origin configured, no response grants CORS access.
#[async_test]
async fn test_cors_without_a_configured_origin_grants_nothing() {
    let (client, _test_user) = client_with_origin(None).await;

    let response = client
        .get("/")
        .header(Header::new("Origin", APP_ORIGIN))
        .dispatch()
        .await;

    assert_no_cors_grant(&response);
    assert_eq!(header(&response, "Access-Control-Allow-Methods"), None);
}

// M11b: every OPTIONS response used to be turned into a 200.
#[async_test]
async fn test_cors_leaves_options_status_alone() {
    let (client, _test_user) = client_with_origin(Some(APP_ORIGIN)).await;

    let response = client
        .options("/does/not/exist")
        .header(Header::new("Origin", APP_ORIGIN))
        .header(Header::new("Access-Control-Request-Method", "GET"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}
