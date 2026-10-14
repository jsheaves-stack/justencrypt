use super::*;

const APP_ORIGIN: &str = "https://app.example.com";

async fn client_with_origin(allow_origin: Option<&str>) -> (TestClient, TestUser) {
    let (app, test_user) =
        setup_app_with_config(|config| config.http.allow_origin = allow_origin.map(str::to_owned))
            .await;
    let client = TestClient::new(app);

    (client, test_user)
}

fn header<'a>(response: &'a TestResponse, name: &str) -> Option<&'a str> {
    response.headers().get_one(name)
}

fn assert_no_cors_grant(response: &TestResponse) {
    assert_eq!(header(response, "Access-Control-Allow-Origin"), None);
    assert_eq!(header(response, "Access-Control-Allow-Credentials"), None);
    assert_eq!(header(response, "Access-Control-Expose-Headers"), None);
}

// M11b: the configured origin gets its CORS headers, echoed back exactly.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cors_allows_the_configured_origin() {
    let (client, _test_user) = client_with_origin(Some(APP_ORIGIN)).await;

    let response = client
        .get("/")
        .header("Origin", APP_ORIGIN)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
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
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cors_answers_preflight_from_the_configured_origin() {
    let (client, _test_user) = client_with_origin(Some(APP_ORIGIN)).await;

    let response = client
        .options("/file/photo.png")
        .header("Origin", APP_ORIGIN)
        .header("Access-Control-Request-Method", "PUT")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
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
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cors_ignores_other_origins() {
    let (client, _test_user) = client_with_origin(Some(APP_ORIGIN)).await;

    for origin in [
        "https://evil.example.com",
        "http://app.example.com",
        "https://app.example.com.evil.example",
    ] {
        let response = client
            .options("/file/photo.png")
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "PUT")
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
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cors_without_a_configured_origin_grants_nothing() {
    let (client, _test_user) = client_with_origin(None).await;

    let response = client
        .get("/")
        .header("Origin", APP_ORIGIN)
        .dispatch()
        .await;

    assert_no_cors_grant(&response);
    assert_eq!(header(&response, "Access-Control-Allow-Methods"), None);
}

// M11b: every OPTIONS response used to be turned into a 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cors_leaves_options_status_alone() {
    let (client, _test_user) = client_with_origin(Some(APP_ORIGIN)).await;

    let response = client
        .options("/does/not/exist")
        .header("Origin", APP_ORIGIN)
        .header("Access-Control-Request-Method", "GET")
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
