// The web layer's own behavior: error bodies, JSON content types, the upload
// routes' place in the URL space, and how request paths are read.

use axum::{body::Body, extract::Request};

use super::*;
use crate::web::{middleware::normalize_path, unrestricted_path::UnrestrictedPath};

const ADMIN_KEY: &str = "web-admin-key";

async fn web_client() -> (TestClient, Cookie<'static>, TestUser) {
    let (app, user) = setup_app_with_config(|config| {
        config.admin_api_key = Some(SecretString::from_str(ADMIN_KEY).unwrap());
    })
    .await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), user.name.clone()).await;

    (client, cookie, user)
}

fn normalized(path: &str) -> String {
    let request = Request::builder().uri(path).body(Body::empty()).unwrap();

    normalize_path(request).uri().to_string()
}

// Every kind of error, wherever it comes from, has a Problem Details body
// whose status matches the response's.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_every_error_is_problem_details() {
    let (client, cookie, _user) = web_client().await;

    client
        .put("/file/a.bin")
        .private_cookie(cookie.clone())
        .body("0123456789")
        .dispatch()
        .await;

    let responses = [
        ("unmatched route", client.get("/nope").dispatch().await),
        ("method not allowed", client.patch("/").dispatch().await),
        ("no session", client.get("/folder").dispatch().await),
        (
            "wrong admin key",
            client
                .get("/admin/session")
                .header("X-Admin-Api-Key", "wrong")
                .dispatch()
                .await,
        ),
        (
            "route error",
            client
                .get("/file/missing.bin")
                .private_cookie(cookie.clone())
                .dispatch()
                .await,
        ),
        (
            "malformed JSON",
            client
                .patch("/file/a.bin")
                .header("Content-Type", "application/json")
                .private_cookie(cookie.clone())
                .body("{")
                .dispatch()
                .await,
        ),
        (
            "bad query",
            client
                .post("/upload/finalize/some-id?total_size=lots")
                .private_cookie(cookie.clone())
                .dispatch()
                .await,
        ),
        (
            "range not satisfiable",
            client
                .get("/file/a.bin")
                .header("Range", "bytes=50-")
                .private_cookie(cookie)
                .dispatch()
                .await,
        ),
    ];

    for (what, response) in responses {
        let status = response.status();

        assert!(status.is_client_error(), "{what}: {status}");

        let problem = response.into_problem().await;

        assert_eq!(problem.status, status.as_u16(), "{what}");
        assert_eq!(problem.kind, "about:blank", "{what}");
        assert_eq!(problem.title, status.canonical_reason().unwrap(), "{what}");
    }
}

// The errors a route reports keep their message as the detail, and a range
// past the end of the file still says how long the file is.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_route_errors_keep_their_message() {
    let (client, cookie, _user) = web_client().await;

    client
        .put("/file/a.bin")
        .private_cookie(cookie.clone())
        .body("0123456789")
        .dispatch()
        .await;

    let response = client.get("/folder").dispatch().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.into_problem().await.detail.as_deref(),
        Some("Failed to find session id")
    );

    let response = client
        .get("/file/a.bin")
        .header("Range", "bytes=50-")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response.headers().get_one("Content-Range"),
        Some("bytes */10")
    );
    assert_eq!(
        response.into_problem().await.detail.as_deref(),
        Some("Range not satisfiable")
    );
}

// Every route that takes a JSON body needs `Content-Type: application/json`.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_json_routes_require_a_json_content_type() {
    let (client, cookie, _user) = web_client().await;

    client
        .put("/file/a.bin")
        .private_cookie(cookie.clone())
        .body("0123456789")
        .dispatch()
        .await;
    client
        .put("/folder/dir")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    let requests = [
        (
            "login",
            client
                .post("/session")
                .body(r#"{"username": "a", "password": "b"}"#),
        ),
        (
            "create user",
            client
                .post("/admin/users")
                .header("X-Admin-Api-Key", ADMIN_KEY)
                .body(r#"{"username": "a", "password": "b"}"#),
        ),
        (
            "rename file",
            client
                .patch("/file/a.bin")
                .private_cookie(cookie.clone())
                .body(r#"{"file_name": "b.bin"}"#),
        ),
        (
            "rename folder",
            client
                .patch("/folder/dir")
                .private_cookie(cookie)
                .body(r#"{"folder_name": "renamed"}"#),
        ),
    ];

    for (what, request) in requests {
        let response = request
            .header("Content-Type", "text/plain")
            .dispatch()
            .await;

        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{what}"
        );
        assert_eq!(response.into_problem().await.status, 415, "{what}");
    }
}

// The upload routes answer CORS preflights like every other route.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_upload_routes_answer_preflights() {
    let (client, _cookie, _user) = web_client().await;

    for path in [
        "/upload/initiate/a.bin",
        "/upload/chunk/some-id",
        "/upload/finalize/some-id",
    ] {
        let response = client.options(path).dispatch().await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path}");
    }
}

// Paths under `upload/` in `/file` are ordinary file paths, apart from the
// `/upload` routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_files_under_upload_are_ordinary_files() {
    let (client, cookie, _user) = web_client().await;

    for path in ["upload/chunk/x", "upload/initiate/y", "upload/finalize/z"] {
        let response = client
            .put(format!("/file/{path}"))
            .private_cookie(cookie.clone())
            .body(path)
            .dispatch()
            .await;
        assert_eq!(response.status(), StatusCode::CREATED, "{path}");

        let response = client
            .get(format!("/file/{path}"))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.into_string().await.unwrap(), path);

        let response = client
            .delete(format!("/file/{path}"))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path}");
    }
}

#[test]
fn test_path_is_decoded_then_split() {
    let cases = [
        ("", ""),
        ("a", "a"),
        ("a/b", "a/b"),
        ("a//b/", "a/b"),
        ("a%20b", "a b"),
        ("a%2Fb", "a/b"),
        ("a/%2Fb", "a/b"),
        ("%2Fsecret", "secret"),
        ("%2F", ""),
        (".hidden", ".hidden"),
        ("h%FFi", "h\u{FFFD}i"),
    ];

    for (raw, expected) in cases {
        let path = UnrestrictedPath::parse(raw).to_path_buf();

        assert_eq!(path.to_str().unwrap(), expected, "{raw:?}");
    }
}

#[test]
fn test_request_paths_lose_empty_segments() {
    assert_eq!(normalized("/"), "/");
    assert_eq!(normalized("/folder"), "/folder");
    assert_eq!(normalized("/folder/"), "/folder");
    assert_eq!(normalized("//folder//a/"), "/folder/a");
    assert_eq!(normalized("/folder/a/?download"), "/folder/a?download");
    assert_eq!(normalized("/file/a%2Fb/"), "/file/a%2Fb");
}
