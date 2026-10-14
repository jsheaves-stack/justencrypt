// The HTTP behavior clients can observe: statuses, headers, cookies, path
// decoding and response shapes. Every request goes through the whole
// application, wired as `main` wires it.

use std::sync::Arc;

use serde_json::Value;

use super::*;
use crate::{app::App, config::AppConfig};

const ADMIN_KEY: &str = "http-admin-key";
const APP_ORIGIN: &str = "https://app.example.com";

/// A client for the whole application with an admin key and an allowed
/// origin, logged in as a new user.
async fn http_client(
    configure: impl FnOnce(&mut AppConfig),
) -> (TestClient, Cookie<'static>, TestUser) {
    let name = uuid::Uuid::new_v4().to_string();
    let user = TestUser {
        path: std::env::temp_dir().join(&name),
        name,
    };

    let mut config = test_config();
    config.admin_api_key = Some(SecretString::from_str(ADMIN_KEY).unwrap());
    config.http.allow_origin = Some(APP_ORIGIN.to_string());
    configure(&mut config);

    let app = Arc::new(App::new(Arc::new(config)));
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), user.name.clone()).await;

    (client, cookie, user)
}

fn header<'a>(response: &'a TestResponse, name: &str) -> Option<&'a str> {
    response.headers().get_one(name)
}

fn login_body(user: &TestUser) -> String {
    format!(
        r#"{{"username": "{}", "password": "test_password"}}"#,
        user.name
    )
}

async fn list(client: &TestClient, cookie: &Cookie<'static>, path: &str) -> Value {
    let response = client
        .get(format!("/folder/{path}"))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK, "list {path}");

    serde_json::from_str(&response.into_string().await.unwrap()).unwrap()
}

fn names(listing: &Value) -> Vec<String> {
    let mut names: Vec<String> = listing
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["file_name"].as_str().unwrap().to_string())
        .collect();
    names.sort();

    names
}

// An unknown path is `404`; a known path with an unsupported method is `405`,
// with the methods it does support in `Allow`.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_unmatched_requests_are_not_found() {
    let (client, _cookie, _user) = http_client(|_| {}).await;

    let response = client.get("/nope").dispatch().await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.into_problem().await.status, 404);

    let response = client.patch("/").dispatch().await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header(&response, "Allow"), Some("GET,HEAD"));
    assert_eq!(response.into_problem().await.status, 405);
}

// A `HEAD` request gets the download's `Content-Length` and no body.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_head_keeps_the_length_and_drops_the_body() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    client
        .put("/file/a.bin")
        .private_cookie(cookie.clone())
        .body("0123456789")
        .dispatch()
        .await;

    let response = client
        .head("/file/a.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, "Content-Length"), Some("10"));
    assert!(response.into_bytes().await.unwrap_or_default().is_empty());
}

// The path is percent-decoded before it is split (so `%2F` splits a name
// in two), empty segments are dropped, invalid UTF-8 is replaced, and names
// starting with a dot are kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_path_is_decoded_then_split() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    for path in [
        "a%20b", "c//d", "e/", "f%2Fg", ".hidden", "h%FFi", "j/./k", "l/../m",
    ] {
        let response = client
            .put(format!("/folder/{path}"))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::CREATED, "{path}");
    }

    assert_eq!(
        names(&list(&client, &cookie, "").await),
        [".hidden", "a b", "c", "e", "f", "h\u{FFFD}i", "j", "l"]
    );
    assert_eq!(names(&list(&client, &cookie, "c").await), ["d"]);
    assert_eq!(names(&list(&client, &cookie, "f").await), ["g"]);
    assert_eq!(names(&list(&client, &cookie, "j").await), ["k"]);
    assert_eq!(names(&list(&client, &cookie, "l").await), ["m"]);
}

// A segment starting with an encoded `/` stays below the folders before it
// instead of starting again from the root.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_encoded_slash_stays_in_its_folder() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    for (path, body) in [("secret.txt", "root"), ("docs/%2Fsecret.txt", "docs")] {
        let response = client
            .put(format!("/file/{path}"))
            .private_cookie(cookie.clone())
            .body(body)
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::CREATED, "{path}");
    }

    for (path, body) in [("secret.txt", "root"), ("docs/secret.txt", "docs")] {
        let response = client
            .get(format!("/file/{path}"))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(body),
            "{path}"
        );
    }
}

// The bare mount path and a trailing slash reach the same handlers.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_root_forms_and_trailing_slashes() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    for path in ["/folder", "/folder/"] {
        let response = client
            .get(path)
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.into_string().await.unwrap(), "[]", "{path}");
    }

    for path in ["/file", "/file/"] {
        let response = client
            .get(path)
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }

    for path in ["/thumbnail", "/thumbnail/"] {
        let response = client
            .get(path)
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{path}"
        );
    }

    client
        .put("/file/a.bin")
        .private_cookie(cookie.clone())
        .body("0123456789")
        .dispatch()
        .await;

    let response = client
        .get("/file/a.bin/")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = client.options("/session/").dispatch().await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .get("/admin/session/")
        .header("X-Admin-Api-Key", ADMIN_KEY)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

// Without `Content-Type: application/json`, a login is `415`.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_login_content_types() {
    let (client, _cookie, user) = http_client(|_| {}).await;

    let response = client
        .post("/session")
        .body(login_body(&user))
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let response = client
        .post("/session")
        .header("Content-Type", "text/plain")
        .body(login_body(&user))
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let response = client
        .post("/session")
        .header("Content-Type", "application/json; charset=utf-8")
        .body(login_body(&user))
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

// A `PATCH` without `Content-Type: application/json` is `415`.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_patch_without_a_content_type() {
    let (client, cookie, _user) = http_client(|_| {}).await;

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

    let response = client
        .patch("/file/a.bin")
        .private_cookie(cookie.clone())
        .body(r#"{"file_name": "b.bin"}"#)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let response = client
        .patch("/folder/dir")
        .private_cookie(cookie)
        .body(r#"{"folder_name": "renamed"}"#)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// Malformed JSON is `400`; a missing, mistyped or unknown field is `422`; a
// body over the JSON limit is `413`.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_json_body_errors() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    client
        .put("/file/a.bin")
        .private_cookie(cookie.clone())
        .body("0123456789")
        .dispatch()
        .await;

    let cases = [
        ("{", StatusCode::BAD_REQUEST),
        (r#"{"username": "x"}"#, StatusCode::UNPROCESSABLE_ENTITY),
        (
            r#"{"username": 1, "password": "p"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];

    for (body, expected) in cases {
        let response = client
            .post("/session")
            .header("Content-Type", "application/json")
            .body(body)
            .dispatch()
            .await;

        assert_eq!(response.status(), expected, "login {body}");
    }

    let response = client
        .patch("/file/a.bin")
        .header("Content-Type", "application/json")
        .private_cookie(cookie.clone())
        .body(r#"{"file_name": "z", "extra": 1}"#)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let too_large = format!(r#"{{"file_name": "{}"}}"#, "a".repeat(11 * 1024 * 1024));
    let response = client
        .patch("/file/a.bin")
        .header("Content-Type", "application/json")
        .private_cookie(cookie)
        .body(too_large)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// An upload query without its parameter, or with one that doesn't parse, is
// `422`. The session is checked first.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_upload_query_errors() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    let response = client
        .post("/upload/initiate/up.bin")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let upload_id = body["upload_id"].as_str().unwrap().to_string();

    for query in ["", "?total_size=abc"] {
        let response = client
            .post(format!("/upload/finalize/{upload_id}{query}"))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{query}"
        );

        // The session is checked before the query.
        let response = client
            .post(format!("/upload/finalize/{upload_id}{query}"))
            .dispatch()
            .await;

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "unauthenticated {query}"
        );
    }

    for query in ["?offset=0", "?offset=abc"] {
        let response = client
            .put(format!("/upload/chunk/{upload_id}{query}"))
            .dispatch()
            .await;

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "unauthenticated {query}"
        );
    }
}

// A wrong admin key is `401`; without a configured key the admin routes don't
// exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_admin_key_and_routes() {
    let (client, _cookie, _user) = http_client(|_| {}).await;

    let response = client
        .post("/admin/users")
        .header("Content-Type", "application/json")
        .header("X-Admin-Api-Key", "wrong")
        .body("{}")
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (client, _cookie, _user) = http_client(|config| config.admin_api_key = None).await;

    let response = client
        .get("/admin/session")
        .header("X-Admin-Api-Key", ADMIN_KEY)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// The same headers on successes, route errors, unmatched routes and
// rejected sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_security_headers_on_every_response() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    let responses = [
        ("success", client.get("/").dispatch().await),
        (
            "route error",
            client
                .get("/file/missing.bin")
                .private_cookie(cookie.clone())
                .dispatch()
                .await,
        ),
        ("unmatched", client.get("/nope").dispatch().await),
        ("no session", client.get("/folder").dispatch().await),
    ];

    for (what, response) in &responses {
        assert_eq!(
            header(response, "Cache-Control"),
            Some("no-store"),
            "{what}"
        );
        assert_eq!(
            header(response, "Referrer-Policy"),
            Some("no-referrer"),
            "{what}"
        );
        assert_eq!(
            header(response, "X-Content-Type-Options"),
            Some("nosniff"),
            "{what}"
        );
        assert_eq!(
            header(response, "X-Frame-Options"),
            Some("SAMEORIGIN"),
            "{what}"
        );
        assert_eq!(
            header(response, "Permissions-Policy"),
            Some("interest-cohort=()"),
            "{what}"
        );
        assert_eq!(
            header(response, "Strict-Transport-Security"),
            Some("max-age=31536000"),
            "{what}"
        );
        assert_eq!(header(response, "Server"), None, "{what}");
    }

    assert_eq!(responses[3].1.status(), StatusCode::UNAUTHORIZED);
}

// Error responses carry the CORS headers too, so the allowed origin's pages
// can read them.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_cors_on_error_responses() {
    let (client, _cookie, _user) = http_client(|_| {}).await;

    let responses = [
        client
            .get("/nope")
            .header("Origin", APP_ORIGIN)
            .dispatch()
            .await,
        client
            .get("/folder")
            .header("Origin", APP_ORIGIN)
            .dispatch()
            .await,
    ];

    for response in &responses {
        assert_eq!(
            header(response, "Access-Control-Allow-Origin"),
            Some(APP_ORIGIN)
        );
        assert_eq!(
            header(response, "Access-Control-Allow-Credentials"),
            Some("true")
        );
        assert_eq!(header(response, "Vary"), Some("Origin"));
    }

    assert_eq!(responses[0].status(), StatusCode::NOT_FOUND);
    assert_eq!(responses[1].status(), StatusCode::UNAUTHORIZED);
}

// The login cookie's attributes.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_login_cookie_attributes() {
    for secure in [true, false] {
        let (client, _cookie, user) =
            http_client(|config| config.http.secure_cookies = secure).await;

        let response = client
            .post("/session")
            .header("Content-Type", "application/json")
            .body(login_body(&user))
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);

        let set_cookie = header(&response, "Set-Cookie").unwrap();
        let cookie = Cookie::parse(set_cookie.to_string()).unwrap();

        assert_eq!(cookie.name(), "sid");
        assert_eq!(cookie.http_only(), Some(true), "{set_cookie}");
        assert_eq!(
            cookie.same_site(),
            Some(cookie::SameSite::Strict),
            "{set_cookie}"
        );
        assert_eq!(cookie.path(), Some("/"), "{set_cookie}");
        assert_eq!(
            cookie.max_age().map(|age| age.whole_seconds()),
            Some(7 * 24 * 60 * 60),
            "{set_cookie}"
        );
        assert!(cookie.expires().is_some(), "{set_cookie}");
        assert_eq!(cookie.secure().unwrap_or(false), secure, "{set_cookie}");
    }
}

// Logging out clears the cookie, whether or not the server still knew
// the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_logout_clears_the_cookie() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    let known = client
        .delete("/session")
        .private_cookie(cookie)
        .dispatch()
        .await;
    let unknown = client
        .delete("/session")
        .private_cookie(Cookie::new("sid", "no-such-session"))
        .dispatch()
        .await;

    assert_eq!(known.status(), StatusCode::NO_CONTENT);
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);

    for response in [&known, &unknown] {
        let set_cookie = header(response, "Set-Cookie").unwrap();
        let cookie = Cookie::parse(set_cookie.to_string()).unwrap();

        assert_eq!(cookie.name(), "sid");
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.path(), Some("/"), "{set_cookie}");
        assert_eq!(
            cookie.max_age().map(|age| age.whole_seconds()),
            Some(0),
            "{set_cookie}"
        );
    }

    let response = client.delete("/session").dispatch().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(header(&response, "Set-Cookie"), None);
}

// Downloads are `application/octet-stream`; thumbnails have their image's
// type.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_download_and_thumbnail_content_types() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    client
        .put("/file/a.bin")
        .private_cookie(cookie.clone())
        .body("0123456789")
        .dispatch()
        .await;

    let response = client
        .get("/file/a.bin")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(
        header(&response, "Content-Type"),
        Some("application/octet-stream")
    );

    let response = client
        .get("/file/a.bin")
        .header("Range", "bytes=0-1")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        header(&response, "Content-Type"),
        Some("application/octet-stream")
    );

    let mut png = Vec::new();
    image::DynamicImage::new_rgb8(4, 4)
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();

    client
        .put("/file/picture.PNG")
        .private_cookie(cookie.clone())
        .body(png)
        .dispatch()
        .await;

    let response = client
        .get("/thumbnail/picture.PNG")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, "Content-Type"), Some("image/png"));
}

// The JSON shapes of the folder listing and the admin session list.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_json_response_shapes() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    client
        .put("/folder/dir")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    client
        .put("/file/a.bin")
        .private_cookie(cookie.clone())
        .body("0123456789")
        .dispatch()
        .await;

    let listing = list(&client, &cookie, "").await;
    let mut entries = listing.as_array().unwrap().clone();
    entries.sort_by_key(|entry| entry["type"].as_str().unwrap().to_string());

    let mut file_keys: Vec<&str> = entries[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    file_keys.sort();
    assert_eq!(entries[0]["type"], "File");
    assert_eq!(
        file_keys,
        [
            "created_date",
            "file_extension",
            "file_name",
            "file_size",
            "last_modified_date",
            "type"
        ]
    );
    assert_eq!(entries[0]["file_size"], 10);

    let mut folder_keys: Vec<&str> = entries[1]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    folder_keys.sort();
    assert_eq!(entries[1]["type"], "Folder");
    assert_eq!(
        folder_keys,
        [
            "created_date",
            "file_count",
            "file_name",
            "file_size",
            "folder_count",
            "last_modified_date",
            "type"
        ]
    );

    let response = client
        .post("/upload/initiate/up.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = client
        .get("/admin/session")
        .header("X-Admin-Api-Key", ADMIN_KEY)
        .dispatch()
        .await;
    let sessions: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    let session = &sessions.as_array().unwrap()[0];

    let mut session_keys: Vec<&str> = session
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    session_keys.sort();
    assert_eq!(
        session_keys,
        ["active_uploads", "created_at", "session_id", "username"]
    );
    assert!(session["created_at"].is_u64());

    let upload = &session["active_uploads"][0];
    let mut upload_keys: Vec<&str> = upload
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    upload_keys.sort();
    assert_eq!(
        upload_keys,
        [
            "encoded_file_name",
            "file_path",
            "last_updated",
            "upload_id"
        ]
    );
    assert_eq!(upload["file_path"], "up.bin");
    assert!(upload["last_updated"]["secs_since_epoch"].is_u64());
    assert!(upload["last_updated"]["nanos_since_epoch"].is_u64());
}

// The `Range` header is parsed before the file is looked up, so a malformed
// one is `400` even when there is no such file.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_missing_file_with_a_malformed_range() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    let response = client
        .get("/file/missing.bin")
        .header("Range", "bytes=x-")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// A route error's body is Problem Details, with the error's message as the
// detail.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_route_error_bodies() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    let response = client
        .get("/file/missing.bin")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let problem = response.into_problem().await;

    assert_eq!(problem.kind, "about:blank");
    assert_eq!(problem.title, "Not Found");
    assert_eq!(problem.status, 404);
    assert_eq!(problem.detail.as_deref(), Some("Not found"));
}

// A URL parameter that isn't valid UTF-8 is `400`, with a Problem Details
// body like every other error.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_undecodable_path_parameters() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    let responses = [
        client
            .put("/upload/chunk/%FF?offset=0")
            .private_cookie(cookie.clone())
            .dispatch()
            .await,
        client
            .post("/upload/finalize/%FF?total_size=0")
            .private_cookie(cookie.clone())
            .dispatch()
            .await,
        client
            .delete("/admin/session/%FF")
            .header("X-Admin-Api-Key", ADMIN_KEY)
            .dispatch()
            .await,
    ];

    for response in responses {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let problem = response.into_problem().await;

        assert_eq!(problem.status, 400);
        assert!(problem.detail.is_some());
    }
}

// Any `download` parameter, with or without a value, selects the archive.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_http_folder_download_query() {
    let (client, cookie, _user) = http_client(|_| {}).await;

    client
        .put("/folder/dir")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    for (query, archive) in [
        ("?download", true),
        ("?a=1&download", true),
        ("?download=1", true),
        ("?downloads", false),
    ] {
        let response = client
            .get(format!("/folder/dir{query}"))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), StatusCode::OK, "{query}");

        let expected = if archive {
            "application/x-tar"
        } else {
            "application/json"
        };
        assert_eq!(header(&response, "Content-Type"), Some(expected), "{query}");
    }
}
