use std::io::Cursor;

use super::*;

fn assert_security_headers(response: &TestResponse, what: &str) {
    let headers = response.headers();

    assert_eq!(headers.get_one("Cache-Control"), Some("no-store"), "{what}");
    assert_eq!(
        headers.get_one("Referrer-Policy"),
        Some("no-referrer"),
        "{what}"
    );
    assert_eq!(headers.get_one("Server"), None, "{what}");
}

// M11a: decrypted files and thumbnails were sent without `Cache-Control`, so
// browsers and proxies could keep plaintext copies of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_responses_are_not_cacheable() {
    let (app, test_user) = setup_app().await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let mut png = Vec::new();
    image::DynamicImage::new_rgb8(20, 20)
        .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();

    let response = client
        .put("/file/photo.png")
        .private_cookie(cookie.clone())
        .body(&png)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let download = client
        .get("/file/photo.png")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(download.status(), StatusCode::OK);
    assert_security_headers(&download, "download");

    let partial = client
        .get("/file/photo.png")
        .header("Range", "bytes=0-9")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
    assert_security_headers(&partial, "range download");

    let thumbnail = client
        .get("/thumbnail/photo.png")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(thumbnail.status(), StatusCode::OK);
    assert_security_headers(&thumbnail, "thumbnail");

    let missing = client
        .get("/file/missing.png")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_security_headers(&missing, "error");

    let unauthenticated = client.get("/file/photo.png").dispatch().await;
    assert_security_headers(&unauthenticated, "unauthenticated");
}
