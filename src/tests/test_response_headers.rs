use std::io::Cursor;

use rocket::{
    async_test,
    http::{Header, Status},
    local::asynchronous::{Client, LocalResponse},
    routes,
};

use super::*;
use crate::{
    routes::{
        file::{get_file, put_file},
        thumbnail::get_thumbnail,
    },
    web::fairings::SecurityHeaders,
};

fn assert_security_headers(response: &LocalResponse<'_>, what: &str) {
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
#[async_test]
async fn test_responses_are_not_cacheable() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .attach(SecurityHeaders)
        .mount("/file", routes![get_file, put_file])
        .mount("/thumbnail", routes![get_thumbnail]);
    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

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
    assert_eq!(response.status(), Status::Created);

    let download = client
        .get("/file/photo.png")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(download.status(), Status::Ok);
    assert_security_headers(&download, "download");

    let partial = client
        .get("/file/photo.png")
        .header(Header::new("Range", "bytes=0-9"))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(partial.status(), Status::PartialContent);
    assert_security_headers(&partial, "range download");

    let thumbnail = client
        .get("/thumbnail/photo.png")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(thumbnail.status(), Status::Ok);
    assert_security_headers(&thumbnail, "thumbnail");

    let missing = client
        .get("/file/missing.png")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(missing.status(), Status::NotFound);
    assert_security_headers(&missing, "error");

    let unauthenticated = client.get("/file/photo.png").dispatch().await;
    assert_security_headers(&unauthenticated, "unauthenticated");
}
