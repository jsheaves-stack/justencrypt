use super::*;
use crate::routes::thumbnail::{get_thumbnail, thumbnail_options};
use rocket::{http::Status, local::asynchronous::Client, routes};

#[rocket::async_test]
async fn test_get_thumbnail_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/thumbnail", routes![get_thumbnail, thumbnail_options])
        .mount("/file", routes![crate::routes::file::put_file]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    // 1. Upload a real image
    let file_path = "test_image.jpg";

    // Actually, I'll generate a tiny valid JPEG.
    let mut img_data = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut img_data);
    let tiny_img = image::DynamicImage::new_rgb8(10, 10);
    tiny_img
        .write_to(&mut cursor, image::ImageFormat::Jpeg)
        .unwrap();

    let response = client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body(&img_data)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    // 2. Get thumbnail
    let response = client
        .get(format!("/thumbnail/{}", file_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let body = response.into_bytes().await.unwrap();
    assert!(!body.is_empty());
}

#[rocket::async_test]
async fn test_get_thumbnail_not_found() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/thumbnail", routes![get_thumbnail, thumbnail_options]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .get("/thumbnail/does_not_exist.jpg")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}
