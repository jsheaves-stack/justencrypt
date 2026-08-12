use super::*;
use crate::{
    routes::{
        file::{delete_file, put_file},
        thumbnail::{get_thumbnail, thumbnail_options},
    },
    util::sharded_path::get_sharded_path,
};
use rocket::{async_test, http::Status, local::asynchronous::Client, routes};
use std::{fs, io::Cursor};

#[async_test]
async fn test_get_thumbnail_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/thumbnail", routes![get_thumbnail, thumbnail_options])
        .mount("/file", routes![put_file]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    // 1. Upload a real image
    let file_path = "test_image.jpg";

    // Actually, I'll generate a tiny valid JPEG.
    let mut img_data = Vec::new();
    let mut cursor = Cursor::new(&mut img_data);
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
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let body = response.into_bytes().await.unwrap();
    assert!(!body.is_empty());

    // 3. Get thumbnail again (should hit cache directly)
    let response_cache_hit = client
        .get(format!("/thumbnail/{}", file_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response_cache_hit.status(), Status::Ok);
    let body_hit = response_cache_hit.into_bytes().await.unwrap();
    assert_eq!(body, body_hit);
}

#[async_test]
async fn test_thumbnail_true_cache_resiliency() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/thumbnail", routes![get_thumbnail, thumbnail_options])
        .mount("/file", routes![put_file]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let file_path = "resiliency_image.jpg";
    let mut img_data = Vec::new();
    let mut cursor = Cursor::new(&mut img_data);
    let tiny_img = image::DynamicImage::new_rgb8(15, 15);
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

    // Initial thumbnail request (populates cache)
    let response = client
        .get(format!("/thumbnail/{}", file_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let orig_body = response.into_bytes().await.unwrap();

    // Now manually delete the user's .cache directory to simulate cache clearing
    let cache_dir = test_user.path.join(".cache");
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir).unwrap();
    }

    // Request thumbnail again after .cache deletion (must regenerate cleanly without DB errors!)
    let response_regen = client
        .get(format!("/thumbnail/{}", file_path))
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response_regen.status(), Status::Ok);
    let regen_body = response_regen.into_bytes().await.unwrap();
    assert_eq!(orig_body, regen_body);
}

#[async_test]
async fn test_thumbnail_deletion_cleanup() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/thumbnail", routes![get_thumbnail, thumbnail_options])
        .mount("/file", routes![put_file, delete_file]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let file_path = "to_delete.jpg";
    let mut img_data = Vec::new();
    let mut cursor = Cursor::new(&mut img_data);
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

    // Populate thumbnail cache
    let response = client
        .get(format!("/thumbnail/{}", file_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // Verify cache file exists in .cache
    let state = client.rocket().state::<AppState>().unwrap();
    let session_guard = state.sessions_by_id.read().await;
    let session = session_guard.get(&session_id).unwrap().clone();
    let encoded_name = session
        .get_encoded_file_name(file_path.into())
        .await
        .unwrap();
    drop(session_guard);

    let cache_dir = test_user.path.join(".cache");
    let sharded_thumb = get_sharded_path(cache_dir, &encoded_name).await;
    assert!(sharded_thumb.exists());

    // Delete the file
    let del_response = client
        .delete(format!("/file/{}", file_path))
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(del_response.status(), Status::NoContent);

    // Assert thumbnail file was cleaned up
    assert!(!sharded_thumb.exists());
}

#[async_test]
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
