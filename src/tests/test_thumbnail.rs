use std::{fs, io::Cursor};

use rocket::{async_test, http::Status, local::asynchronous::Client, routes};

use super::*;
use crate::{
    routes::{
        file::{delete_file, put_file},
        thumbnail::{get_thumbnail, thumbnail_options},
    },
    session::policy::SessionPolicy,
    util::sharded_path::get_sharded_path,
};

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

    // Request thumbnail again after .cache deletion (must regenerate cleanly
    // without DB errors!)
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
    let session = state.sessions.get_by_id(&session_id).await.unwrap();
    let encoded_name = session
        .get_encoded_file_name(file_path.into())
        .await
        .unwrap();

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

async fn upload_image(client: &Client, cookie: &rocket::http::Cookie<'static>, path: &str) {
    let mut img_data = Vec::new();
    image::DynamicImage::new_rgb8(40, 30)
        .write_to(&mut Cursor::new(&mut img_data), image::ImageFormat::Png)
        .unwrap();

    let response = client
        .put(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .body(&img_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);
}

fn cached_thumbnails(user_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let cache = user_dir.join(".cache");

    stored_files(user_dir)
        .into_iter()
        .filter(|path| path.starts_with(&cache))
        .collect()
}

fn assert_is_thumbnail(body: &[u8]) {
    let img = image::load_from_memory(body).expect("response should be a valid image");

    assert!(img.width() <= 150 && img.height() <= 150);
}

// M9: a damaged cache entry used to make that thumbnail return 500 forever.
#[async_test]
async fn test_corrupt_cached_thumbnail_is_regenerated() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/thumbnail", routes![get_thumbnail])
        .mount("/file", routes![put_file]);
    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    upload_image(&client, &cookie, "pic.png").await;

    let first = client
        .get("/thumbnail/pic.png")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(first.status(), Status::Ok);
    let first = first.into_bytes().await.unwrap();

    let cached = cached_thumbnails(&test_user.path);
    assert_eq!(cached.len(), 1);
    fs::write(&cached[0], b"not an encrypted thumbnail").unwrap();

    for _ in 0..2 {
        let response = client
            .get("/thumbnail/pic.png")
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_bytes().await.unwrap(), first);
    }

    // The cache entry was replaced with a good one.
    assert_ne!(fs::read(&cached[0]).unwrap(), b"not an encrypted thumbnail");
}

#[async_test]
async fn test_concurrent_thumbnail_requests_all_succeed() {
    let (rocket, test_user) = setup_rocket_with_options(SessionPolicy::default(), false, 8).await;
    let rocket = rocket
        .mount("/thumbnail", routes![get_thumbnail])
        .mount("/file", routes![put_file]);
    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;
    upload_image(&client, &cookie, "busy.png").await;

    let request = || async {
        let response = client
            .get("/thumbnail/busy.png")
            .private_cookie(cookie.clone())
            .dispatch()
            .await;
        let status = response.status();

        (status, response.into_bytes().await.unwrap_or_default())
    };
    let results = rocket::tokio::join!(
        request(),
        request(),
        request(),
        request(),
        request(),
        request(),
        request(),
        request()
    );
    let results = [
        results.0, results.1, results.2, results.3, results.4, results.5, results.6, results.7,
    ];

    for (status, body) in &results {
        assert_eq!(*status, Status::Ok);
        assert_is_thumbnail(body);
        assert_eq!(body, &results[0].1);
    }

    // One complete cache entry, no temporary files, and it decrypts.
    assert_eq!(cached_thumbnails(&test_user.path).len(), 1);

    let again = client
        .get("/thumbnail/busy.png")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(again.status(), Status::Ok);
    assert_eq!(again.into_bytes().await.unwrap(), results[0].1);
}
