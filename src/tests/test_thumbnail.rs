use super::*;
use crate::routes::thumbnail::{get_thumbnail, thumbnail_options};
use rocket::{http::Status, local::asynchronous::Client, routes};

#[rocket::async_test]
async fn test_get_thumbnail_not_found() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/thumbnail", routes![get_thumbnail, thumbnail_options]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client.get("/thumbnail/does_not_exist.jpg")
                         .private_cookie(cookie)
                         .dispatch().await;

    assert_eq!(response.status(), Status::NotFound); 
}
