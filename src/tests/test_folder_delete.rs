use super::*;
use crate::{
    routes::{
        file::put_file,
        folder::{create_folder, delete_folder, get_folder},
    },
    AppState,
};
use rocket::{http::Status, local::asynchronous::Client, routes};

#[rocket::async_test]
async fn test_delete_folder_success() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/folder", routes![create_folder, get_folder, delete_folder])
        .mount("/file", routes![put_file]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let parent_folder = "parent_folder";
    let child_folder = format!("{}/child_folder", parent_folder);

    // Create folders
    client
        .put(format!("/folder/{}", parent_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    client
        .put(format!("/folder/{}", child_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    // Create a file inside the child folder
    let file_path = format!("{}/test.txt", child_folder);
    client
        .put(format!("/file/{}", file_path))
        .private_cookie(cookie.clone())
        .body("test content")
        .dispatch()
        .await;

    // Delete the root parent folder (should recursively delete everything)
    let response = client
        .delete(format!("/folder/{}", parent_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);

    // Verify folder is gone
    let session_guard = client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions_by_id
        .read()
        .await;
    let session_lock = session_guard.get(&session_id).unwrap().clone();
    let session = session_lock.clone();

    // The DB query should fail because the folder doesn't exist
    let lookup_result = session.get_folder_id(parent_folder.into()).await;
    assert!(lookup_result.is_err() || lookup_result.unwrap() == None);
}

#[rocket::async_test]
async fn test_delete_folder_not_found() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/folder", routes![delete_folder]);

    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .delete("/folder/does_not_exist")
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NotFound);
}
