use rocket::{async_test, http::Status, local::asynchronous::Client, routes};

use super::*;
use crate::{
    routes::{
        file::{get_file, put_file},
        folder::{create_folder, delete_folder, get_folder},
    },
    AppState,
};

#[async_test]
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
    let session = client
        .rocket()
        .state::<AppState>()
        .unwrap()
        .sessions
        .get_by_id(&session_id)
        .await
        .unwrap();

    // The DB query should fail because the folder doesn't exist
    let lookup_result = session.get_folder_id(parent_folder.into()).await;
    assert!(lookup_result.is_err() || lookup_result.unwrap().is_none());
}

#[async_test]
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

async fn put_text(client: &Client, cookie: &rocket::http::Cookie<'static>, path: &str) {
    let response = client
        .put(format!("/file/{}", path))
        .private_cookie(cookie.clone())
        .body("content")
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);
}

// M7: deleting the root used to delete every file and folder first, then fail
// on the root itself, wiping the account and still returning 500.
#[async_test]
async fn test_delete_root_folder_is_rejected_and_deletes_nothing() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/folder", routes![get_folder, delete_folder])
        .mount("/file", routes![put_file, get_file]);
    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    put_text(&client, &cookie, "top.txt").await;
    put_text(&client, &cookie, "docs/nested/deep.txt").await;
    let blobs_before = stored_files(&test_user.path).len();

    for root in ["/folder/", "/folder"] {
        let response = client
            .delete(root)
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest, "DELETE {}", root);
    }

    for path in ["top.txt", "docs/nested/deep.txt"] {
        let response = client
            .get(format!("/file/{}", path))
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok, "{} should survive", path);
    }

    assert_eq!(stored_files(&test_user.path).len(), blobs_before);
}

#[async_test]
async fn test_delete_folder_tree_removes_every_file_and_leaves_siblings() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount("/folder", routes![get_folder, delete_folder])
        .mount("/file", routes![put_file, get_file]);
    let client = Client::tracked(rocket).await.expect("valid rocket");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    put_text(&client, &cookie, "doomed/a.txt").await;
    put_text(&client, &cookie, "doomed/sub/b.txt").await;
    put_text(&client, &cookie, "doomed/sub/deeper/c.txt").await;
    put_text(&client, &cookie, "kept/d.txt").await;
    put_text(&client, &cookie, "e.txt").await;

    let response = client
        .delete("/folder/doomed")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(stored_files(&test_user.path).len(), 2);

    for (path, expected) in [
        ("/folder/doomed", Status::NotFound),
        ("/folder/doomed/sub", Status::NotFound),
        ("/file/doomed/sub/b.txt", Status::NotFound),
        ("/file/kept/d.txt", Status::Ok),
        ("/file/e.txt", Status::Ok),
    ] {
        let response = client
            .get(path)
            .private_cookie(cookie.clone())
            .dispatch()
            .await;

        assert_eq!(response.status(), expected, "GET {}", path);
    }

    // The deleted folder is gone from the root listing; its sibling isn't.
    let response = client
        .get("/folder/")
        .private_cookie(cookie)
        .dispatch()
        .await;
    let listing: serde_json::Value = response.into_json().await.unwrap();
    let names: Vec<&str> = listing
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["file_name"].as_str().unwrap())
        .collect();

    assert!(!names.contains(&"doomed"), "listing: {:?}", names);
    assert!(names.contains(&"kept"), "listing: {:?}", names);
}
