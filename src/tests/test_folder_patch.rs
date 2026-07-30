use super::*;
use crate::routes::folder::{create_folder, get_folder, patch_folder, PatchFolderData};
use rocket::{http::Status, local::asynchronous::Client, routes};

#[rocket::async_test]
async fn test_patch_folder_rename() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/folder", routes![create_folder, patch_folder, get_folder]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let folder_path = "old_folder";
    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    let patch_data = PatchFolderData {
        folder_name: Some("new_folder".to_string()),
        parent_folder_path: None,
    };

    let response = client
        .patch(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .json(&patch_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);
    
    let get_response = client
        .get("/folder/new_folder")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(get_response.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_patch_folder_move() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/folder", routes![create_folder, patch_folder, get_folder]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let folder_path = "source_folder";
    let dest_path = "dest_folder";
    
    client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
        
    client
        .put(format!("/folder/{}", dest_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    let patch_data = PatchFolderData {
        folder_name: None,
        parent_folder_path: Some(dest_path.to_string()),
    };

    let response = client
        .patch(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .json(&patch_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::NoContent);
    
    let get_response = client
        .get(format!("/folder/{}/{}", dest_path, folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(get_response.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_patch_folder_move_into_self_fails() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/folder", routes![create_folder, patch_folder]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let folder_path = "source_folder";
    
    client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    let patch_data = PatchFolderData {
        folder_name: None,
        parent_folder_path: Some(format!("{}/child", folder_path)),
    };

    let response = client
        .patch(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .json(&patch_data)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::BadRequest);
}
