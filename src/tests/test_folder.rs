use super::*;
use crate::{
    db::sqlite::FolderContent,
    routes::{
        file::put_file,
        folder::{create_folder, delete_folder, folder_options, get_folder},
    },
    AppState,
};
use rocket::{http::Status, local::asynchronous::Client, routes};

#[rocket::async_test]
async fn test_create_folder() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/folder",
        routes![create_folder, get_folder, delete_folder, folder_options],
    );

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (session_id, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    let state = client.rocket().state::<AppState>().unwrap();
    let session_guard = state.sessions_by_id.read().await;
    let session_lock = session_guard.get(&session_id).unwrap().clone();
    let session = session_lock.clone();

    let folder_id = session
        .get_folder_id(folder_path.into())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(2, folder_id);
}

#[rocket::async_test]
async fn test_get_folder() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/folder",
        routes![create_folder, get_folder, delete_folder, folder_options],
    );

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    let response = client
        .get(format!("/folder/{}", folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
}

#[rocket::async_test]
async fn test_create_folder_no_auth() {
    let (rocket, _test_user) = setup_rocket().await;
    let rocket = rocket.mount(
        "/folder",
        routes![create_folder, get_folder, delete_folder, folder_options],
    );
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_get_folder_file_metadata() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount(
            "/folder",
            routes![create_folder, get_folder, delete_folder, folder_options],
        )
        .mount("/file", routes![put_file]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let folder_path = "meta_folder";
    let file_name = "test_meta.txt";
    let file_content = "metadata test content";

    // Create folder
    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    // Create file inside folder
    let response = client
        .put(format!("/file/{}/{}", folder_path, file_name))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    // Get folder contents
    let response = client
        .get(format!("/folder/{}", folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    let entries: Vec<FolderContent> = response.into_json().await.unwrap();
    assert_eq!(entries.len(), 1);

    let entry = &entries[0];
    if let FolderContent::File(file) = entry {
        assert_eq!(file.file_name, file_name);
        assert_eq!(file.file_size, Some(file_content.len() as u64));
        assert!(file.created_date.is_some());
        assert!(file.last_modified_date.is_some());
    } else {
        panic!("Expected a file");
    }
}

#[rocket::async_test]
async fn test_get_folder_with_subfolder_size() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket
        .mount(
            "/folder",
            routes![create_folder, get_folder, delete_folder, folder_options],
        )
        .mount("/file", routes![put_file]);

    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");

    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let main_folder = "main_folder_for_size";
    let sub_folder = "sub_folder_for_size";
    let file_name = "file_for_size.txt";
    let file_content = "some content for size calculation";

    // Create main folder
    let response = client
        .put(format!("/folder/{}", main_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    // Create sub folder
    let response = client
        .put(format!("/folder/{}/{}", main_folder, sub_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    // Create file inside sub folder
    let response = client
        .put(format!(
            "/file/{}/{}/{}",
            main_folder, sub_folder, file_name
        ))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    // Get main folder contents
    let response = client
        .get(format!("/folder/{}", main_folder))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);

    let entries: Vec<FolderContent> = response.into_json().await.unwrap();
    assert_eq!(entries.len(), 1);

    let entry = &entries[0];
    if let FolderContent::Folder(folder) = entry {
        assert_eq!(folder.file_name, sub_folder);
        assert_eq!(folder.file_size, Some(file_content.len() as u64));
        assert_eq!(folder.file_count, 1);
        assert_eq!(folder.folder_count, 0);
        assert!(folder.created_date.is_some());
    } else {
        panic!("Expected a folder");
    }
}
