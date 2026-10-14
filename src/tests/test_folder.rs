use super::*;
use crate::web::routes::folder::FolderEntry;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_folder() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (session_id, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let state = client.app();
    let session = state.sessions.get_by_id(&session_id).await.unwrap();

    let folder_id = session
        .context
        .get_folder_id(folder_path.into())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(2, folder_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_folder() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let response = client
        .get(format!("/folder/{}", folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_create_folder_no_auth() {
    let (app, _test_user) = setup_app().await;
    let client = TestClient::new(app);

    let folder_path = "test_folder";

    let response = client
        .put(format!("/folder/{}", folder_path))
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_folder_file_metadata() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    let folder_path = "meta_folder";
    let file_name = "test_meta.txt";
    let file_content = "metadata test content";

    // Create folder
    let response = client
        .put(format!("/folder/{}", folder_path))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Create file inside folder
    let response = client
        .put(format!("/file/{}/{}", folder_path, file_name))
        .private_cookie(cookie.clone())
        .body(file_content)
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Get folder contents
    let response = client
        .get(format!("/folder/{}", folder_path))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let entries: Vec<FolderEntry> = response.into_json().await.unwrap();
    assert_eq!(entries.len(), 1);

    let entry = &entries[0];

    if let FolderEntry::File(file) = entry {
        assert_eq!(file.file_name, file_name);
        assert_eq!(file.file_size, Some(file_content.len() as u64));
        assert!(file.created_date.is_some());
        assert!(file.last_modified_date.is_some());
    } else {
        panic!("Expected a file");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_folder_with_subfolder_size() {
    let (app, test_user) = setup_app().await;

    let client = TestClient::new(app);

    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

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
    assert_eq!(response.status(), StatusCode::CREATED);

    // Create sub folder
    let response = client
        .put(format!("/folder/{}/{}", main_folder, sub_folder))
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

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
    assert_eq!(response.status(), StatusCode::CREATED);

    // Get main folder contents
    let response = client
        .get(format!("/folder/{}", main_folder))
        .private_cookie(cookie)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let entries: Vec<FolderEntry> = response.into_json().await.unwrap();
    assert_eq!(entries.len(), 1);

    let entry = &entries[0];

    if let FolderEntry::Folder(folder) = entry {
        assert_eq!(folder.file_name, sub_folder);
        assert_eq!(folder.file_size, Some(file_content.len() as u64));
        assert_eq!(folder.file_count, 1);
        assert_eq!(folder.folder_count, 0);
        assert!(folder.created_date.is_some());
    } else {
        panic!("Expected a folder");
    }
}
