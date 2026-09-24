use std::time::Duration;

use rocket::{
    async_test,
    http::{Cookie, Status},
    local::asynchronous::{Client, LocalResponse},
    routes,
    tokio::time::timeout,
};

use super::*;
use crate::routes::folder::{create_folder, get_folder, patch_folder, PatchFolderData};

#[async_test]
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

#[async_test]
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

#[async_test]
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

// A folder-cycle regression used to hang the request forever, and the stuck
// blocking thread would then wedge the whole test binary. If that ever happens
// again, fail loudly by exiting instead.
async fn move_folder_or_exit<'c>(
    client: &'c Client,
    cookie: &Cookie<'static>,
    folder: &str,
    destination: &str,
) -> LocalResponse<'c> {
    let request = client
        .patch(format!("/folder/{}", folder))
        .private_cookie(cookie.clone())
        .json(&PatchFolderData {
            folder_name: None,
            parent_folder_path: Some(destination.to_string()),
        });

    match timeout(Duration::from_secs(5), request.dispatch()).await {
        Ok(response) => response,
        Err(_) => {
            eprintln!(
                "PATCH /folder/{} hung for destination '{}'",
                folder, destination
            );

            std::process::exit(1);
        },
    }
}

#[async_test]
async fn test_patch_folder_move_into_own_subtree_is_rejected_for_every_path_spelling() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/folder", routes![create_folder, patch_folder, get_folder]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    let response = client
        .put("/folder/a/b/c")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Created);

    for destination in [
        "a/b",
        "a/b/c",
        "a/./b/c",
        "a/b/../b/c",
        "a//b/c",
        "./a/b/c",
        "/a/b/c",
        "a/b/c/",
    ] {
        let response = move_folder_or_exit(&client, &cookie, "a/b", destination).await;

        assert_eq!(
            response.status(),
            Status::BadRequest,
            "destination '{}'",
            destination
        );
    }

    let response = client
        .get("/folder/a/b/c")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

#[async_test]
async fn test_rejected_folder_move_does_not_leave_new_folders_behind() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/folder", routes![create_folder, patch_folder, get_folder]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    client
        .put("/folder/a/b")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    // Resolves to a/b/new, so the move is a cycle, but only after the missing
    // destination folder has been created.
    let response = move_folder_or_exit(&client, &cookie, "a/b", "a//b/new").await;
    assert_eq!(response.status(), Status::BadRequest);

    let response = client
        .get("/folder/a/b/new")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NotFound);
}

#[async_test]
async fn test_patch_folder_move_creates_a_missing_destination() {
    let (rocket, test_user) = setup_rocket().await;
    let rocket = rocket.mount("/folder", routes![create_folder, patch_folder, get_folder]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie) = create_test_session(client.rocket(), test_user.name.clone()).await;

    client
        .put("/folder/a/b")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    let response = move_folder_or_exit(&client, &cookie, "a/b", "x/y").await;
    assert_eq!(response.status(), Status::NoContent);

    let moved = client
        .get("/folder/x/y/b")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;
    assert_eq!(moved.status(), Status::Ok);

    let old = client
        .get("/folder/a/b")
        .private_cookie(cookie)
        .dispatch()
        .await;
    assert_eq!(old.status(), Status::NotFound);
}
