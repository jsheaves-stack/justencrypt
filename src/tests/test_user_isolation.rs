// Database work runs on the server's blocking threads, which every user
// shares (Rocket's test runtime has 32). Requests waiting for one user's
// database connections must not hold any, or one user flooding the server
// would leave every other user's requests waiting behind theirs.

use std::{
    env,
    io::Cursor,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};

use rocket::{
    async_test,
    futures::future::join_all,
    http::{ContentType, Cookie, Status},
    local::asynchronous::{Client, LocalResponse},
    routes,
    tokio::{
        self,
        time::{sleep, timeout},
    },
};
use uuid::Uuid;

use super::*;
use crate::routes::{
    file::put_file,
    folder::{download_folder, get_folder},
    session::{create_session, destroy_session},
    thumbnail::get_thumbnail,
};

/// More requests than the test runtime has blocking threads.
const FLOOD: usize = 40;

/// A client with two users, A and B, whose pools hold `max_connections`
/// connections each. Each has a 1 MiB file in `big/` and an image `pic.png`.
async fn two_users(
    max_connections: u32,
    configure: impl FnOnce(&mut AppConfig),
) -> (Client, Cookie<'static>, Cookie<'static>, TestUser, TestUser) {
    let (rocket, user_a) = setup_rocket_with_config(|config| {
        config.db.max_connections = NonZeroU32::new(max_connections).unwrap();
        configure(config);
    })
    .await;
    let rocket = rocket
        .mount("/file", routes![put_file])
        .mount("/folder", routes![get_folder, download_folder])
        .mount("/thumbnail", routes![get_thumbnail]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let (_, cookie_a) = create_test_session(client.rocket(), user_a.name.clone()).await;

    let name_b = Uuid::new_v4().to_string();
    let user_b = TestUser {
        path: env::temp_dir().join(&name_b),
        name: name_b,
    };
    let (_, cookie_b) = create_test_session(client.rocket(), user_b.name.clone()).await;

    let mut image = Vec::new();

    image::DynamicImage::new_rgb8(40, 30)
        .write_to(&mut Cursor::new(&mut image), image::ImageFormat::Png)
        .unwrap();

    for cookie in [&cookie_a, &cookie_b] {
        for (path, body) in [
            ("big/big.bin", vec![7u8; 1024 * 1024]),
            ("pic.png", image.clone()),
        ] {
            let response = client
                .put(format!("/file/{path}"))
                .private_cookie(cookie.clone())
                .body(body)
                .dispatch()
                .await;

            assert_eq!(response.status(), Status::Created);
        }
    }

    (client, cookie_a, cookie_b, user_a, user_b)
}

async fn download_big<'c>(client: &'c Client, cookie: &Cookie<'static>) -> LocalResponse<'c> {
    client
        .get("/folder/big?download")
        .private_cookie(cookie.clone())
        .dispatch()
        .await
}

/// Runs `flood` while user B lists their root folder, which must answer
/// promptly: before the flood is over, and within a few seconds.
async fn assert_b_is_unaffected(
    client: &Client,
    cookie_b: &Cookie<'static>,
    flood: impl std::future::Future,
) {
    let b_lists_a_folder = async {
        // Gives the flood time to take hold first.
        sleep(Duration::from_millis(500)).await;

        timeout(
            Duration::from_secs(5),
            client
                .get("/folder/")
                .private_cookie(cookie_b.clone())
                .dispatch(),
        )
        .await
        .expect("user B's request waited behind user A's")
        .status()
    };

    let status = tokio::select! {
        _ = flood => panic!("user A's requests finished before user B's was tested"),
        status = b_lists_a_folder => status,
    };

    assert_eq!(status, Status::Ok);
}

// A's only connection is held by a running download, so each of A's folder
// listings has to wait for it.
#[async_test]
async fn test_requests_waiting_for_a_connection_do_not_starve_other_users() {
    let (client, cookie_a, cookie_b, _user_a, _user_b) = two_users(1, |_| {}).await;

    // Not read, so it keeps running and holds the connection.
    let download = download_big(&client, &cookie_a).await;

    assert_eq!(download.status(), Status::Ok);

    let listings = join_all((0..FLOOD).map(|_| {
        client
            .get("/folder/big")
            .private_cookie(cookie_a.clone())
            .dispatch()
    }));

    assert_b_is_unaffected(&client, &cookie_b, listings).await;
}

// Each folder download holds a connection for as long as it runs, and none of
// these are read, so they keep running.
#[async_test]
async fn test_many_folder_downloads_do_not_starve_other_users() {
    let (client, cookie_a, cookie_b, _user_a, _user_b) = two_users(2, |_| {}).await;

    let downloads = join_all((0..FLOOD).map(|_| download_big(&client, &cookie_a)));

    assert_b_is_unaffected(&client, &cookie_b, downloads).await;
}

// Folder downloads may only take half of a user's connections, so the rest
// stay free for the user's other requests.
#[async_test]
async fn test_folder_downloads_leave_connections_for_the_users_other_requests() {
    let (client, cookie_a, _cookie_b, _user_a, _user_b) = two_users(2, |_| {}).await;

    // One of these takes the only download slot (and a connection); the rest
    // wait for the slot rather than taking the other connection.
    let downloads = join_all((0..3).map(|_| download_big(&client, &cookie_a)));

    let a_lists_a_folder = async {
        sleep(Duration::from_millis(500)).await;

        timeout(
            Duration::from_secs(5),
            client
                .get("/folder/big")
                .private_cookie(cookie_a.clone())
                .dispatch(),
        )
        .await
        .expect("the listing waited behind the user's downloads")
        .status()
    };

    let status = tokio::select! {
        _ = downloads => panic!("the downloads finished before the listing was tested"),
        status = a_lists_a_folder => status,
    };

    assert_eq!(status, Status::Ok);
}

// A download waiting for one of its own user's slots must not hold one of the
// server-wide permits meanwhile, or other users would be turned away.
#[async_test]
async fn test_a_download_waiting_on_its_user_leaves_server_permits_to_others() {
    let (client, cookie_a, cookie_b, _user_a, _user_b) = two_users(2, |config| {
        config.max_active_downloads = NonZeroUsize::new(2);
        config.db.connection_timeout_seconds = NonZeroU64::new(2).unwrap();
    })
    .await;

    // Holds A's only download slot and one of the two server-wide permits.
    let running = download_big(&client, &cookie_a).await;

    assert_eq!(running.status(), Status::Ok);

    // A's second download waits for A's slot; B starts one meanwhile.
    let (waiting, other_user) = tokio::join!(download_big(&client, &cookie_a), async {
        sleep(Duration::from_millis(500)).await;

        download_big(&client, &cookie_b).await
    });

    assert_eq!(other_user.status(), Status::Ok);
    assert_eq!(waiting.status(), Status::TooManyRequests);
}

// Logging out and back in must not give a user a fresh set of permits while
// work from before, here a download still running, holds the old ones.
#[async_test]
async fn test_logging_in_again_keeps_the_users_limits() {
    let (rocket, user) = setup_rocket_with_config(|config| {
        config.db.max_connections = NonZeroU32::new(2).unwrap();
        config.db.connection_timeout_seconds = NonZeroU64::new(1).unwrap();
    })
    .await;
    let rocket = rocket
        .mount("/file", routes![put_file])
        .mount("/folder", routes![download_folder])
        .mount("/session", routes![create_session, destroy_session]);
    let client = Client::tracked(rocket)
        .await
        .expect("Failed to create client");
    let password = SecretString::from_str("test_password").unwrap();
    let state = client.rocket().state::<AppState>().unwrap();

    create_account_storage(&user.name, &password, &state.config)
        .await
        .unwrap();

    // The tracked client keeps the session cookie each login sets.
    let log_in = || async {
        client
            .post("/session")
            .header(ContentType::JSON)
            .body(format!(
                r#"{{"username": "{}", "password": "test_password"}}"#,
                user.name
            ))
            .dispatch()
            .await
            .status()
    };

    assert_eq!(log_in().await, Status::Created);

    let response = client
        .put("/file/big/big.bin")
        .body(vec![7u8; 1024 * 1024])
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Created);

    // Not read, so it keeps running and holds the user's only download slot
    // after the session that started it is gone.
    let running = client.get("/folder/big?download").dispatch().await;

    assert_eq!(running.status(), Status::Ok);
    assert_eq!(
        client.delete("/session").dispatch().await.status(),
        Status::NoContent
    );
    assert_eq!(log_in().await, Status::Created);

    let second = client.get("/folder/big?download").dispatch().await;

    assert_eq!(second.status(), Status::TooManyRequests);
}

// A thumbnail waiting on its own user must not hold the server-wide
// thumbnail permit meanwhile (the tests' server allows one at a time), or
// other users' thumbnails would wait behind it.
#[async_test]
async fn test_a_thumbnail_waiting_on_its_user_leaves_server_permits_to_others() {
    let (client, cookie_a, cookie_b, _user_a, _user_b) = two_users(1, |config| {
        config.db.connection_timeout_seconds = NonZeroU64::new(3).unwrap();
    })
    .await;

    // Not read, so it keeps running and holds A's only connection.
    let running = download_big(&client, &cookie_a).await;

    assert_eq!(running.status(), Status::Ok);

    // A's thumbnail waits up to 3s for that connection; B asks for one
    // meanwhile.
    let (_waiting, other_user) = tokio::join!(
        client
            .get("/thumbnail/pic.png")
            .private_cookie(cookie_a.clone())
            .dispatch(),
        async {
            sleep(Duration::from_millis(500)).await;

            timeout(
                Duration::from_secs(1),
                client
                    .get("/thumbnail/pic.png")
                    .private_cookie(cookie_b.clone())
                    .dispatch(),
            )
            .await
            .expect("user B's thumbnail waited behind user A's")
            .status()
        }
    );

    assert_eq!(other_user, Status::Ok);
}

// A request kept waiting by the user's own work in progress is told to try
// again later (429), not that the server failed (500).
#[async_test]
async fn test_a_request_waiting_too_long_on_its_own_user_gets_429() {
    let (client, cookie_a, _cookie_b, _user_a, _user_b) = two_users(1, |config| {
        config.db.connection_timeout_seconds = NonZeroU64::new(1).unwrap();
    })
    .await;

    // Not read, so it keeps running and holds A's only connection.
    let running = download_big(&client, &cookie_a).await;

    assert_eq!(running.status(), Status::Ok);

    let response = client
        .get("/folder/big")
        .private_cookie(cookie_a.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::TooManyRequests);
}
