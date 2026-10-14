use std::{
    collections::BTreeMap,
    io::Read,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

use rusqlite::params;
use tokio::time::sleep;

use super::*;
use crate::db::sqlite;

/// What an archive entry unpacked to: a directory, or a file's bytes.
#[derive(Debug, PartialEq)]
enum Unpacked {
    Dir,
    File(Vec<u8>),
}

async fn download_client(
    configure: impl FnOnce(&mut AppConfig),
) -> (TestClient, Cookie<'static>, TestUser) {
    let (app, test_user) = setup_app_with_config(configure).await;
    let client = TestClient::new(app);
    let (_, cookie) = create_test_session(client.app(), test_user.name.clone()).await;

    (client, cookie, test_user)
}

// Percent-encodes everything but unreserved characters and `/`, so any name
// can go in a request URI.
fn encode(path: &str) -> String {
    path.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

async fn put(client: &TestClient, cookie: &Cookie<'static>, path: &str, body: &[u8]) {
    let response = client
        .put(format!("/file/{}", encode(path)))
        .private_cookie(cookie.clone())
        .body(body)
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED, "{path}");
}

async fn download(client: &TestClient, cookie: &Cookie<'static>, path: &str) -> TestResponse {
    client
        .get(format!("/folder/{}?download", encode(path)))
        .private_cookie(cookie.clone())
        .dispatch()
        .await
}

fn content_length(response: &TestResponse) -> usize {
    response
        .headers()
        .get_one("Content-Length")
        .expect("no Content-Length")
        .parse()
        .unwrap()
}

/// Reads a complete download, checking that it is exactly as long as its
/// `Content-Length` said.
async fn read_archive(response: TestResponse) -> Vec<u8> {
    assert_eq!(response.status(), StatusCode::OK);

    let expected_len = content_length(&response);
    let body = response.into_bytes().await.unwrap();

    assert_eq!(body.len(), expected_len);

    body
}

// Unpacks an archive with an independent TAR reader. Paths are keyed without
// a directory's trailing `/`.
fn unpack(archive: &[u8]) -> BTreeMap<String, Unpacked> {
    let mut entries = BTreeMap::new();

    for entry in ::tar::Archive::new(archive).entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry
            .path()
            .unwrap()
            .to_string_lossy()
            .trim_end_matches('/')
            .to_string();
        let unpacked = if entry.header().entry_type().is_dir() {
            Unpacked::Dir
        } else {
            let mut data = Vec::new();

            entry.read_to_end(&mut data).unwrap();

            Unpacked::File(data)
        };

        entries.insert(path, unpacked);
    }

    entries
}

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_folder_tree() {
    let (client, cookie, _user) = download_client(|_| {}).await;
    let big = patterned(200_000);

    put(&client, &cookie, "docs/a.txt", b"hello").await;
    put(&client, &cookie, "docs/sub/big.bin", &big).await;
    put(&client, &cookie, "docs/sub/empty.txt", b"").await;
    put(&client, &cookie, "other/outside.txt", b"not included").await;

    let response = client
        .put("/folder/docs/empty_dir")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let response = download(&client, &cookie, "docs").await;

    assert_eq!(response.content_type(), Some("application/x-tar"));
    assert_eq!(
        response.headers().get_one("Content-Disposition"),
        Some("attachment; filename=\"docs.tar\"; filename*=UTF-8''docs.tar")
    );

    let entries = unpack(&read_archive(response).await);
    let expected = BTreeMap::from([
        ("docs".to_string(), Unpacked::Dir),
        ("docs/empty_dir".to_string(), Unpacked::Dir),
        ("docs/sub".to_string(), Unpacked::Dir),
        ("docs/a.txt".to_string(), Unpacked::File(b"hello".to_vec())),
        ("docs/sub/big.bin".to_string(), Unpacked::File(big)),
        ("docs/sub/empty.txt".to_string(), Unpacked::File(Vec::new())),
    ]);

    assert_eq!(entries, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_long_and_unicode_names() {
    let (client, cookie, _user) = download_client(|_| {}).await;
    let long_dir = "d".repeat(200);
    let long_path = format!("names/{long_dir}/{}.txt", "f".repeat(150));
    let unicode_path = "names/ünï cödé \"quoted\".txt";

    put(&client, &cookie, &long_path, b"long").await;
    put(&client, &cookie, unicode_path, b"unicode").await;

    let entries = unpack(&read_archive(download(&client, &cookie, "names").await).await);

    assert_eq!(entries[&long_path], Unpacked::File(b"long".to_vec()));
    assert_eq!(entries[unicode_path], Unpacked::File(b"unicode".to_vec()));
    assert_eq!(entries[&format!("names/{long_dir}")], Unpacked::Dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_names_the_file_after_a_unicode_folder() {
    let (client, cookie, _user) = download_client(|_| {}).await;

    put(&client, &cookie, "fötö \"x\"/a.txt", b"a").await;

    let response = download(&client, &cookie, "fötö \"x\"").await;

    assert_eq!(
        response.headers().get_one("Content-Disposition"),
        Some(
            "attachment; filename=\"f_t_ _x_.tar\"; filename*=UTF-8''f%C3%B6t%C3%B6%20%22x%22.tar"
        )
    );

    let entries = unpack(&read_archive(response).await);

    assert_eq!(entries["fötö \"x\"/a.txt"], Unpacked::File(b"a".to_vec()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_root_folder_is_named_after_the_user() {
    let (client, cookie, user) = download_client(|_| {}).await;

    put(&client, &cookie, "top.txt", b"top").await;
    put(&client, &cookie, "dir/inner.txt", b"inner").await;

    let response = download(&client, &cookie, "").await;
    let name = &user.name;

    assert!(response
        .headers()
        .get_one("Content-Disposition")
        .unwrap()
        .contains(&format!("filename=\"{name}.tar\"")));

    let entries = unpack(&read_archive(response).await);
    let expected = BTreeMap::from([
        (name.clone(), Unpacked::Dir),
        (format!("{name}/dir"), Unpacked::Dir),
        (format!("{name}/top.txt"), Unpacked::File(b"top".to_vec())),
        (
            format!("{name}/dir/inner.txt"),
            Unpacked::File(b"inner".to_vec()),
        ),
    ]);

    assert_eq!(entries, expected);
}

// Entries whose names the API would refuse could point outside the directory
// the archive is extracted to. They are left out, and the archive is still
// exactly as long as its Content-Length says.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_leaves_out_entries_with_invalid_names() {
    let (client, cookie, _user) = download_client(|_| {}).await;

    put(&client, &cookie, "mixed/good.txt", b"good").await;

    let state = client.app();
    let session = state.sessions.snapshot().await.pop().unwrap();
    let db = session.context.pool().get().unwrap();
    let mixed_id = sqlite::get_folder_id(&db, "mixed").unwrap().unwrap();

    // No blobs exist for these rows: if one were not left out, reading it
    // would fail and the body would come up short.
    db.execute(
        "INSERT INTO files (parent_folder_id, name, encoded_name, key) VALUES (?1, ?2, 'bad-blob', zeroblob(32))",
        params![mixed_id, "bad\u{1}name.txt"],
    )
    .unwrap();
    db.execute(
        "INSERT INTO folders (parent_folder_id, name) VALUES (?1, '..')",
        params![mixed_id],
    )
    .unwrap();

    let parent_id = db.last_insert_rowid();

    db.execute(
        "INSERT INTO files (parent_folder_id, name, encoded_name, key) VALUES (?1, 'escaped.txt', 'escaped-blob', zeroblob(32))",
        params![parent_id],
    )
    .unwrap();
    drop(db);

    let entries = unpack(&read_archive(download(&client, &cookie, "mixed").await).await);
    let expected = BTreeMap::from([
        ("mixed".to_string(), Unpacked::Dir),
        (
            "mixed/good.txt".to_string(),
            Unpacked::File(b"good".to_vec()),
        ),
    ]);

    assert_eq!(entries, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_get_folder_without_download_still_lists_it() {
    let (client, cookie, _user) = download_client(|_| {}).await;

    put(&client, &cookie, "listed/a.txt", b"a").await;

    let response = client
        .get("/folder/listed")
        .private_cookie(cookie.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.content_type(), Some("application/json"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_missing_folder_is_not_found() {
    let (client, cookie, _user) = download_client(|_| {}).await;

    let response = download(&client, &cookie, "missing").await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_without_a_session_is_unauthorized() {
    let (client, _cookie, _user) = download_client(|_| {}).await;

    let response = client.get("/folder/?download").dispatch().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// Folder downloads are unlimited unless a limit is configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_downloads_are_unlimited_by_default() {
    let (client, cookie, _user) = download_client(|_| {}).await;

    put(&client, &cookie, "many/big.bin", &patterned(1024 * 1024)).await;

    // None of these bodies is read, so all five downloads are still running
    // at once.
    let mut running = Vec::new();

    for _ in 0..5 {
        let response = download(&client, &cookie, "many").await;

        assert_eq!(response.status(), StatusCode::OK);

        running.push(response);
    }

    for response in running {
        let entries = unpack(&read_archive(response).await);

        assert_eq!(
            entries["many/big.bin"],
            Unpacked::File(patterned(1024 * 1024))
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_beyond_the_limit_is_rejected() {
    let (client, cookie, _user) =
        download_client(|config| config.max_active_downloads = NonZeroUsize::new(1)).await;

    put(&client, &cookie, "busy/big.bin", &patterned(1024 * 1024)).await;

    // The first download's body isn't read yet, so it is still running and
    // holds the only permit.
    let first = download(&client, &cookie, "busy").await;

    assert_eq!(first.status(), StatusCode::OK);

    let second = download(&client, &cookie, "busy").await;

    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    let entries = unpack(&read_archive(first).await);

    assert_eq!(
        entries["busy/big.bin"],
        Unpacked::File(patterned(1024 * 1024))
    );
}

// A user's folder downloads may use half of their connections. One more waits
// for a slot, up to the connection timeout, and then is turned away.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_beyond_the_users_share_waits_then_is_rejected() {
    let (client, cookie, _user) = download_client(|config| {
        config.db.max_connections = NonZeroU32::new(2).unwrap();
        config.db.connection_timeout_seconds = NonZeroU64::new(1).unwrap();
    })
    .await;

    put(&client, &cookie, "share/big.bin", &patterned(1024 * 1024)).await;

    // Not read, so it keeps running and holds the user's only download slot.
    let running = download(&client, &cookie, "share").await;

    assert_eq!(running.status(), StatusCode::OK);

    let started = Instant::now();
    let waiting = download(&client, &cookie, "share").await;

    assert_eq!(waiting.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_is_abandoned_when_the_client_stops_reading() {
    let (client, cookie, _user) = download_client(|config| {
        config.max_active_downloads = NonZeroUsize::new(1);
        config.download_stall_timeout_seconds = NonZeroU64::new(1).unwrap();
    })
    .await;

    put(&client, &cookie, "stalled/big.bin", &patterned(1024 * 1024)).await;

    // Nothing reads this body, so once the channel is full the download waits
    // for the client, gives up after a second, and frees the only permit.
    let stalled = download(&client, &cookie, "stalled").await;

    assert_eq!(stalled.status(), StatusCode::OK);

    let mut status = StatusCode::TOO_MANY_REQUESTS;

    for _ in 0..50 {
        status = download(&client, &cookie, "stalled").await.status();

        if status != StatusCode::TOO_MANY_REQUESTS {
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(status, StatusCode::OK);

    // What the abandoned download had already queued still arrives, but the
    // body falls short of its Content-Length, so the client sees a failure.
    let expected_len = content_length(&stalled);
    let body = stalled.into_bytes().await.unwrap();

    assert!(
        body.len() < expected_len,
        "{} >= {}",
        body.len(),
        expected_len
    );
}

// The folder pass and the file pass each read the database; one read
// transaction makes both see the database as it was when the download
// started.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_is_a_snapshot_of_when_it_started() {
    let (client, cookie, _user) = download_client(|_| {}).await;

    put(&client, &cookie, "snap/a.txt", b"a").await;

    // Enough subfolders with long names (each needs a PAX header, 1.5 KiB in
    // all) that their entries alone overflow the ~192 KiB the producer can
    // buffer. Until the body is read, the producer is stuck in the folder
    // pass, and the file pass hasn't begun.
    let state = client.app();
    let session = state.sessions.snapshot().await.pop().unwrap();
    let mut db = session.context.pool().get().unwrap();
    let snap_id = sqlite::get_folder_id(&db, "snap").unwrap().unwrap();
    let inserts = db.transaction().unwrap();
    let mut expected = BTreeMap::from([
        ("snap".to_string(), Unpacked::Dir),
        ("snap/a.txt".to_string(), Unpacked::File(b"a".to_vec())),
    ]);

    for i in 0..200 {
        let name = format!("{i:0>150}");

        inserts
            .execute(
                "INSERT INTO folders (parent_folder_id, name) VALUES (?1, ?2)",
                params![snap_id, name],
            )
            .unwrap();
        expected.insert(format!("snap/{name}"), Unpacked::Dir);
    }

    inserts.commit().unwrap();
    drop(db);

    let response = download(&client, &cookie, "snap").await;

    // Added after the length was worked out but before the file pass reads
    // the files table: without the snapshot it would end up in the archive,
    // which would no longer match its Content-Length.
    put(&client, &cookie, "snap/later.txt", b"later").await;

    assert_eq!(unpack(&read_archive(response).await), expected);
}

// A client that goes away mid-download frees its permit right away, without
// waiting for the stall timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_dropping_a_download_frees_its_permit() {
    let (client, cookie, _user) = download_client(|config| {
        config.max_active_downloads = NonZeroUsize::new(1);
    })
    .await;

    put(&client, &cookie, "dropped/big.bin", &patterned(1024 * 1024)).await;

    let first = download(&client, &cookie, "dropped").await;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        download(&client, &cookie, "dropped").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    drop(first);

    // The producer notices the next time it sends, which wakes it at once;
    // the stall timeout (60s here) never comes into it.
    let mut status = StatusCode::TOO_MANY_REQUESTS;

    for _ in 0..50 {
        status = download(&client, &cookie, "dropped").await.status();

        if status != StatusCode::TOO_MANY_REQUESTS {
            break;
        }

        sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_download_with_a_missing_blob_ends_short() {
    let (client, cookie, _user) = download_client(|_| {}).await;

    put(&client, &cookie, "gone/a.txt", b"still here").await;
    put(&client, &cookie, "gone/b.txt", b"blob deleted").await;

    let state = client.app();
    let session = state.sessions.snapshot().await.pop().unwrap();
    let encoded_name = session
        .context
        .get_encoded_file_name("gone/b.txt".into())
        .await
        .unwrap();
    let blob = session.context.blob_path(&encoded_name);

    fs::remove_file(blob).unwrap();

    let response = download(&client, &cookie, "gone").await;

    assert_eq!(response.status(), StatusCode::OK);

    let expected_len = content_length(&response);
    let body = response.into_bytes().await.unwrap();

    assert!(
        body.len() < expected_len,
        "{} >= {}",
        body.len(),
        expected_len
    );
}
