use std::{
    io,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocket::async_test;
use tempfile::tempdir;

use crate::{config::DbConfig, session::user_context::UserContext};

// A context whose files live in `dir`, limited to one blocking thread,
// that gives up waiting for a turn after a second.
fn one_thread_context(dir: &std::path::Path) -> UserContext {
    let pool = Pool::builder()
        .max_size(1)
        .build_unchecked(SqliteConnectionManager::memory());

    UserContext::new(
        pool,
        dir.to_path_buf(),
        &DbConfig {
            max_connections: NonZeroU32::new(1).unwrap(),
            connection_timeout_seconds: NonZeroU64::new(1).unwrap(),
            ..DbConfig::default()
        },
        NonZeroUsize::new(1),
    )
}

fn is_busy(result: io::Result<impl Sized>) -> bool {
    result.is_err_and(|e| e.to_string().contains("Timed out waiting"))
}

// File access counts against the user's limits like database work does: with
// the user's only blocking thread taken, every file operation waits for it.
#[async_test]
async fn test_file_operations_wait_for_the_users_turn() {
    let dir = tempdir().unwrap();
    let context = one_thread_context(dir.path());
    let file = context.create_upload("a").await.unwrap();

    file.write_at(vec![1, 2, 3], 0).await.unwrap();
    context.commit_upload("a").await.unwrap();

    let taken = context.reserve_blocking().await.unwrap();

    assert!(is_busy(context.create_upload("b").await));
    assert!(is_busy(context.open_blob("a").await));
    assert!(is_busy(file.write_at(vec![4], 3).await));
    assert!(is_busy(file.sync().await));
    assert!(is_busy(context.sync_blob_dir("a").await));
    assert!(is_busy(context.remove_blob("a").await));
    assert!(context.list_stored_files().await.is_err());

    drop(taken);

    let (read, len) = context
        .open_blob("a")
        .await
        .unwrap()
        .read_at(vec![0; 8], 0)
        .await
        .unwrap();

    assert_eq!(&read[..len], [1, 2, 3]);
}

// Removing a file also removes the shard directories it leaves empty, but
// never the user's own directory or a shard still in use.
#[async_test]
async fn test_removing_a_file_prunes_only_empty_shard_directories() {
    let dir = tempdir().unwrap();
    let context = one_thread_context(dir.path());

    for name in ["abcd-1", "abcd-2"] {
        context.create_upload(name).await.unwrap();
        context.commit_upload(name).await.unwrap();
    }

    let shard = context.blob_path("abcd-1").parent().unwrap().to_path_buf();

    context.remove_blob("abcd-1").await.unwrap();

    assert!(shard.is_dir(), "the shard still holds abcd-2");

    context.remove_blob("abcd-2").await.unwrap();

    assert!(!shard.exists());
    assert!(!dir.path().join("ab").exists());
    assert!(dir.path().is_dir());
}
