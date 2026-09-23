use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocket::{
    async_test,
    tokio::{self, runtime::Builder, sync::Mutex, time::timeout},
};
use secrecy::SecretString;
use uuid::Uuid;

use crate::session::{store::SessionStore, user_session::UserSession};

// A session that never touches the disk: the pool is built without
// establishing a connection.
fn detached_session(username: &str) -> Arc<UserSession> {
    let pool = Pool::builder()
        .max_size(1)
        .build_unchecked(SqliteConnectionManager::memory());
    let session_id = Uuid::new_v4().to_string();

    Arc::new(UserSession {
        user_path: PathBuf::new(),
        db_pool: pool,
        username: username.to_string(),
        created_at: SystemTime::now(),
        session_id: session_id.clone(),
        user_token: SecretString::from(format!("token-{session_id}")),
        active_uploads: Mutex::new(HashMap::new()),
    })
}

#[async_test]
async fn test_insert_then_lookup_by_token_and_id() {
    let store = SessionStore::default();
    let session = detached_session("alice");

    store.insert("tok-a".into(), session.clone()).await;

    assert!(Arc::ptr_eq(&store.get("tok-a").await.unwrap(), &session));
    assert!(Arc::ptr_eq(
        &store.get_by_id(&session.session_id).await.unwrap(),
        &session
    ));
    assert!(store.get("nope").await.is_none());
    assert!(store.get_by_id("nope").await.is_none());
}

#[async_test]
async fn test_remove_by_token_clears_both_lookups() {
    let store = SessionStore::default();
    let session = detached_session("alice");
    store.insert("tok-a".into(), session.clone()).await;

    let removed = store.remove_by_token("tok-a").await.unwrap();

    assert!(Arc::ptr_eq(&removed, &session));
    assert!(store.get("tok-a").await.is_none());
    assert!(store.get_by_id(&session.session_id).await.is_none());
    assert!(store.remove_by_token("tok-a").await.is_none());
}

#[async_test]
async fn test_remove_by_id_clears_both_lookups() {
    let store = SessionStore::default();
    let session = detached_session("alice");
    store.insert("tok-a".into(), session.clone()).await;

    let removed = store.remove_by_id(&session.session_id).await.unwrap();

    assert!(Arc::ptr_eq(&removed, &session));
    assert!(store.get("tok-a").await.is_none());
    assert!(store.get_by_id(&session.session_id).await.is_none());
    assert!(store.remove_by_id(&session.session_id).await.is_none());
}

#[async_test]
async fn test_reinserting_a_token_replaces_the_old_session_completely() {
    let store = SessionStore::default();
    let old = detached_session("alice");
    let new = detached_session("alice");
    store.insert("tok-a".into(), old.clone()).await;

    store.insert("tok-a".into(), new.clone()).await;

    assert!(Arc::ptr_eq(&store.get("tok-a").await.unwrap(), &new));
    assert!(store.get_by_id(&old.session_id).await.is_none());
    assert!(store.remove_by_id(&old.session_id).await.is_none());
    assert_eq!(store.snapshot().await.len(), 1);
}

#[async_test]
async fn test_reinserting_a_session_under_a_new_token_drops_the_old_token() {
    let store = SessionStore::default();
    let session = detached_session("alice");
    store.insert("tok-old".into(), session.clone()).await;

    store.insert("tok-new".into(), session.clone()).await;

    assert!(store.get("tok-old").await.is_none());
    assert!(Arc::ptr_eq(&store.get("tok-new").await.unwrap(), &session));
    assert_eq!(store.snapshot().await.len(), 1);
}

#[async_test]
async fn test_snapshot_and_pool_for_user() {
    let store = SessionStore::default();
    store
        .insert("tok-a".into(), detached_session("alice"))
        .await;
    store.insert("tok-b".into(), detached_session("bob")).await;

    let mut names: Vec<_> = store
        .snapshot()
        .await
        .iter()
        .map(|s| s.username.clone())
        .collect();
    names.sort();

    assert_eq!(names, ["alice", "bob"]);
    assert!(store.pool_for_user("alice").await.is_some());
    assert!(store.pool_for_user("carol").await.is_none());
}

// H1 regression: concurrent readers must keep making progress while other
// tasks insert and remove sessions. Under the old two-map layout the
// equivalent workload deadlocked permanently. This needs real parallelism, so
// it builds its own 8-worker runtime instead of using `async_test`.
#[test]
fn test_concurrent_reads_and_removals_do_not_deadlock() {
    let runtime = Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let store = Arc::new(SessionStore::default());
        store
            .insert("stable".into(), detached_session("reader"))
            .await;

        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();

                tokio::spawn(async move {
                    for _ in 0..50_000 {
                        assert!(store.get("stable").await.is_some());
                    }
                })
            })
            .collect();

        let churn = {
            let store = store.clone();
            let stop = stop.clone();

            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let session = detached_session("churn");
                    let id = session.session_id.clone();

                    store.insert("churn-a".into(), session.clone()).await;
                    store.remove_by_token("churn-a").await;
                    store.insert("churn-b".into(), session).await;
                    store.remove_by_id(&id).await;
                    store.snapshot().await;
                    tokio::task::yield_now().await;
                }
            })
        };

        let all_readers = async {
            for reader in readers {
                reader.await.unwrap();
            }
        };

        timeout(Duration::from_secs(30), all_readers)
            .await
            .expect("session store deadlocked");

        stop.store(true, Ordering::Relaxed);

        timeout(Duration::from_secs(30), churn)
            .await
            .expect("churn task deadlocked")
            .unwrap();
    });
}
