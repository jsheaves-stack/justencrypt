use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, UNIX_EPOCH},
};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use secrecy::ExposeSecret;
use tokio::{runtime::Builder, sync::Mutex, time::timeout};
use uuid::Uuid;

use crate::{
    config::DbConfig,
    session::{
        policy::SessionPolicy,
        reaper::{reap_once, SessionReaper},
        store::{token_digest, SessionStore},
        user_session::{new_session_token, UserSession},
    },
    storage::user_context::UserContext,
    util::time::unix_now_secs,
};

// A session that never touches the disk: the pool is built without
// establishing a connection.
fn detached_session(username: &str) -> Arc<UserSession> {
    aged_session(username, 0, 0)
}

// A detached session created `age_secs` ago whose last request was
// `idle_secs` ago.
fn aged_session(username: &str, age_secs: u64, idle_secs: u64) -> Arc<UserSession> {
    let pool = Pool::builder()
        .max_size(1)
        .build_unchecked(SqliteConnectionManager::memory());
    let session_id = Uuid::new_v4().to_string();
    let now = unix_now_secs();

    Arc::new(UserSession {
        context: UserContext::new(pool, PathBuf::new(), &DbConfig::default(), None),
        username: username.to_string(),
        created_at: UNIX_EPOCH + Duration::from_secs(now - age_secs),
        session_id: session_id.clone(),
        active_uploads: Mutex::new(HashMap::new()),
        last_seen: AtomicU64::new(now - idle_secs),
    })
}

fn policy(idle_secs: u64, lifetime_secs: u64, max_per_user: usize) -> SessionPolicy {
    SessionPolicy {
        idle_timeout: Duration::from_secs(idle_secs),
        max_lifetime: Duration::from_secs(lifetime_secs),
        max_per_user,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_insert_then_lookup_by_token_and_id() {
    let store = SessionStore::default();
    let session = detached_session("alice");

    store.insert("tok-a", session.clone()).await;

    assert!(Arc::ptr_eq(&store.get("tok-a").await.unwrap(), &session));
    assert!(Arc::ptr_eq(
        &store.get_by_id(&session.session_id).await.unwrap(),
        &session
    ));
    assert!(store.get("nope").await.is_none());
    assert!(store.get_by_id("nope").await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_remove_by_token_clears_both_lookups() {
    let store = SessionStore::default();
    let session = detached_session("alice");
    store.insert("tok-a", session.clone()).await;

    let removed = store.remove_by_token("tok-a").await.unwrap();

    assert!(Arc::ptr_eq(&removed, &session));
    assert!(store.get("tok-a").await.is_none());
    assert!(store.get_by_id(&session.session_id).await.is_none());
    assert!(store.remove_by_token("tok-a").await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_remove_by_id_clears_both_lookups() {
    let store = SessionStore::default();
    let session = detached_session("alice");
    store.insert("tok-a", session.clone()).await;

    let removed = store.remove_by_id(&session.session_id).await.unwrap();

    assert!(Arc::ptr_eq(&removed, &session));
    assert!(store.get("tok-a").await.is_none());
    assert!(store.get_by_id(&session.session_id).await.is_none());
    assert!(store.remove_by_id(&session.session_id).await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reinserting_a_token_replaces_the_old_session_completely() {
    let store = SessionStore::default();
    let old = detached_session("alice");
    let new = detached_session("alice");
    store.insert("tok-a", old.clone()).await;

    store.insert("tok-a", new.clone()).await;

    assert!(Arc::ptr_eq(&store.get("tok-a").await.unwrap(), &new));
    assert!(store.get_by_id(&old.session_id).await.is_none());
    assert!(store.remove_by_id(&old.session_id).await.is_none());
    assert_eq!(store.snapshot().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reinserting_a_session_under_a_new_token_drops_the_old_token() {
    let store = SessionStore::default();
    let session = detached_session("alice");
    store.insert("tok-old", session.clone()).await;

    store.insert("tok-new", session.clone()).await;

    assert!(store.get("tok-old").await.is_none());
    assert!(Arc::ptr_eq(&store.get("tok-new").await.unwrap(), &session));
    assert_eq!(store.snapshot().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_snapshot_and_context_for_user() {
    let store = SessionStore::default();
    store.insert("tok-a", detached_session("alice")).await;
    store.insert("tok-b", detached_session("bob")).await;

    let mut names: Vec<_> = store
        .snapshot()
        .await
        .iter()
        .map(|s| s.username.clone())
        .collect();
    names.sort();

    assert_eq!(names, ["alice", "bob"]);
    assert!(store.context_for_user("alice").await.is_some());
    assert!(store.context_for_user("carol").await.is_none());
}

// H1 regression: concurrent readers must keep making progress while other
// tasks insert and remove sessions. Under the old two-map layout the
// equivalent workload deadlocked permanently. This needs real parallelism, so
// it builds its own 8-worker runtime instead of using the single-worker test
// runtime.
#[test]
fn test_concurrent_reads_and_removals_do_not_deadlock() {
    let runtime = Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let store = Arc::new(SessionStore::default());
        store.insert("stable", detached_session("reader")).await;

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

                    store.insert("churn-a", session.clone()).await;
                    store.remove_by_token("churn-a").await;
                    store.insert("churn-b", session).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_insert_over_the_per_user_limit_evicts_the_oldest_sessions() {
    let store = SessionStore::new(policy(3600, 86400, 2));
    let oldest = aged_session("alice", 300, 0);
    let middle = aged_session("alice", 200, 0);
    let newest = aged_session("alice", 100, 0);
    let bob = aged_session("bob", 400, 0);

    assert!(store.insert("bob", bob.clone()).await.is_empty());
    assert!(store.insert("a1", oldest.clone()).await.is_empty());
    assert!(store.insert("a2", middle.clone()).await.is_empty());

    let evicted = store.insert("a3", newest.clone()).await;

    assert_eq!(evicted.len(), 1);
    assert!(Arc::ptr_eq(&evicted[0], &oldest));
    assert!(store.get("a1").await.is_none());
    assert!(store.get_by_id(&oldest.session_id).await.is_none());
    assert!(store.get("a2").await.is_some());
    assert!(store.get("a3").await.is_some());
    // Other users' sessions don't count toward alice's limit.
    assert!(store.get("bob").await.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_remove_expired_removes_idle_and_too_old_sessions_only() {
    let store = SessionStore::new(policy(60, 3600, 10));
    let fresh = aged_session("alice", 10, 10);
    let idle = aged_session("alice", 120, 61);
    let too_old = aged_session("alice", 3601, 0);
    let at_the_limit = aged_session("alice", 3600, 60);

    for (token, session) in [
        ("fresh", &fresh),
        ("idle", &idle),
        ("too-old", &too_old),
        ("at-the-limit", &at_the_limit),
    ] {
        store.insert(token, session.clone()).await;
    }

    let expired = store.remove_expired(unix_now_secs()).await;
    let mut expired_ids: Vec<_> = expired.iter().map(|s| s.session_id.clone()).collect();
    let mut expected = vec![idle.session_id.clone(), too_old.session_id.clone()];
    expired_ids.sort();
    expected.sort();

    assert_eq!(expired_ids, expected);
    assert!(store.get("idle").await.is_none());
    assert!(store.get_by_id(&too_old.session_id).await.is_none());
    assert!(store.get("fresh").await.is_some());
    assert!(store.get("at-the-limit").await.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_touch_refreshes_last_seen() {
    let session = aged_session("alice", 100, 100);
    let expiry = policy(60, 3600, 10);

    assert!(session.is_expired(unix_now_secs(), &expiry));

    session.touch();

    assert!(!session.is_expired(unix_now_secs(), &expiry));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_reap_once_removes_expired_sessions() {
    let store = SessionStore::new(policy(60, 3600, 10));
    let live = aged_session("alice", 10, 10);
    let expired = aged_session("alice", 100, 100);
    store.insert("live", live).await;
    store.insert("expired", expired).await;

    reap_once(&store, Duration::from_secs(24 * 60 * 60)).await;

    assert!(store.get("live").await.is_some());
    assert!(store.get("expired").await.is_none());
}

#[test]
fn test_reaper_interval_of_zero_disables_it() {
    assert!(SessionReaper::every(0).is_none());
    assert!(SessionReaper::every(60).is_some());
}

#[test]
fn test_session_tokens_are_256_bit_base64url() {
    let a = new_session_token();
    let b = new_session_token();

    assert_eq!(a.expose_secret().len(), 43);
    assert!(a
        .expose_secret()
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    assert_ne!(a.expose_secret(), b.expose_secret());
}

// M12: logins for the same user wait for each other; other users don't.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_login_lock_serialises_logins_per_user() {
    let store = SessionStore::default();
    let alice = store.lock_login("alice").await;

    assert!(
        timeout(Duration::from_millis(50), store.lock_login("alice"))
            .await
            .is_err(),
        "a second login for the same user must wait"
    );
    assert!(
        timeout(Duration::from_millis(50), store.lock_login("bob"))
            .await
            .is_ok(),
        "another user's login must not wait"
    );

    drop(alice);

    assert!(
        timeout(Duration::from_millis(50), store.lock_login("alice"))
            .await
            .is_ok(),
        "the lock must be free once the first login finishes"
    );
}

// A7: the store used raw session tokens as its keys, so anything that exposed
// its memory exposed working session cookies. It keeps only their digests.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_store_keeps_token_digests_not_tokens() {
    let store = SessionStore::default();
    let session = detached_session("alice");
    let token = new_session_token();

    store.insert(token.expose_secret(), session.clone()).await;

    let keys = store.stored_keys().await;

    assert_eq!(keys, vec![token_digest(token.expose_secret())]);
    assert_ne!(keys[0], *token.expose_secret());
    // Lookups still take the token itself, and the digest is no substitute.
    assert!(store.get(token.expose_secret()).await.is_some());
    assert!(store.get(&keys[0]).await.is_none());
    assert!(store.remove_by_token(token.expose_secret()).await.is_some());
    assert!(store.stored_keys().await.is_empty());
}
