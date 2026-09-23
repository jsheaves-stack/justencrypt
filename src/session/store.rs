use std::{collections::HashMap, sync::Arc};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocket::tokio::sync::RwLock;

use crate::session::user_session::UserSession;

/// The set of live user sessions.
///
/// Both lookup maps live behind a single lock so they can never be observed
/// out of sync, and so there is no lock ordering to get wrong. Every method
/// takes the lock exactly once, returns owned data, and never awaits anything
/// else while holding it. Callers that need to do slow work per session should
/// call [`SessionStore::snapshot`] and work on the returned `Arc`s.
#[derive(Default)]
pub struct SessionStore {
    inner: RwLock<Inner>,
}

/// Invariant: `token_of` is the exact inverse of `by_token`, so every session
/// is reachable from both its token key and its session id.
#[derive(Default)]
struct Inner {
    by_token: HashMap<String, Arc<UserSession>>,
    token_of: HashMap<String, String>,
}

impl SessionStore {
    /// Registers `session` under `token_key`. Any earlier registration of the
    /// same token or of the same session is replaced, so the two lookups can
    /// never disagree.
    pub async fn insert(&self, token_key: String, session: Arc<UserSession>) {
        let session_id = session.session_id.clone();
        let mut inner = self.inner.write().await;

        if let Some(old_token) = inner.token_of.insert(session_id.clone(), token_key.clone()) {
            if old_token != token_key {
                inner.by_token.remove(&old_token);
            }
        }

        if let Some(previous) = inner.by_token.insert(token_key, session) {
            if previous.session_id != session_id {
                inner.token_of.remove(&previous.session_id);
            }
        }
    }

    pub async fn get(&self, token_key: &str) -> Option<Arc<UserSession>> {
        self.inner.read().await.by_token.get(token_key).cloned()
    }

    pub async fn get_by_id(&self, session_id: &str) -> Option<Arc<UserSession>> {
        let inner = self.inner.read().await;
        let token_key = inner.token_of.get(session_id)?;

        inner.by_token.get(token_key).cloned()
    }

    pub async fn remove_by_token(&self, token_key: &str) -> Option<Arc<UserSession>> {
        let mut inner = self.inner.write().await;
        let session = inner.by_token.remove(token_key)?;

        inner.token_of.remove(&session.session_id);

        Some(session)
    }

    pub async fn remove_by_id(&self, session_id: &str) -> Option<Arc<UserSession>> {
        let mut inner = self.inner.write().await;
        let token_key = inner.token_of.remove(session_id)?;

        inner.by_token.remove(&token_key)
    }

    /// Clones every live session out of the store and releases the lock, so
    /// the caller can do slow per-session work without blocking anyone else.
    pub async fn snapshot(&self) -> Vec<Arc<UserSession>> {
        self.inner.read().await.by_token.values().cloned().collect()
    }

    /// Returns the shared DB pool of any live session belonging to `username`.
    pub async fn pool_for_user(&self, username: &str) -> Option<Pool<SqliteConnectionManager>> {
        self.inner
            .read()
            .await
            .by_token
            .values()
            .find(|s| s.username == username)
            .map(|s| s.db_pool.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        path::PathBuf,
        time::{Duration, SystemTime},
    };

    use rocket::tokio::{runtime::Builder, sync::Mutex, time::timeout};
    use secrecy::SecretString;

    use super::*;

    // A session that never touches the disk: the pool is built without
    // establishing a connection.
    fn test_session(username: &str) -> Arc<UserSession> {
        let pool = Pool::builder()
            .max_size(1)
            .build_unchecked(SqliteConnectionManager::memory());
        let session_id = uuid::Uuid::new_v4().to_string();

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

    fn run<F: std::future::Future>(workers: usize, fut: F) -> F::Output {
        Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn insert_then_lookup_by_token_and_id() {
        run(1, async {
            let store = SessionStore::default();
            let session = test_session("alice");

            store.insert("tok-a".into(), session.clone()).await;

            assert!(Arc::ptr_eq(&store.get("tok-a").await.unwrap(), &session));
            assert!(Arc::ptr_eq(
                &store.get_by_id(&session.session_id).await.unwrap(),
                &session
            ));
            assert!(store.get("nope").await.is_none());
            assert!(store.get_by_id("nope").await.is_none());
        });
    }

    #[test]
    fn remove_by_token_clears_both_lookups() {
        run(1, async {
            let store = SessionStore::default();
            let session = test_session("alice");
            store.insert("tok-a".into(), session.clone()).await;

            let removed = store.remove_by_token("tok-a").await.unwrap();

            assert!(Arc::ptr_eq(&removed, &session));
            assert!(store.get("tok-a").await.is_none());
            assert!(store.get_by_id(&session.session_id).await.is_none());
            assert!(store.remove_by_token("tok-a").await.is_none());
        });
    }

    #[test]
    fn remove_by_id_clears_both_lookups() {
        run(1, async {
            let store = SessionStore::default();
            let session = test_session("alice");
            store.insert("tok-a".into(), session.clone()).await;

            let removed = store.remove_by_id(&session.session_id).await.unwrap();

            assert!(Arc::ptr_eq(&removed, &session));
            assert!(store.get("tok-a").await.is_none());
            assert!(store.get_by_id(&session.session_id).await.is_none());
            assert!(store.remove_by_id(&session.session_id).await.is_none());
        });
    }

    #[test]
    fn reinserting_a_token_replaces_the_old_session_completely() {
        run(1, async {
            let store = SessionStore::default();
            let old = test_session("alice");
            let new = test_session("alice");
            store.insert("tok-a".into(), old.clone()).await;

            store.insert("tok-a".into(), new.clone()).await;

            assert!(Arc::ptr_eq(&store.get("tok-a").await.unwrap(), &new));
            assert!(store.get_by_id(&old.session_id).await.is_none());
            assert!(store.remove_by_id(&old.session_id).await.is_none());
            assert_eq!(store.snapshot().await.len(), 1);
        });
    }

    #[test]
    fn reinserting_a_session_under_a_new_token_drops_the_old_token() {
        run(1, async {
            let store = SessionStore::default();
            let session = test_session("alice");
            store.insert("tok-old".into(), session.clone()).await;

            store.insert("tok-new".into(), session.clone()).await;

            assert!(store.get("tok-old").await.is_none());
            assert!(Arc::ptr_eq(&store.get("tok-new").await.unwrap(), &session));
            assert_eq!(store.snapshot().await.len(), 1);
        });
    }

    #[test]
    fn snapshot_and_pool_for_user() {
        run(1, async {
            let store = SessionStore::default();
            store.insert("tok-a".into(), test_session("alice")).await;
            store.insert("tok-b".into(), test_session("bob")).await;

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
        });
    }

    // H1 regression: concurrent readers must keep making progress while other
    // tasks insert and remove sessions. Under the old two-map layout the
    // equivalent workload deadlocked permanently.
    #[test]
    fn concurrent_reads_and_removals_do_not_deadlock() {
        run(8, async {
            let store = Arc::new(SessionStore::default());
            let stable = test_session("reader");
            store.insert("stable".into(), stable.clone()).await;

            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

            let readers: Vec<_> = (0..8)
                .map(|_| {
                    let store = store.clone();
                    rocket::tokio::spawn(async move {
                        for _ in 0..50_000 {
                            assert!(store.get("stable").await.is_some());
                        }
                    })
                })
                .collect();

            let churn = {
                let store = store.clone();
                let stop = stop.clone();
                rocket::tokio::spawn(async move {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let session = test_session("churn");
                        let id = session.session_id.clone();

                        store.insert("churn-a".into(), session.clone()).await;
                        store.remove_by_token("churn-a").await;
                        store.insert("churn-b".into(), session).await;
                        store.remove_by_id(&id).await;
                        store.snapshot().await;
                        rocket::tokio::task::yield_now().await;
                    }
                })
            };

            let all = async {
                for reader in readers {
                    reader.await.unwrap();
                }
            };

            timeout(Duration::from_secs(30), all)
                .await
                .expect("session store deadlocked");

            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            timeout(Duration::from_secs(30), churn)
                .await
                .expect("churn task deadlocked")
                .unwrap();
        });
    }
}
