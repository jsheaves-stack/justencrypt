use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocket::tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

use crate::session::{policy::SessionPolicy, user_session::UserSession};

/// The set of live user sessions.
///
/// Sessions are found by their session token, but the store only keeps each
/// token's [`token_digest`], so its memory never holds a usable session
/// cookie. Methods take the token itself and hash it.
///
/// Both lookup maps live behind a single lock so they can never be observed
/// out of sync, and so there is no lock ordering to get wrong. Every method
/// takes the lock exactly once, returns owned data, and never awaits anything
/// else while holding it. Callers that need to do slow work per session should
/// call [`SessionStore::snapshot`] and work on the returned `Arc`s.
///
/// The store also applies the [`SessionPolicy`]: it caps sessions per user on
/// insert and finds expired sessions in [`SessionStore::remove_expired`].
/// Sessions it drops are returned to the caller, who owns cleaning up their
/// uploads.
pub struct SessionStore {
    inner: RwLock<Inner>,
    policy: SessionPolicy,
    login_locks: LoginLocks,
}

type LoginLocks = StdMutex<HashMap<String, Arc<Mutex<()>>>>;

/// Held while a user logs in; see [`SessionStore::lock_login`]. Dropping it
/// releases the lock, and removes the user's entry once nobody else holds or
/// is waiting for it.
pub struct LoginGuard<'a> {
    guard: Option<OwnedMutexGuard<()>>,
    lock: Arc<Mutex<()>>,
    username: String,
    login_locks: &'a LoginLocks,
}

impl Drop for LoginGuard<'_> {
    fn drop(&mut self) {
        self.guard.take();

        let mut locks = self.login_locks.lock().unwrap_or_else(|e| e.into_inner());

        // One reference is the map's and one is ours; any more belong to
        // logins still waiting for the lock.

        if Arc::strong_count(&self.lock) == 2 {
            locks.remove(&self.username);
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(SessionPolicy::default())
    }
}

/// Invariant: `token_of` is the exact inverse of `by_token`, so every session
/// is reachable from both its token digest and its session id.
#[derive(Default)]
struct Inner {
    by_token: HashMap<String, Arc<UserSession>>,
    token_of: HashMap<String, String>,
}

/// The key a session token is stored under: its BLAKE2b-256 digest as hex.
pub fn token_digest(token: &str) -> String {
    let digest = orion::hash::digest(token.as_bytes()).expect("hashing a token cannot fail");

    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl SessionStore {
    #[cfg(test)]
    pub async fn stored_keys(&self) -> Vec<String> {
        self.inner.read().await.by_token.keys().cloned().collect()
    }

    pub fn new(policy: SessionPolicy) -> Self {
        Self {
            inner: RwLock::default(),
            policy,
            login_locks: StdMutex::default(),
        }
    }

    /// Waits until no other login for `username` is in progress. Holding the
    /// guard from the pool lookup until the new session is inserted means
    /// concurrent logins open (and migrate) the user's database one at a
    /// time, and later ones reuse the pool the first one created.
    pub async fn lock_login(&self, username: &str) -> LoginGuard<'_> {
        let lock = self
            .login_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(username.to_owned())
            .or_default()
            .clone();
        let guard = lock.clone().lock_owned().await;

        LoginGuard {
            guard: Some(guard),
            lock,
            username: username.to_owned(),
            login_locks: &self.login_locks,
        }
    }

    pub fn policy(&self) -> &SessionPolicy {
        &self.policy
    }

    /// Registers `session` under `token`. Any earlier registration of the
    /// same token or of the same session is replaced, so the two lookups can
    /// never disagree.
    ///
    /// If the user now has more sessions than the policy allows, their oldest
    /// other sessions are removed and returned.
    pub async fn insert(&self, token: &str, session: Arc<UserSession>) -> Vec<Arc<UserSession>> {
        let token_key = token_digest(token);
        let session_id = session.session_id.clone();
        let username = session.username.clone();
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

        let mut others: Vec<Arc<UserSession>> = inner
            .by_token
            .values()
            .filter(|s| s.username == username && s.session_id != session_id)
            .cloned()
            .collect();
        let allowed_others = self.policy.max_per_user.saturating_sub(1);

        if others.len() <= allowed_others {
            return Vec::new();
        }

        others.sort_by_key(|s| s.created_at);
        let evict_count = others.len() - allowed_others;
        let evicted: Vec<Arc<UserSession>> = others.into_iter().take(evict_count).collect();

        for session in &evicted {
            if let Some(token_key) = inner.token_of.remove(&session.session_id) {
                inner.by_token.remove(&token_key);
            }
        }

        evicted
    }

    /// Removes and returns every session that has expired at `now_secs`.
    pub async fn remove_expired(&self, now_secs: u64) -> Vec<Arc<UserSession>> {
        let mut inner = self.inner.write().await;
        let mut expired = Vec::new();

        inner.by_token.retain(|_, session| {
            if session.is_expired(now_secs, &self.policy) {
                expired.push(session.clone());

                false
            } else {
                true
            }
        });

        for session in &expired {
            inner.token_of.remove(&session.session_id);
        }

        expired
    }

    pub async fn get(&self, token: &str) -> Option<Arc<UserSession>> {
        let token_key = token_digest(token);

        self.inner.read().await.by_token.get(&token_key).cloned()
    }

    pub async fn get_by_id(&self, session_id: &str) -> Option<Arc<UserSession>> {
        let inner = self.inner.read().await;
        let token_key = inner.token_of.get(session_id)?;

        inner.by_token.get(token_key).cloned()
    }

    pub async fn remove_by_token(&self, token: &str) -> Option<Arc<UserSession>> {
        let token_key = token_digest(token);
        let mut inner = self.inner.write().await;
        let session = inner.by_token.remove(&token_key)?;

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
