use std::{collections::HashMap, sync::Arc};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocket::tokio::sync::RwLock;

use crate::session::{policy::SessionPolicy, user_session::UserSession};

/// The set of live user sessions.
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
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(SessionPolicy::default())
    }
}

/// Invariant: `token_of` is the exact inverse of `by_token`, so every session
/// is reachable from both its token key and its session id.
#[derive(Default)]
struct Inner {
    by_token: HashMap<String, Arc<UserSession>>,
    token_of: HashMap<String, String>,
}

impl SessionStore {
    pub fn new(policy: SessionPolicy) -> Self {
        Self {
            inner: RwLock::default(),
            policy,
        }
    }

    pub fn policy(&self) -> &SessionPolicy {
        &self.policy
    }

    /// Registers `session` under `token_key`. Any earlier registration of the
    /// same token or of the same session is replaced, so the two lookups can
    /// never disagree.
    ///
    /// If the user now has more sessions than the policy allows, their oldest
    /// other sessions are removed and returned.
    pub async fn insert(
        &self,
        token_key: String,
        session: Arc<UserSession>,
    ) -> Vec<Arc<UserSession>> {
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
