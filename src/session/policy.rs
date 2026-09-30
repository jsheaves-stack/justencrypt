use std::time::Duration;

use crate::config::SessionConfig;

/// Rules for how long sessions live and how many a user may have.
#[derive(Clone, Debug)]
pub struct SessionPolicy {
    /// A session with no requests for longer than this expires.
    pub idle_timeout: Duration,
    /// A session older than this expires, however active it is. Also used as
    /// the session cookie's `Max-Age`.
    pub max_lifetime: Duration,
    /// Logging in beyond this many sessions ends the user's oldest session.
    pub max_per_user: usize,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::from(&SessionConfig::default())
    }
}

impl From<&SessionConfig> for SessionPolicy {
    fn from(config: &SessionConfig) -> Self {
        Self {
            idle_timeout: Duration::from_secs(config.idle_timeout_seconds.get()),
            max_lifetime: Duration::from_secs(config.max_lifetime_seconds.get()),
            max_per_user: config.max_per_user.get(),
        }
    }
}
