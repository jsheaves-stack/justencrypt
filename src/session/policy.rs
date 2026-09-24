use std::{env, time::Duration};

const DEFAULT_IDLE_TIMEOUT_SECONDS: u64 = 60 * 60;
const DEFAULT_MAX_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_MAX_SESSIONS_PER_USER: usize = 5;

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
        Self {
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECONDS),
            max_lifetime: Duration::from_secs(DEFAULT_MAX_LIFETIME_SECONDS),
            max_per_user: DEFAULT_MAX_SESSIONS_PER_USER,
        }
    }
}

impl SessionPolicy {
    /// Reads the policy from `JUSTENCRYPT_SESSION_IDLE_TIMEOUT_SECONDS`,
    /// `JUSTENCRYPT_SESSION_MAX_LIFETIME_SECONDS` and
    /// `JUSTENCRYPT_MAX_SESSIONS_PER_USER`. Missing, unparsable or zero values
    /// fall back to the defaults.
    pub fn from_env() -> Self {
        let defaults = Self::default();

        Self {
            idle_timeout: positive_env("JUSTENCRYPT_SESSION_IDLE_TIMEOUT_SECONDS")
                .map(Duration::from_secs)
                .unwrap_or(defaults.idle_timeout),
            max_lifetime: positive_env("JUSTENCRYPT_SESSION_MAX_LIFETIME_SECONDS")
                .map(Duration::from_secs)
                .unwrap_or(defaults.max_lifetime),
            max_per_user: positive_env("JUSTENCRYPT_MAX_SESSIONS_PER_USER")
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(defaults.max_per_user),
        }
    }
}

fn positive_env(name: &str) -> Option<u64> {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
}
