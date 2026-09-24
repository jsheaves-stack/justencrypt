use std::time::{SystemTime, UNIX_EPOCH};

/// Current time in whole seconds since the Unix epoch.
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
