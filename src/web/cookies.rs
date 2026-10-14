use std::time::Duration;

use cookie::{
    time::{self, OffsetDateTime},
    Cookie, Key, SameSite,
};
use secrecy::{ExposeSecret, SecretString};

use crate::config::decode_secret_key;

/// The name of the cookie that holds the session token.
pub const SESSION_COOKIE: &str = "sid";

/// The key the session cookies are encrypted with, from the configured secret
/// key. Without one (allowed only in debug builds), a random key is made, so
/// sessions don't survive a restart.
pub fn cookie_key(secret_key: Option<&SecretString>) -> Key {
    let Some(secret_key) = secret_key else {
        warn!("JUSTENCRYPT_SECRET_KEY is not set; using a random key for this launch.");

        return Key::generate();
    };

    // The configuration has already checked the key.
    let bytes = decode_secret_key(secret_key.expose_secret())
        .expect("the secret key was checked when the configuration was read");

    if bytes.len() >= 64 {
        Key::from(&bytes)
    } else {
        Key::derive_from(&bytes)
    }
}

/// The cookie that carries a new session's `token` for `max_age`. Page
/// scripts can't read it (`HttpOnly`), and it is HTTPS-only when `secure` is
/// set.
pub fn session_cookie(token: SecretString, max_age: Duration, secure: bool) -> Cookie<'static> {
    let max_age = time::Duration::seconds(i64::try_from(max_age.as_secs()).unwrap_or(i64::MAX));
    let mut cookie = Cookie::new(SESSION_COOKIE, token.expose_secret().clone());

    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_secure(secure);
    cookie.set_path("/");
    cookie.set_max_age(max_age);
    cookie.set_expires(OffsetDateTime::now_utc().saturating_add(max_age));

    cookie
}

/// The cookie that makes the browser forget the session cookie.
pub fn session_cookie_removal() -> Cookie<'static> {
    let mut cookie = Cookie::from(SESSION_COOKIE);

    cookie.set_path("/");
    cookie.set_same_site(SameSite::Lax);

    cookie
}
