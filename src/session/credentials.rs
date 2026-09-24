use std::env;

use zxcvbn::{zxcvbn, Score};

use crate::enums::request_error::RequestError;

pub const MAX_USERNAME_BYTES: usize = 64;
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// A username becomes a directory and file name, so it must be non-empty, at
/// most 64 bytes, and free of path separators, dots and control characters.
pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_USERNAME_BYTES
        && !username.contains(['/', '\\', '.'])
        && !username.chars().any(char::is_control)
}

/// Checks the shape of a username and password before anything else looks at
/// them. Says nothing about whether the account exists.
pub fn validate_credentials(username: &str, password: &str) -> Result<(), RequestError> {
    if !is_valid_username(username) {
        return Err(RequestError::BadRequest(format!(
            "Username must be 1-{} bytes and must not contain '/', '\\', '.' or control characters",
            MAX_USERNAME_BYTES
        )));
    }

    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(RequestError::BadRequest(format!(
            "Password must be 1-{} bytes",
            MAX_PASSWORD_BYTES
        )));
    }

    Ok(())
}

/// Applies the minimum zxcvbn score from
/// `JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE` (default 4; any value above
/// 4 means 3).
pub fn check_password_strength(password: &str) -> Result<(), RequestError> {
    let minimum = match env::var("JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(4)
    {
        0 => Score::Zero,
        1 => Score::One,
        2 => Score::Two,
        3 => Score::Three,
        4 => Score::Four,
        _ => Score::Three,
    };

    let score = zxcvbn(password, &[]).score();

    if score < minimum {
        trace!(
            "Password score {} does not meet minimum required score {}.",
            score,
            minimum
        );

        return Err(RequestError::PasswordDoesNotMeetRequirements);
    }

    Ok(())
}
