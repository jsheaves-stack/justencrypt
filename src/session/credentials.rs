use zxcvbn::{zxcvbn, Score};

use crate::enums::request_error::RequestError;

/// The longest username accepted.
pub const MAX_USERNAME_BYTES: usize = 64;
/// The longest password accepted.
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

/// Requires a zxcvbn score of at least `minimum_score` (0-4; the config
/// rejects anything higher at startup).
pub fn check_password_strength(password: &str, minimum_score: u8) -> Result<(), RequestError> {
    let minimum = match minimum_score {
        0 => Score::Zero,
        1 => Score::One,
        2 => Score::Two,
        3 => Score::Three,
        _ => Score::Four,
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
