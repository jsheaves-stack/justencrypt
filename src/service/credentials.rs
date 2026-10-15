use zxcvbn::{zxcvbn, Score};

use crate::{
    enums::service_error::ServiceError,
    util::names::{is_valid_username, MAX_USERNAME_BYTES},
};

/// The longest password accepted.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Checks the shape of a username and password before anything else looks at
/// them. Says nothing about whether the account exists.
pub fn validate_credentials(username: &str, password: &str) -> Result<(), ServiceError> {
    if !is_valid_username(username) {
        return Err(ServiceError::InvalidInput(format!(
            "Username must be 1-{} bytes, must not contain '/', '\\', '.', ':', '*', '?', '\"', '<', '>', '|' or control characters, must not end with a space, and must not be a device name such as CON or NUL",
            MAX_USERNAME_BYTES
        )));
    }

    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(ServiceError::InvalidInput(format!(
            "Password must be 1-{} bytes",
            MAX_PASSWORD_BYTES
        )));
    }

    Ok(())
}

/// Requires a zxcvbn score of at least `minimum_score` (0-4; the config
/// rejects anything higher at startup).
pub fn check_password_strength(password: &str, minimum_score: u8) -> Result<(), ServiceError> {
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

        return Err(ServiceError::PasswordDoesNotMeetRequirements);
    }

    Ok(())
}
