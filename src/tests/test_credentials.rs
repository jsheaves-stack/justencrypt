use crate::session::credentials::{is_valid_username, validate_credentials};

#[test]
fn test_valid_usernames() {
    for username in [
        "alice",
        "user_1",
        "a-b",
        "UPPER",
        "\u{e9}l\u{e8}ve",
        &"a".repeat(64),
    ] {
        assert!(
            is_valid_username(username),
            "{:?} should be valid",
            username
        );
    }
}

#[test]
fn test_invalid_usernames() {
    for username in [
        "",
        "/etc/passwd",
        "../x",
        "a/b",
        "a\\b",
        "a.b",
        ".",
        "..",
        "a\u{0}b",
        "a\nb",
        "a\tb",
        &"a".repeat(65),
    ] {
        assert!(
            !is_valid_username(username),
            "{:?} should be invalid",
            username
        );
    }
}

#[test]
fn test_password_length_limits() {
    assert!(validate_credentials("alice", "x").is_ok());
    assert!(validate_credentials("alice", &"x".repeat(1024)).is_ok());
    assert!(validate_credentials("alice", "").is_err());
    assert!(validate_credentials("alice", &"x".repeat(1025)).is_err());
}
