use crate::{service::credentials::validate_credentials, util::names::is_valid_username};

#[test]
fn test_valid_usernames() {
    for username in [
        "alice",
        "user_1",
        "a-b",
        "UPPER",
        "\u{e9}l\u{e8}ve",
        " leading",
        "a b",
        "console",
        "COM10",
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
        "C:",
        "a:b",
        "a*b",
        "a?b",
        "a\"b",
        "a<b",
        "a>b",
        "a|b",
        "trailing ",
        "CON",
        "nul",
        "Aux",
        "com1",
        "LPT9",
        "COM\u{b9}",
        "conin$",
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
