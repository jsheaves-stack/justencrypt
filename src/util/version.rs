//! The server's version.

/// `JUSTENCRYPT_VERSION` when it was set at compile time (CI builds set it to
/// `<Cargo.toml version>-<UTC date>.<build of the day>`), otherwise the
/// version in Cargo.toml.
pub const VERSION: &str = match option_env!("JUSTENCRYPT_VERSION") {
    Some(version) if !version.is_empty() => version,
    _ => env!("CARGO_PKG_VERSION"),
};
