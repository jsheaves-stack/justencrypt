use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use rocket::data::{Limits, ToByteUnit};
use secrecy::ExposeSecret;

use crate::config::{AppConfig, LogLevel, SyncMode, TempStore};

fn load(vars: &[(&str, &str)]) -> Result<AppConfig, String> {
    AppConfig::from_vars(
        vars.iter()
            .map(|(name, value)| (name.to_string(), value.to_string())),
    )
    .map_err(|e| e.to_string())
}

fn load_err(vars: &[(&str, &str)]) -> String {
    load(vars).expect_err("config should have been rejected")
}

#[test]
fn test_config_defaults_with_no_variables() {
    let config = load(&[]).unwrap();

    assert_eq!(config.server.address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(config.server.port, 8000);
    assert_eq!(config.server.workers.get(), 16);
    assert_eq!(config.server.log_level, LogLevel::Warn);
    assert_eq!(config.user_data_path, PathBuf::from("./user_data"));
    assert_eq!(config.minimum_password_security_score, 4);
    assert!(config.secure_cookies);
    assert!(config.admin_api_key.is_none());
    assert!(config.max_active_uploads.is_none());
    assert!(!config.orphan_scan_enabled);
    assert_eq!(config.upload_ttl_seconds.get(), 86400);
    assert_eq!(config.session.reaper_interval_seconds, 0);
    assert_eq!(config.db.max_connections.get(), 16);
    assert_eq!(config.db.synchronous_mode, SyncMode::Normal);
    assert_eq!(config.db.temp_store, TempStore::Memory);
    assert_eq!(config.limits.file, 64.gibibytes());
    assert!(config.thumbnail.concurrency.is_none());
    assert_eq!(config.thumbnail.max_decode_memory, 256.mebibytes());
}

#[test]
fn test_config_reads_every_group() {
    let config = load(&[
        ("JUSTENCRYPT_ADDRESS", "127.0.0.1"),
        ("JUSTENCRYPT_PORT", "9000"),
        ("JUSTENCRYPT_LOG_LEVEL", "debug"),
        ("JUSTENCRYPT_LIMITS_FILE", "1GiB"),
        ("JUSTENCRYPT_LIMITS_FILE_JPG", "5MiB"),
        ("JUSTENCRYPT_SESSION_IDLE_TIMEOUT_SECONDS", "120"),
        ("JUSTENCRYPT_MAX_SESSIONS_PER_USER", "2"),
        ("JUSTENCRYPT_MAX_DB_CONNECTIONS_PER_USER", "4"),
        ("JUSTENCRYPT_DB_SYNCHRONOUS_MODE", "full"),
        ("JUSTENCRYPT_USER_DATA_PATH", "/srv/data"),
        ("JUSTENCRYPT_MAX_ACTIVE_UPLOADS", "100"),
        ("JUSTENCRYPT_ADMIN_API_KEY", "12345"),
        ("JUSTENCRYPT_SECURE_COOKIES", "false"),
    ])
    .unwrap();

    assert_eq!(config.server.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(config.server.port, 9000);
    assert_eq!(config.server.log_level, LogLevel::Debug);
    assert_eq!(config.limits.file, 1.gibibytes());
    assert_eq!(config.session.idle_timeout_seconds.get(), 120);
    assert_eq!(config.session.max_per_user.get(), 2);
    assert_eq!(config.db.max_connections.get(), 4);
    assert_eq!(config.db.synchronous_mode, SyncMode::Full);
    assert_eq!(config.user_data_path, PathBuf::from("/srv/data"));
    assert_eq!(config.max_active_uploads.unwrap().get(), 100);
    // A numeric key must stay a string.
    assert_eq!(
        config.admin_api_key.as_ref().unwrap().expose_secret(),
        "12345"
    );
    assert!(!config.secure_cookies);

    // The other limits keep their defaults.
    assert_eq!(config.limits.json, 10.mebibytes());
    assert_eq!(config.limits.string, 10.mebibytes());

    let limits: Limits = config.rocket_figment().extract_inner("limits").unwrap();
    assert_eq!(limits.get("file"), Some(1.gibibytes()));
    assert_eq!(limits.get("file/jpg"), Some(5.mebibytes()));
}

#[test]
fn test_config_empty_values_count_as_unset() {
    let config = load(&[
        ("JUSTENCRYPT_ALLOW_ORIGIN", ""),
        ("JUSTENCRYPT_ADMIN_API_KEY", "  "),
        ("JUSTENCRYPT_TLS_CERT_PATH", ""),
        ("JUSTENCRYPT_PORT", ""),
    ])
    .unwrap();

    assert!(config.allow_origin.is_none());
    assert!(config.admin_api_key.is_none());
    assert!(config.server.tls_cert_path.is_none());
    assert_eq!(config.server.port, 8000);
}

#[test]
fn test_config_ignores_other_variables() {
    assert!(load(&[("PATH", "/usr/bin"), ("ROCKET_PORT", "1")]).is_ok());
}

#[test]
fn test_config_orphan_scan_flag_values() {
    for value in ["true", "TRUE", "1", " yes ", "on"] {
        let config = load(&[("JUSTENCRYPT_ORPHAN_SCAN_ENABLED", value)]).unwrap();
        assert!(config.orphan_scan_enabled, "{:?}", value);
    }

    for value in ["false", "0", "no", "off"] {
        let config = load(&[("JUSTENCRYPT_ORPHAN_SCAN_ENABLED", value)]).unwrap();
        assert!(!config.orphan_scan_enabled, "{:?}", value);
    }

    let error = load_err(&[("JUSTENCRYPT_ORPHAN_SCAN_ENABLED", "nonsense")]);
    assert!(
        error.contains("JUSTENCRYPT_ORPHAN_SCAN_ENABLED"),
        "{}",
        error
    );
}

#[test]
fn test_config_errors_name_the_variable() {
    for (name, value) in [
        ("JUSTENCRYPT_PORT", "eighty"),
        ("JUSTENCRYPT_PORT", "70000"),
        ("JUSTENCRYPT_WORKERS", "0"),
        ("JUSTENCRYPT_LIMITS_FILE", "lots"),
        ("JUSTENCRYPT_UPLOAD_TTL_SECONDS", "0"),
        ("JUSTENCRYPT_SESSION_IDLE_TIMEOUT_SECONDS", "-5"),
        ("JUSTENCRYPT_MAX_ACTIVE_UPLOADS", "0"),
        ("JUSTENCRYPT_DB_CACHE_SIZE_KB", "-1"),
        (
            "JUSTENCRYPT_DB_SYNCHRONOUS_MODE",
            "NORMAL; DROP TABLE files",
        ),
        ("JUSTENCRYPT_DB_TEMP_STORE", "DISK"),
        ("JUSTENCRYPT_LOG_LEVEL", "Loud"),
        ("JUSTENCRYPT_ROCKET_LOG_LEVEL", "Warn"),
        ("JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE", "5"),
        ("JUSTENCRYPT_ADDRESS", "localhost"),
    ] {
        let error = load_err(&[(name, value)]);

        assert!(error.contains(name), "{}={:?} gave: {}", name, value, error);
    }
}

#[test]
fn test_config_rejects_unknown_justencrypt_variables() {
    let error = load_err(&[("JUSTENCRYPT_MAX_UPLOADS", "5")]);

    assert!(error.contains("JUSTENCRYPT_MAX_UPLOADS"), "{}", error);
}

#[test]
fn test_config_rejects_inconsistent_values() {
    let error = load_err(&[
        ("JUSTENCRYPT_MIN_DB_CONNECTIONS_PER_USER", "8"),
        ("JUSTENCRYPT_MAX_DB_CONNECTIONS_PER_USER", "4"),
    ]);
    assert!(
        error.contains("JUSTENCRYPT_MIN_DB_CONNECTIONS_PER_USER"),
        "{}",
        error
    );

    let error = load_err(&[("JUSTENCRYPT_TLS_CERT_PATH", "/cert.pem")]);
    assert!(error.contains("JUSTENCRYPT_TLS_KEY_PATH"), "{}", error);
}

#[test]
fn test_config_thumbnail_settings() {
    // Without a setting, 70% of the workers, and never zero.
    assert_eq!(load(&[]).unwrap().thumbnail_concurrency(), 11);
    assert_eq!(
        load(&[("JUSTENCRYPT_WORKERS", "1")])
            .unwrap()
            .thumbnail_concurrency(),
        1
    );

    let config = load(&[
        ("JUSTENCRYPT_THUMBNAIL_CONCURRENCY", "3"),
        ("JUSTENCRYPT_THUMBNAIL_MAX_DECODE_MEMORY", "64MiB"),
    ])
    .unwrap();

    assert_eq!(config.thumbnail_concurrency(), 3);
    assert_eq!(config.thumbnail.max_decode_memory, 64.mebibytes());
    assert!(load_err(&[("JUSTENCRYPT_THUMBNAIL_CONCURRENCY", "0")])
        .contains("JUSTENCRYPT_THUMBNAIL_CONCURRENCY"));
}
