//! Server configuration. It is read once at startup from `JUSTENCRYPT_*`
//! environment variables (`main` loads `.env` first) and checked before the
//! server starts, so a bad value stops the server with a message naming the
//! variable instead of silently falling back to a default.

use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use log::LevelFilter;
use rocket::{
    config::{Config, TlsConfig},
    data::{ByteUnit, Limits, ToByteUnit},
    figment::{providers::Serialized, Figment},
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::enums::config_error::ConfigError;

const ENV_PREFIX: &str = "JUSTENCRYPT_";

/// Every environment variable the server reads, without the `JUSTENCRYPT_`
/// prefix, and the [`AppConfig`] field its value goes to.
const ENV_KEYS: &[(&str, &str)] = &[
    ("ADDRESS", "server.address"),
    ("PORT", "server.port"),
    ("WORKERS", "server.workers"),
    ("KEEP_ALIVE", "server.keep_alive"),
    ("ROCKET_SECRET_KEY", "server.secret_key"),
    ("TLS_CERT_PATH", "server.tls_cert_path"),
    ("TLS_KEY_PATH", "server.tls_key_path"),
    ("LOG_LEVEL", "server.log_level"),
    ("ROCKET_LOG_LEVEL", "server.rocket_log_level"),
    ("LIMITS_FORM", "limits.form"),
    ("LIMITS_DATA_FORM", "limits.data_form"),
    ("LIMITS_FILE", "limits.file"),
    ("LIMITS_FILE_CHUNK", "limits.file_chunk"),
    ("LIMITS_JSON", "limits.json"),
    ("LIMITS_MSGPACK", "limits.msgpack"),
    ("LIMITS_FILE_JPG", "limits.file_jpg"),
    ("LIMITS_BYTES", "limits.bytes"),
    ("LIMITS_STRING", "limits.string"),
    (
        "SESSION_IDLE_TIMEOUT_SECONDS",
        "session.idle_timeout_seconds",
    ),
    (
        "SESSION_MAX_LIFETIME_SECONDS",
        "session.max_lifetime_seconds",
    ),
    ("MAX_SESSIONS_PER_USER", "session.max_per_user"),
    (
        "SESSION_REAPER_INTERVAL_SECONDS",
        "session.reaper_interval_seconds",
    ),
    ("MIN_DB_CONNECTIONS_PER_USER", "db.min_connections"),
    ("MAX_DB_CONNECTIONS_PER_USER", "db.max_connections"),
    ("DB_IDLE_TIMEOUT_SECONDS", "db.idle_timeout_seconds"),
    ("DB_BUSY_TIMEOUT_MS", "db.busy_timeout_ms"),
    ("DB_SYNCHRONOUS_MODE", "db.synchronous_mode"),
    ("DB_CACHE_SIZE_KB", "db.cache_size_kb"),
    ("DB_TEMP_STORE", "db.temp_store"),
    ("DB_JOURNAL_SIZE_LIMIT_BYTES", "db.journal_size_limit_bytes"),
    (
        "DB_CONNECTION_TIMEOUT_SECONDS",
        "db.connection_timeout_seconds",
    ),
    ("THUMBNAIL_CONCURRENCY", "thumbnail.concurrency"),
    ("THUMBNAIL_MAX_DECODE_MEMORY", "thumbnail.max_decode_memory"),
    ("USER_DATA_PATH", "user_data_path"),
    (
        "MINIMUM_PASSWORD_SECURITY_SCORE",
        "minimum_password_security_score",
    ),
    ("SECURE_COOKIES", "secure_cookies"),
    ("ALLOW_ORIGIN", "allow_origin"),
    ("ADMIN_API_KEY", "admin_api_key"),
    ("MAX_ACTIVE_UPLOADS", "max_active_uploads"),
    ("UPLOAD_TTL_SECONDS", "upload_ttl_seconds"),
    ("ORPHAN_SCAN_ENABLED", "orphan_scan_enabled"),
];

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub limits: LimitsConfig,
    pub session: SessionConfig,
    pub db: DbConfig,
    pub thumbnail: ThumbnailConfig,
    /// Directory that holds one sub-directory per user.
    pub user_data_path: PathBuf,
    /// Minimum zxcvbn score (0-4) for the password of a new account.
    pub minimum_password_security_score: u8,
    /// Whether session cookies are only sent over HTTPS.
    pub secure_cookies: bool,
    /// Value of the `Access-Control-Allow-Origin` header; none when unset.
    pub allow_origin: Option<String>,
    /// Key for the admin routes, which are only mounted when it is set.
    pub admin_api_key: Option<SecretString>,
    /// Most uploads a session may have in progress; no limit when unset.
    pub max_active_uploads: Option<NonZeroUsize>,
    /// How long an upload can sit idle before it is considered abandoned.
    pub upload_ttl_seconds: NonZeroU64,
    /// Whether every login starts a scan for the user's unreferenced files.
    pub orphan_scan_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub address: IpAddr,
    pub port: u16,
    pub workers: NonZeroUsize,
    pub keep_alive: u32,
    /// Signs the private session cookies. Required in release builds; debug
    /// builds let Rocket generate one for each launch.
    pub secret_key: Option<SecretString>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub log_level: LogLevel,
    pub rocket_log_level: RocketLogLevel,
}

/// Request body limits, passed to Rocket as its `limits` setting.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub form: ByteUnit,
    pub data_form: ByteUnit,
    /// Largest file that may be stored.
    pub file: ByteUnit,
    /// Largest body of a single chunk-upload request.
    pub file_chunk: ByteUnit,
    pub json: ByteUnit,
    pub msgpack: ByteUnit,
    pub file_jpg: ByteUnit,
    pub bytes: ByteUnit,
    pub string: ByteUnit,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    pub idle_timeout_seconds: NonZeroU64,
    pub max_lifetime_seconds: NonZeroU64,
    pub max_per_user: NonZeroUsize,
    /// How often the background reaper runs; 0 disables it.
    pub reaper_interval_seconds: u64,
}

/// Limits on generating thumbnails. At most `concurrency` images are decoded
/// at once, each using at most `max_decode_memory`, so decoding never needs
/// more than their product.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ThumbnailConfig {
    /// Most thumbnails generated at once; 70% of the workers when unset.
    pub concurrency: Option<NonZeroUsize>,
    /// Most memory one image may need to decode. Larger images get no
    /// thumbnail.
    pub max_decode_memory: ByteUnit,
}

/// Connection pool and SQLite settings for each user's database.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DbConfig {
    pub min_connections: u32,
    pub max_connections: NonZeroU32,
    pub idle_timeout_seconds: NonZeroU64,
    pub busy_timeout_ms: u64,
    pub synchronous_mode: SyncMode,
    pub cache_size_kb: u32,
    pub temp_store: TempStore,
    pub journal_size_limit_bytes: u64,
    pub connection_timeout_seconds: NonZeroU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum RocketLogLevel {
    Off,
    Critical,
    Normal,
    Debug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum SyncMode {
    Off,
    Normal,
    Full,
    Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum TempStore {
    Default,
    File,
    Memory,
}

/// Parses each listed name, in any case, into its variant.
macro_rules! parse_names {
    ($ty:ident { $($name:literal => $variant:ident),+ $(,)? }) => {
        impl TryFrom<String> for $ty {
            type Error = String;

            fn try_from(value: String) -> Result<Self, String> {
                $(
                    if value.eq_ignore_ascii_case($name) {
                        return Ok(Self::$variant);
                    }
                )+

                Err(format!(
                    "unknown value '{}', expected one of: {}",
                    value,
                    [$($name),+].join(", ")
                ))
            }
        }
    };
}

parse_names!(LogLevel {
    "Off" => Off,
    "Error" => Error,
    "Warn" => Warn,
    "Info" => Info,
    "Debug" => Debug,
    "Trace" => Trace,
});

parse_names!(RocketLogLevel {
    "Off" => Off,
    "Critical" => Critical,
    "Normal" => Normal,
    "Debug" => Debug,
});

parse_names!(SyncMode {
    "OFF" => Off,
    "NORMAL" => Normal,
    "FULL" => Full,
    "EXTRA" => Extra,
});

parse_names!(TempStore {
    "DEFAULT" => Default,
    "FILE" => File,
    "MEMORY" => Memory,
});

impl LogLevel {
    pub fn filter(self) -> LevelFilter {
        match self {
            Self::Off => LevelFilter::Off,
            Self::Error => LevelFilter::Error,
            Self::Warn => LevelFilter::Warn,
            Self::Info => LevelFilter::Info,
            Self::Debug => LevelFilter::Debug,
            Self::Trace => LevelFilter::Trace,
        }
    }
}

impl RocketLogLevel {
    pub fn filter(self) -> LevelFilter {
        match self {
            Self::Off => LevelFilter::Off,
            Self::Critical => LevelFilter::Error,
            Self::Normal => LevelFilter::Info,
            Self::Debug => LevelFilter::Debug,
        }
    }
}

impl SyncMode {
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Off => "OFF",
            Self::Normal => "NORMAL",
            Self::Full => "FULL",
            Self::Extra => "EXTRA",
        }
    }
}

impl TempStore {
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Default => "DEFAULT",
            Self::File => "FILE",
            Self::Memory => "MEMORY",
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            limits: LimitsConfig::default(),
            session: SessionConfig::default(),
            db: DbConfig::default(),
            thumbnail: ThumbnailConfig::default(),
            user_data_path: PathBuf::from("./user_data"),
            minimum_password_security_score: 4,
            secure_cookies: true,
            allow_origin: None,
            admin_api_key: None,
            max_active_uploads: None,
            upload_ttl_seconds: NonZeroU64::new(24 * 60 * 60).unwrap(),
            orphan_scan_enabled: false,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 8000,
            workers: NonZeroUsize::new(16).unwrap(),
            keep_alive: 5,
            secret_key: None,
            tls_cert_path: None,
            tls_key_path: None,
            log_level: LogLevel::Warn,
            rocket_log_level: RocketLogLevel::Critical,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            form: 10.mebibytes(),
            data_form: 10.mebibytes(),
            file: 64.gibibytes(),
            file_chunk: 32.mebibytes(),
            json: 10.mebibytes(),
            msgpack: 1.mebibytes(),
            file_jpg: 10.gibibytes(),
            bytes: 10.mebibytes(),
            string: 10.mebibytes(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_seconds: NonZeroU64::new(60 * 60).unwrap(),
            max_lifetime_seconds: NonZeroU64::new(7 * 24 * 60 * 60).unwrap(),
            max_per_user: NonZeroUsize::new(5).unwrap(),
            reaper_interval_seconds: 0,
        }
    }
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            min_connections: 0,
            max_connections: NonZeroU32::new(16).unwrap(),
            idle_timeout_seconds: NonZeroU64::new(600).unwrap(),
            busy_timeout_ms: 60_000,
            synchronous_mode: SyncMode::Normal,
            cache_size_kb: 16_000,
            temp_store: TempStore::Memory,
            journal_size_limit_bytes: 64 * 1024 * 1024,
            connection_timeout_seconds: NonZeroU64::new(30).unwrap(),
        }
    }
}

impl Default for ThumbnailConfig {
    fn default() -> Self {
        Self {
            concurrency: None,
            // Enough for a 64-megapixel RGB photo.
            max_decode_memory: 256.mebibytes(),
        }
    }
}

impl LimitsConfig {
    pub fn to_rocket(&self) -> Limits {
        Limits::default()
            .limit("form", self.form)
            .limit("data-form", self.data_form)
            .limit("file", self.file)
            .limit("file-chunk", self.file_chunk)
            .limit("json", self.json)
            .limit("msgpack", self.msgpack)
            .limit("file/jpg", self.file_jpg)
            .limit("bytes", self.bytes)
            .limit("string", self.string)
    }
}

impl AppConfig {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(
            env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
        )
    }

    /// Reads the configuration from `JUSTENCRYPT_*` name/value pairs; other
    /// names, and `JUSTENCRYPT_*` names the server doesn't know, are ignored.
    /// An empty value counts as unset.
    pub fn from_vars<I>(vars: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut figment = Figment::new();

        for (name, value) in vars {
            let Some(short_name) = name.strip_prefix(ENV_PREFIX) else {
                continue;
            };
            let value = value.trim();

            if value.is_empty() {
                continue;
            }

            let Some((_, key)) = ENV_KEYS.iter().find(|(n, _)| *n == short_name) else {
                continue;
            };

            figment = figment.merge(Serialized::default(key, value));
        }

        // Every value arrives as a string; the lossy extraction turns "8000"
        // and "true" into the numbers and booleans the fields expect.
        let config: Self = figment.extract_lossy().map_err(describe_errors)?;

        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |name: &str, message: &str| {
            Err(ConfigError::Invalid(format!(
                "{ENV_PREFIX}{name}: {message}"
            )))
        };

        if self.minimum_password_security_score > 4 {
            return invalid("MINIMUM_PASSWORD_SECURITY_SCORE", "must be between 0 and 4");
        }

        if self.db.min_connections > self.db.max_connections.get() {
            return invalid(
                "MIN_DB_CONNECTIONS_PER_USER",
                "must not be larger than JUSTENCRYPT_MAX_DB_CONNECTIONS_PER_USER",
            );
        }

        if self.server.tls_cert_path.is_some() != self.server.tls_key_path.is_some() {
            return invalid(
                "TLS_CERT_PATH",
                "JUSTENCRYPT_TLS_CERT_PATH and JUSTENCRYPT_TLS_KEY_PATH must be set together",
            );
        }

        if let Some(origin) = &self.allow_origin {
            if origin == "*" {
                return invalid(
                    "ALLOW_ORIGIN",
                    "must be a single origin; browsers don't allow `*` with credentials",
                );
            }

            if !is_origin(origin) {
                return invalid(
                    "ALLOW_ORIGIN",
                    "must be an origin such as https://app.example.com, with no path or trailing slash",
                );
            }
        }

        if !cfg!(debug_assertions) && self.server.secret_key.is_none() {
            return invalid("ROCKET_SECRET_KEY", "must be set in release builds");
        }

        Ok(())
    }

    /// Rocket's own settings: address, port, workers, keep-alive, body
    /// limits, secret key and TLS. Responses get no `Server` header.
    pub fn rocket_figment(&self) -> Figment {
        let server = &self.server;

        let mut figment = Config::figment()
            .merge(("address", server.address))
            .merge(("port", server.port))
            .merge(("workers", server.workers))
            .merge(("keep_alive", server.keep_alive))
            .merge(("ident", false))
            .merge(("limits", self.limits.to_rocket()));

        if let Some(secret_key) = &server.secret_key {
            figment = figment.merge(("secret_key", secret_key.expose_secret()));
        }

        if let (Some(cert), Some(key)) = (&server.tls_cert_path, &server.tls_key_path) {
            figment = figment.merge(("tls", TlsConfig::from_paths(cert, key)));
        }

        figment
    }

    /// How many thumbnails may be generated at once.
    pub fn thumbnail_concurrency(&self) -> usize {
        match self.thumbnail.concurrency {
            Some(concurrency) => concurrency.get(),
            None => (self.server.workers.get() * 7 / 10).max(1),
        }
    }

    pub fn upload_ttl(&self) -> Duration {
        Duration::from_secs(self.upload_ttl_seconds.get())
    }
}

// Whether `value` has the form of a web origin: an http(s) scheme and a host,
// optionally with a port, and nothing after it. Browsers send the `Origin`
// header in exactly this form, so anything else could never match.
fn is_origin(value: &str) -> bool {
    let Some(host) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };

    !host.is_empty() && !host.contains(['/', '?', '#', ' '])
}

// Reports each error against the environment variable it came from.
fn describe_errors(errors: rocket::figment::Error) -> ConfigError {
    let messages: Vec<String> = errors
        .into_iter()
        .map(|e| {
            let key = e.path.join(".");

            match ENV_KEYS.iter().find(|(_, k)| *k == key) {
                Some((name, _)) => format!("{ENV_PREFIX}{name}: {}", e.kind),
                None => e.to_string(),
            }
        })
        .collect();

    ConfigError::Invalid(messages.join("; "))
}
