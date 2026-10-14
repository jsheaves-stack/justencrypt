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

use base64::{engine::general_purpose::STANDARD, Engine};
use figment::{providers::Serialized, Figment};
use log::LevelFilter;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use ubyte::{ByteUnit, ToByteUnit};

use crate::enums::config_error::ConfigError;

const ENV_PREFIX: &str = "JUSTENCRYPT_";

/// Every environment variable the server reads, without the `JUSTENCRYPT_`
/// prefix, and the [`AppConfig`] field its value goes to.
const ENV_KEYS: &[(&str, &str)] = &[
    ("ADDRESS", "http.address"),
    ("PORT", "http.port"),
    ("WORKERS", "runtime.workers"),
    ("MAX_BLOCKING_THREADS", "runtime.max_blocking_threads"),
    ("SECRET_KEY", "http.secret_key"),
    ("LOG_LEVEL", "runtime.log_level"),
    ("HTTP_LOG_LEVEL", "http.log_level"),
    ("LIMITS_FILE", "limits.file"),
    ("LIMITS_FILE_CHUNK", "limits.file_chunk"),
    ("LIMITS_JSON", "http.json_limit"),
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
    ("SECURE_COOKIES", "http.secure_cookies"),
    ("ALLOW_ORIGIN", "http.allow_origin"),
    ("ADMIN_API_KEY", "admin_api_key"),
    ("MAX_ACTIVE_UPLOADS", "max_active_uploads"),
    ("MAX_ACTIVE_DOWNLOADS", "max_active_downloads"),
    (
        "MAX_BLOCKING_THREADS_PER_USER",
        "max_blocking_threads_per_user",
    ),
    (
        "DOWNLOAD_STALL_TIMEOUT_SECONDS",
        "download_stall_timeout_seconds",
    ),
    ("UPLOAD_TTL_SECONDS", "upload_ttl_seconds"),
    ("ORPHAN_SCAN_ENABLED", "orphan_scan_enabled"),
];

/// The server's whole configuration, read from `JUSTENCRYPT_*` variables.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub runtime: RuntimeConfig,
    pub http: HttpConfig,
    pub limits: LimitsConfig,
    pub session: SessionConfig,
    pub db: DbConfig,
    pub thumbnail: ThumbnailConfig,
    /// Directory that holds one sub-directory per user.
    pub user_data_path: PathBuf,
    /// Minimum zxcvbn score (0-4) for the password of a new account.
    pub minimum_password_security_score: u8,
    /// Key for the admin routes, which are only mounted when it is set.
    pub admin_api_key: Option<SecretString>,
    /// Most uploads a session may have in progress; no limit when unset.
    pub max_active_uploads: Option<NonZeroUsize>,
    /// Most folder downloads that may run at once, across all users; no limit
    /// when unset. Each one holds a blocking thread and a database connection
    /// until it finishes.
    pub max_active_downloads: Option<NonZeroUsize>,
    /// Most blocking threads one user's requests may occupy at once; no limit
    /// when unset, so a single user may use all of them.
    pub max_blocking_threads_per_user: Option<NonZeroUsize>,
    /// How long a file or folder download may wait for the client to read
    /// more before it is abandoned, freeing what it holds.
    pub download_stall_timeout_seconds: NonZeroU64,
    /// How long an upload can sit idle before it is considered abandoned.
    pub upload_ttl_seconds: NonZeroU64,
    /// Whether every login starts a scan for the user's unreferenced files.
    pub orphan_scan_enabled: bool,
}

/// How many threads the server runs, and how much it logs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Threads that run requests.
    pub workers: NonZeroUsize,
    /// Threads for work that blocks (database queries, file access, image
    /// decoding), shared by every user.
    pub max_blocking_threads: NonZeroUsize,
    pub log_level: LogLevel,
}

/// Settings only the web layer reads: where it listens, its cookies, CORS,
/// request bodies and how the HTTP server logs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub address: IpAddr,
    pub port: u16,
    /// Encrypts the session cookies: 256 or 512 bits, as base64 or hex.
    /// Required in release builds; debug builds without one use a random key
    /// for each launch.
    pub secret_key: Option<SecretString>,
    /// How much the HTTP server and its libraries log.
    pub log_level: LogLevel,
    /// Whether session cookies are only sent over HTTPS.
    pub secure_cookies: bool,
    /// Value of the `Access-Control-Allow-Origin` header; none when unset.
    pub allow_origin: Option<String>,
    /// Largest JSON request body.
    pub json_limit: ByteUnit,
}

/// How large stored files and upload requests may be.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Largest file that may be stored.
    pub file: ByteUnit,
    /// Largest body of a single chunk-upload request.
    pub file_chunk: ByteUnit,
}

/// When sessions expire, how many a user may have, and how often expired ones
/// are cleared out.
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

/// How much the server itself logs.
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

/// SQLite's `synchronous` setting: how hard it waits for writes to reach the
/// disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum SyncMode {
    Off,
    Normal,
    Full,
    Extra,
}

/// SQLite's `temp_store` setting: where it keeps temporary tables and indexes.
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
    /// The level as the logger takes it.
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

impl SyncMode {
    /// The mode as written in a `PRAGMA synchronous` statement.
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
    /// The setting as written in a `PRAGMA temp_store` statement.
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
            runtime: RuntimeConfig::default(),
            http: HttpConfig::default(),
            limits: LimitsConfig::default(),
            session: SessionConfig::default(),
            db: DbConfig::default(),
            thumbnail: ThumbnailConfig::default(),
            user_data_path: PathBuf::from("./user_data"),
            minimum_password_security_score: 4,
            admin_api_key: None,
            max_active_uploads: None,
            max_active_downloads: None,
            max_blocking_threads_per_user: None,
            download_stall_timeout_seconds: NonZeroU64::new(60).unwrap(),
            upload_ttl_seconds: NonZeroU64::new(24 * 60 * 60).unwrap(),
            orphan_scan_enabled: false,
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            workers: NonZeroUsize::new(16).unwrap(),
            max_blocking_threads: NonZeroUsize::new(512).unwrap(),
            log_level: LogLevel::Warn,
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 8000,
            secret_key: None,
            log_level: LogLevel::Error,
            secure_cookies: true,
            allow_origin: None,
            json_limit: 10.mebibytes(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            file: 64.gibibytes(),
            file_chunk: 32.mebibytes(),
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

    /// Checks the values that are valid on their own but not together, or
    /// that need more than a type to check, naming the variable at fault.
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

        if let Some(origin) = &self.http.allow_origin {
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

        match &self.http.secret_key {
            Some(key) => {
                if let Err(message) = decode_secret_key(key.expose_secret()) {
                    return invalid("SECRET_KEY", &message);
                }
            },
            None if !cfg!(debug_assertions) => {
                return invalid("SECRET_KEY", "must be set in release builds");
            },
            None => {},
        }

        Ok(())
    }

    /// How many thumbnails may be generated at once.
    pub fn thumbnail_concurrency(&self) -> usize {
        match self.thumbnail.concurrency {
            Some(concurrency) => concurrency.get(),
            None => (self.runtime.workers.get() * 7 / 10).max(1),
        }
    }

    /// How long an upload can sit idle before it is considered abandoned.
    pub fn upload_ttl(&self) -> Duration {
        Duration::from_secs(self.upload_ttl_seconds.get())
    }

    /// How long a download may wait for the client to read more.
    pub fn download_stall_timeout(&self) -> Duration {
        Duration::from_secs(self.download_stall_timeout_seconds.get())
    }
}

/// The key material in a secret key setting: 256 or 512 bits, written as
/// base64 (44 or 88 characters) or hex (64 characters). A key of all zero
/// bytes is rejected.
pub fn decode_secret_key(value: &str) -> Result<Vec<u8>, String> {
    let bytes = match value.len() {
        44 | 88 => STANDARD
            .decode(value)
            .map_err(|_| "is not valid base64".to_string())?,
        64 => decode_hex(value).ok_or_else(|| "is not valid hex".to_string())?,
        n => {
            return Err(format!(
                "has {n} characters, but must be 44 or 88 (base64) or 64 (hex); generate one with \
                 `openssl rand -base64 32`"
            ))
        },
    };

    if bytes.len() < 32 {
        return Err("must be at least 256 bits".to_string());
    }

    if bytes.iter().all(|byte| *byte == 0) {
        return Err("must not be all zeros".to_string());
    }

    Ok(bytes)
}

// The bytes `hex` spells out, two digits each.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.is_ascii() {
        return None;
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
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
fn describe_errors(errors: figment::Error) -> ConfigError {
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
