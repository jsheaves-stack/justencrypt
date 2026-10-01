use thiserror::Error;

/// A configuration value that could not be read or is out of range. The
/// message names the environment variable at fault.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
}
