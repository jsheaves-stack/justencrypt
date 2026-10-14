use std::io;

use thiserror::Error;

use crate::enums::{
    blocking_error::{is_busy, BlockingError},
    db_error::DbError,
    encryption_error::EncryptionError,
};

/// Why an operation failed. The web layer maps each one to a status code.
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Failed to find session id")]
    MissingSessionId,

    #[error("Failed to find an active session for this session id")]
    MissingActiveSession,

    #[error("Password does not meet security requirements")]
    PasswordDoesNotMeetRequirements,

    #[error("Failed to process data")]
    FailedToProcessData,

    #[error("Unsupported file type")]
    UnsupportedFileType,

    #[error("Image is too large to process")]
    ImageTooLarge,

    #[error("Invalid API key")]
    InvalidApiKey,

    #[error("Not found")]
    NotFound,

    #[error("Unauthorized")]
    InvalidCredentials,

    #[error("Bad request: {0}")]
    InvalidInput(String),

    #[error("Range not satisfiable")]
    RangeNotSatisfiable { total_size: u64 },

    #[error("Internal server error")]
    Internal,

    #[error("Too many active uploads")]
    TooManyActiveUploads,

    #[error("Too many active downloads")]
    TooManyActiveDownloads,

    /// The user's own work in progress kept this request waiting too long.
    #[error("Too many requests in progress; try again later")]
    Busy,

    #[error("Payload too large")]
    TooLarge,

    #[error("Account already exists")]
    AccountAlreadyExists,

    #[error("Conflict: {0}")]
    Conflict(String),
}

impl From<DbError> for ServiceError {
    fn from(error: DbError) -> Self {
        match error {
            DbError::NotFound => ServiceError::NotFound,
            DbError::Busy => ServiceError::Busy,
            DbError::UserDoesNotExist => ServiceError::InvalidCredentials,
            DbError::InvalidInput(msg) => ServiceError::InvalidInput(msg),
            DbError::Conflict(msg) => ServiceError::Conflict(msg),
            DbError::MissingFileName => ServiceError::InvalidInput("Missing file name".into()),
            DbError::InvalidPath => ServiceError::InvalidInput("Invalid path".into()),
            _ => ServiceError::Internal,
        }
    }
}

impl From<EncryptionError> for ServiceError {
    fn from(error: EncryptionError) -> Self {
        match error {
            EncryptionError::TooLarge => ServiceError::TooLarge,
            EncryptionError::InvalidOffset(msg) => ServiceError::InvalidInput(msg),
            EncryptionError::Io(e) if is_busy(&e) => ServiceError::Busy,
            e => {
                error!("Encryption error: {}", e);

                ServiceError::FailedToProcessData
            },
        }
    }
}

impl From<BlockingError> for ServiceError {
    fn from(error: BlockingError) -> Self {
        match error {
            BlockingError::Busy => {
                warn!("{}", error);

                ServiceError::Busy
            },
            BlockingError::Failed(_) => {
                error!("{}", error);

                ServiceError::Internal
            },
        }
    }
}

/// For a failed file operation the caller has already logged.
impl From<io::Error> for ServiceError {
    fn from(error: io::Error) -> Self {
        if is_busy(&error) {
            ServiceError::Busy
        } else {
            ServiceError::FailedToProcessData
        }
    }
}
