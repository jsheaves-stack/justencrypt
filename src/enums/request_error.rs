use std::io;

use thiserror::Error;

use crate::enums::{
    blocking_error::{is_busy, BlockingError},
    db_error::DbError,
    encryption_error::EncryptionError,
};

/// Why a request failed. Each one maps to a status code in `web::responders`.
#[derive(Error, Debug)]
pub enum RequestError {
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
    Unauthorized,

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Range not satisfiable")]
    RangeNotSatisfiable { total_size: u64 },

    #[error("Internal server error")]
    InternalServerError,

    #[error("Too many active uploads")]
    TooManyActiveUploads,

    #[error("Too many active downloads")]
    TooManyActiveDownloads,

    /// The user's own work in progress kept this request waiting too long.
    #[error("Too many requests in progress; try again later")]
    Busy,

    #[error("Payload too large")]
    PayloadTooLarge,

    #[error("Account already exists")]
    AccountAlreadyExists,

    #[error("Conflict: {0}")]
    Conflict(String),
}

impl From<DbError> for RequestError {
    fn from(error: DbError) -> Self {
        match error {
            DbError::NotFound => RequestError::NotFound,
            DbError::Busy => RequestError::Busy,
            DbError::UserDoesNotExist => RequestError::Unauthorized,
            DbError::InvalidInput(msg) => RequestError::BadRequest(msg),
            DbError::Conflict(msg) => RequestError::Conflict(msg),
            DbError::MissingFileName => RequestError::BadRequest("Missing file name".into()),
            DbError::InvalidPath => RequestError::BadRequest("Invalid path".into()),
            _ => RequestError::InternalServerError,
        }
    }
}

impl From<EncryptionError> for RequestError {
    fn from(error: EncryptionError) -> Self {
        match error {
            EncryptionError::TooLarge => RequestError::PayloadTooLarge,
            EncryptionError::InvalidOffset(msg) => RequestError::BadRequest(msg),
            EncryptionError::Io(e) if is_busy(&e) => RequestError::Busy,
            e => {
                error!("Encryption error: {}", e);

                RequestError::FailedToProcessData
            },
        }
    }
}

impl From<BlockingError> for RequestError {
    fn from(error: BlockingError) -> Self {
        match error {
            BlockingError::Busy => {
                warn!("{}", error);

                RequestError::Busy
            },
            BlockingError::Failed(_) => {
                error!("{}", error);

                RequestError::InternalServerError
            },
        }
    }
}

/// For a failed file operation the caller has already logged.
impl From<io::Error> for RequestError {
    fn from(error: io::Error) -> Self {
        if is_busy(&error) {
            RequestError::Busy
        } else {
            RequestError::FailedToProcessData
        }
    }
}
