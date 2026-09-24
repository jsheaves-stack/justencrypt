use thiserror::Error;

use crate::enums::{db_error::DbError, encryption_error::EncryptionError};

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

    #[error("Failed to write data")]
    FailedToWriteData,

    #[error("Failed to create user session")]
    FailedToCreateUserSession,

    #[error("Unsupported file type")]
    UnsupportedFileType,

    #[error("Failed to remove file")]
    FailedToRemoveFile,

    #[error("Failed to rename file")]
    FailedToRenameFile,

    #[error("Failed to move file")]
    FailedToMoveFile,

    #[error("Failed to add file")]
    FailedToAddFile,

    #[error("Failed to create folder")]
    FailedToCreateFolder,

    #[error("Failed to read folder contents")]
    FailedToReadFolderContents,

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

    #[error("Payload too large")]
    PayloadTooLarge,

    #[error("Account already exists")]
    AccountAlreadyExists,
}

impl From<DbError> for RequestError {
    fn from(error: DbError) -> Self {
        match error {
            DbError::NotFound => RequestError::NotFound,
            DbError::UserDoesNotExist => RequestError::Unauthorized,
            DbError::InvalidInput(msg) => RequestError::BadRequest(msg),
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
            e => {
                error!("Encryption error: {}", e);

                RequestError::FailedToProcessData
            },
        }
    }
}
