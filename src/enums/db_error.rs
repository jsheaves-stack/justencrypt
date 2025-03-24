use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database error: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    #[error("Missing file name in path")]
    MissingFileName,

    #[error("Failed to convert path to str")]
    InvalidPath,

    #[error("Connection pool error: {0}")]
    PoolError(#[from] r2d2::Error),

    #[error("Thread join error: {0}")]
    ThreadJoinError(String),

    #[error("Failed to add file to db: {0}")]
    FailedToAddFileToDb(String),

    #[error("Failed to get folder id from the provided file path: {0}")]
    FailedToGetFolderIdFromPath(String),

    #[error("Failed to get file from the db: {0}")]
    FailedToGetFileFromDb(String),

    #[error("User does not exist")]
    UserDoesNotExist,
}
