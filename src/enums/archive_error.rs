use std::io;

use thiserror::Error;

use crate::enums::db_error::DbError;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error(transparent)]
    Db(#[from] DbError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Encrypted file {encoded_name} is truncated: expected {expected} bytes, got {got}")]
    Truncated {
        encoded_name: String,
        expected: u64,
        got: u64,
    },
}
