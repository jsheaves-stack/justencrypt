use std::io;

use thiserror::Error;

/// Why blocking work done for a user couldn't run.
#[derive(Debug, Error)]
pub enum BlockingError {
    /// The user's connections or blocking threads stayed busy for the whole
    /// connection timeout: the user has too much work in progress.
    #[error("Timed out waiting for the user's other work to finish")]
    Busy,

    #[error("Blocking task failed: {0}")]
    Failed(String),
}

impl From<BlockingError> for io::Error {
    fn from(error: BlockingError) -> Self {
        io::Error::other(error)
    }
}

/// Whether an I/O error is a [`BlockingError::Busy`] passed along as one.
pub fn is_busy(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<BlockingError>())
        .is_some_and(|inner| matches!(inner, BlockingError::Busy))
}
