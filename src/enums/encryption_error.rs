use std::{io, time::Duration};

use orion::errors::UnknownCryptoError;
use thiserror::Error;

/// Why encrypting or decrypting a file failed.
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Cryptography error: {0}")]
    Crypto(#[from] UnknownCryptoError),
    #[error(
        "Tampering detected! Index mismatch at chunk {expected}: expected {expected}, got {got}"
    )]
    TamperingDetected { expected: u64, got: u64 },
    #[error("Chunk {0} is malformed (too short)")]
    MalformedChunk(u64),
    #[error("Invalid offset: {0}")]
    InvalidOffset(String),
    #[error("Data exceeds the maximum allowed size")]
    TooLarge,
    #[error("Encrypted file is truncated: expected {expected} plaintext bytes, got {got}")]
    Truncated { expected: u64, got: u64 },
    #[error("Unsupported encryption format version {0}")]
    UnsupportedVersion(i32),
    #[error("The client read nothing for {0:?}")]
    Stalled(Duration),
}
