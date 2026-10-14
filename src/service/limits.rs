use tokio::io::{AsyncRead, AsyncReadExt, Take};

use crate::config::LimitsConfig;

/// Largest file, in plaintext bytes, that may be stored
/// (`JUSTENCRYPT_LIMITS_FILE`).
pub fn max_file_size(limits: &LimitsConfig) -> u64 {
    limits.file.as_u64()
}

/// Most bytes a single chunk upload may carry
/// (`JUSTENCRYPT_LIMITS_FILE_CHUNK`).
pub fn max_chunk_request_size(limits: &LimitsConfig) -> u64 {
    limits.file_chunk.as_u64()
}

/// Reads `body` so that sending more than `max_bytes` is detectable: the
/// stream ends silently one byte past the limit, and the encryptor reports
/// that byte as too much.
pub fn read_with_limit<R: AsyncRead + Unpin>(body: R, max_bytes: u64) -> Take<R> {
    body.take(max_bytes.saturating_add(1))
}
