use rocket::data::{ByteUnit, Data, DataStream, Limits};

const DEFAULT_MAX_FILE_SIZE: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_MAX_CHUNK_REQUEST_SIZE: u64 = 32 * 1024 * 1024;

/// Largest file, in plaintext bytes, that may be stored. Configured through
/// Rocket's `file` limit (`JUSTENCRYPT_LIMITS_FILE`).
pub fn max_file_size(limits: &Limits) -> u64 {
    limits
        .get("file")
        .map(|limit| limit.as_u64())
        .unwrap_or(DEFAULT_MAX_FILE_SIZE)
}

/// Most bytes a single chunk-upload request may carry. Configured through
/// Rocket's `file-chunk` limit (`JUSTENCRYPT_LIMITS_FILE_CHUNK`).
pub fn max_chunk_request_size(limits: &Limits) -> u64 {
    limits
        .get("file-chunk")
        .map(|limit| limit.as_u64())
        .unwrap_or(DEFAULT_MAX_CHUNK_REQUEST_SIZE)
}

/// Opens a request body so that reading more than `max_bytes` is detectable:
/// Rocket ends the stream silently at its limit, so the limit is one byte
/// higher and the encryptor reports the overflow.
pub fn open_with_limit(data: Data<'_>, max_bytes: u64) -> DataStream<'_> {
    data.open(ByteUnit::Byte(max_bytes.saturating_add(1)))
}
