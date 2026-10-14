use std::collections::BTreeMap;

use crate::{encryption::CHUNK_SIZE, enums::service_error::ServiceError};

const MAX_REPORTED_MISSING_CHUNKS: usize = 100;

/// Checks that the chunks uploaded so far make up exactly `total_size`
/// plaintext bytes: every chunk from the first to the last is present, every
/// chunk but the last is full, and nothing lies past the end.
pub fn check_uploaded_chunks(
    chunks: &BTreeMap<u64, u32>,
    total_size: u64,
) -> Result<(), ServiceError> {
    let chunk_size = CHUNK_SIZE as u64;
    let expected_chunks = total_size.div_ceil(chunk_size);
    let present = chunks.range(..expected_chunks).count() as u64;

    if present < expected_chunks {
        let missing_count = expected_chunks - present;
        let missing: Vec<u64> = (0..expected_chunks)
            .filter(|i| !chunks.contains_key(i))
            .take(MAX_REPORTED_MISSING_CHUNKS)
            .collect();
        let mut message = format!("Missing chunks: {:?}", missing);

        if missing_count > missing.len() as u64 {
            message.push_str(&format!(
                " (and {} more)",
                missing_count - missing.len() as u64
            ));
        }

        return Err(ServiceError::InvalidInput(message));
    }

    let size_mismatch =
        || ServiceError::InvalidInput("total_size does not match uploaded data".to_string());

    if chunks.len() as u64 != expected_chunks {
        return Err(size_mismatch());
    }

    for (&index, &len) in chunks {
        let is_last = index + 1 == expected_chunks;
        let expected_len = if is_last {
            total_size - index * chunk_size
        } else {
            chunk_size
        };

        if len as u64 != expected_len {
            if is_last {
                return Err(size_mismatch());
            }

            return Err(ServiceError::InvalidInput(format!(
                "Chunk {} is incomplete: expected {} bytes, got {}",
                index, expected_len, len
            )));
        }
    }

    Ok(())
}
