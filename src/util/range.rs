use crate::enums::request_error::RequestError;

/// Parses a `Range` header for a file of `total_size` bytes into the inclusive
/// byte range to send.
///
/// Returns `None` when the whole file should be sent instead: for a unit
/// other than `bytes`, which a server must ignore, and for several ranges,
/// which a server may ignore (RFC 9110, section 14.2). A range that starts at
/// or past the end of the file, or asks for no bytes, is not satisfiable.
pub fn parse_range(range_str: &str, total_size: u64) -> Result<Option<(u64, u64)>, RequestError> {
    let Some(ranges) = range_str.trim().strip_prefix("bytes=") else {
        return Ok(None);
    };

    if ranges.contains(',') {
        return Ok(None);
    }

    let not_satisfiable = || RequestError::RangeNotSatisfiable { total_size };
    let (first, last) = ranges
        .trim()
        .split_once('-')
        .ok_or_else(|| RequestError::BadRequest("Invalid Range format".into()))?;
    let parse = |value: &str, what: &str| {
        value
            .parse::<u64>()
            .map_err(|_| RequestError::BadRequest(format!("Invalid range {what}")))
    };

    // `bytes=-N`: the last N bytes.

    if first.is_empty() {
        let suffix_length = parse(last, "suffix length")?;

        if suffix_length == 0 || total_size == 0 {
            return Err(not_satisfiable());
        }

        return Ok(Some((
            total_size.saturating_sub(suffix_length),
            total_size - 1,
        )));
    }

    let start = parse(first, "start")?;
    let end = if last.is_empty() {
        total_size.saturating_sub(1)
    } else {
        parse(last, "end")?
    };

    if start > end || start >= total_size {
        return Err(not_satisfiable());
    }

    Ok(Some((start, end.min(total_size - 1))))
}
