use crate::{enums::service_error::ServiceError, service::files::ByteRangeSpec};

/// Parses a `Range` header into the byte range it asks for. Whether the range
/// fits the file is checked later, against its size.
///
/// Returns `None` when the whole file should be sent instead: for a unit
/// other than `bytes`, which a server must ignore, and for several ranges,
/// which a server may ignore (RFC 9110, section 14.2).
pub fn parse_range(range_str: &str) -> Result<Option<ByteRangeSpec>, ServiceError> {
    let Some(ranges) = range_str.trim().strip_prefix("bytes=") else {
        return Ok(None);
    };

    if ranges.contains(',') {
        return Ok(None);
    }

    let (first, last) = ranges
        .trim()
        .split_once('-')
        .ok_or_else(|| ServiceError::InvalidInput("Invalid Range format".into()))?;
    let parse = |value: &str, what: &str| {
        value
            .parse::<u64>()
            .map_err(|_| ServiceError::InvalidInput(format!("Invalid range {what}")))
    };

    // `bytes=-N`: the last N bytes.

    if first.is_empty() {
        return Ok(Some(ByteRangeSpec::Suffix(parse(last, "suffix length")?)));
    }

    let start = parse(first, "start")?;

    if last.is_empty() {
        return Ok(Some(ByteRangeSpec::From(start)));
    }

    Ok(Some(ByteRangeSpec::FromTo(start, parse(last, "end")?)))
}
