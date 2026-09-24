use rocket::http::Status;

use crate::enums::request_error::RequestError;

pub fn parse_range(range_str: &str, total_size: u64) -> Result<(u64, u64, Status), RequestError> {
    if !range_str.starts_with("bytes=") {
        return Err(RequestError::BadRequest("Invalid Range header".into()));
    }

    let range_val = &range_str[6..];
    let parts: Vec<&str> = range_val.split('-').collect();

    if parts.len() != 2 {
        return Err(RequestError::BadRequest("Invalid Range format".into()));
    }

    let start = parts[0]
        .parse::<u64>()
        .map_err(|_| RequestError::BadRequest("Invalid range start".into()))?;
    let end = if parts[1].is_empty() {
        total_size.saturating_sub(1)
    } else {
        parts[1]
            .parse::<u64>()
            .map_err(|_| RequestError::BadRequest("Invalid range end".into()))?
    };

    if start > end || start >= total_size {
        return Err(RequestError::RangeNotSatisfiable { total_size });
    }
    Ok((start, end.min(total_size - 1), Status::PartialContent))
}
