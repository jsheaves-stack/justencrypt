use crate::{enums::request_error::RequestError, util::range::parse_range};

fn range(header: &str, total_size: u64) -> Option<(u64, u64)> {
    parse_range(header, total_size).expect("range should be accepted")
}

fn is_unsatisfiable(header: &str, total_size: u64) -> bool {
    matches!(
        parse_range(header, total_size),
        Err(RequestError::RangeNotSatisfiable { total_size: t }) if t == total_size
    )
}

#[test]
fn test_parse_range_first_and_last_positions() {
    assert_eq!(range("bytes=0-99", 1000), Some((0, 99)));
    assert_eq!(range("bytes=5-", 10), Some((5, 9)));
    // An end past the file is cut short.
    assert_eq!(range("bytes=5-1000", 10), Some((5, 9)));
    assert_eq!(range("bytes= 2-3 ", 10), Some((2, 3)));
}

// M11f: `bytes=-N` asks for the last N bytes; it used to be a 400.
#[test]
fn test_parse_range_suffix() {
    assert_eq!(range("bytes=-3", 10), Some((7, 9)));
    // Asking for more than the file has gives the whole file.
    assert_eq!(range("bytes=-500", 10), Some((0, 9)));
    assert!(is_unsatisfiable("bytes=-0", 10));
    assert!(is_unsatisfiable("bytes=-5", 0));
}

// M11f: several ranges used to be a 400; the server may send the whole file
// instead (RFC 9110, section 14.2).
#[test]
fn test_parse_range_ignores_multiple_ranges() {
    assert_eq!(range("bytes=0-1,5-6", 10), None);
    assert_eq!(range("bytes=0-1, -2", 10), None);
}

// M11f: a server must ignore a range unit it doesn't understand; it used to
// be a 400.
#[test]
fn test_parse_range_ignores_other_units() {
    assert_eq!(range("items=0-5", 10), None);
    assert_eq!(range("0-5", 10), None);
}

#[test]
fn test_parse_range_unsatisfiable() {
    assert!(is_unsatisfiable("bytes=10-20", 10));
    assert!(is_unsatisfiable("bytes=10-", 10));
    assert!(is_unsatisfiable("bytes=6-5", 10));
    assert!(is_unsatisfiable("bytes=0-", 0));
}

#[test]
fn test_parse_range_malformed() {
    for header in ["bytes=", "bytes=-", "bytes=a-5", "bytes=0-b", "bytes=1-2-3"] {
        assert!(
            matches!(parse_range(header, 10), Err(RequestError::BadRequest(_))),
            "{header}"
        );
    }
}
