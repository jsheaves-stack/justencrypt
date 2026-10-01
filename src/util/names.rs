use std::path::{Component, Path};

pub const MAX_ENTRY_NAME_BYTES: usize = 255;

/// The error message for a name that fails [`is_valid_entry_name`].
pub const INVALID_ENTRY_NAME_MESSAGE: &str = "Names must be 1-255 bytes, not '.' or '..', and must not contain '/', '\\' or control characters";

/// Whether `name` can be the name of a file or folder: non-empty, at most 255
/// bytes, not `.` or `..`, and free of path separators and control characters
/// (which would make the entry unreachable by path).
pub fn is_valid_entry_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ENTRY_NAME_BYTES
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

/// Whether every file and folder name in `path` is a valid entry name. `.`,
/// `..` and empty segments are skipped, as path resolution skips them.
pub fn is_valid_entry_path(path: &str) -> bool {
    Path::new(path.trim_matches('/'))
        .components()
        .all(|component| match component {
            Component::Normal(name) => name.to_str().is_some_and(is_valid_entry_name),
            _ => true,
        })
}
