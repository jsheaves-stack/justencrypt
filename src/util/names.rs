use std::path::{Component, Path};

/// The longest username accepted.
pub const MAX_USERNAME_BYTES: usize = 64;

/// The longest file or folder name accepted.
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

/// Whether every `/`-separated segment of `path` is a valid entry name, with
/// no empty, `.` or `..` segments, so the path stays inside the directory it
/// is extracted to. One trailing `/` (a directory) is allowed.
pub fn is_valid_relative_path(path: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);

    path.split('/').all(is_valid_entry_name)
}

/// A username becomes a directory and file name, so it must be non-empty, at
/// most 64 bytes, and free of path separators, dots and control characters.
pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_USERNAME_BYTES
        && !username.contains(['/', '\\', '.'])
        && !username.chars().any(char::is_control)
}
