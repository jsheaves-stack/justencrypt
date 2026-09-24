pub const MAX_ENTRY_NAME_BYTES: usize = 255;

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
