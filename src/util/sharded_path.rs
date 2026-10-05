use std::path::PathBuf;

/// Where the file `file_name` is stored under `base`: two directory levels
/// down, named by its first four characters, so no single directory ends up
/// holding every file.
pub fn sharded_path(mut base: PathBuf, file_name: &str) -> PathBuf {
    if file_name.len() >= 4 {
        base.push(&file_name[0..2]);
        base.push(&file_name[2..4]);
    }

    base.push(file_name);

    base
}
