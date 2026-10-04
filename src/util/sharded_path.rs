use std::{
    error::Error,
    path::{Path, PathBuf},
};

use rocket::tokio::fs;

pub async fn remove_sharded_path(base_path: &Path, file_path: &Path) -> Result<(), Box<dyn Error>> {
    fs::remove_file(file_path).await?;

    let mut current_dir = file_path.parent();

    while let Some(dir) = current_dir {
        if dir == base_path {
            break;
        }

        if fs::read_dir(dir).await?.next_entry().await?.is_none() {
            fs::remove_dir(dir).await?;
        } else {
            break;
        }
        current_dir = dir.parent();
    }
    Ok(())
}

pub async fn get_sharded_path(user_path: PathBuf, file_name: &str) -> PathBuf {
    sharded_path(user_path, file_name)
}

/// Where the blob `file_name` is stored under `user_path`. A synchronous
/// version of [`get_sharded_path`], for blocking threads.
pub fn sharded_path(mut user_path: PathBuf, file_name: &str) -> PathBuf {
    if file_name.len() >= 4 {
        user_path.push(&file_name[0..2]);
        user_path.push(&file_name[2..4]);
    }

    user_path.push(file_name);

    user_path
}

/// Deletes a blob that no database row references any more, together with its
/// cached thumbnail. Failures are only logged: the row is already gone, so as
/// far as the user is concerned the file is too.
pub async fn remove_blob_and_thumbnail(user_path: &Path, encoded_name: &str) {
    let encoded_name = encoded_name.to_string();
    let blob_path = get_sharded_path(user_path.to_path_buf(), &encoded_name).await;
    let thumb_path = get_sharded_path(user_path.join(".cache"), &encoded_name).await;

    if let Err(e) = remove_sharded_path(user_path, &blob_path).await {
        if is_not_found(e.as_ref()) {
            warn!("Blob {} was already missing from disk", encoded_name);
        } else {
            error!("Failed to delete blob {}: {}", encoded_name, e);
        }
    }

    // Most files have no thumbnail, so a missing one is expected.

    if let Err(e) = remove_sharded_path(user_path, &thumb_path).await {
        if !is_not_found(e.as_ref()) {
            warn!("Failed to delete thumbnail for {}: {}", encoded_name, e);
        }
    }
}

/// Whether an error from `remove_sharded_path` means the file was already gone.
pub fn is_not_found(e: &(dyn Error + 'static)) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}

/// Waits until the directory containing `path` is on disk, which makes a
/// rename or file creation inside it survive a crash or power loss.
pub async fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let Some(dir) = path.parent().map(Path::to_path_buf) else {
        return Ok(());
    };

    rocket::tokio::task::spawn_blocking(move || std::fs::File::open(dir)?.sync_all())
        .await
        .map_err(std::io::Error::other)?
}
