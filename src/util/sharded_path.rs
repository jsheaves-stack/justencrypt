use rocket::tokio::fs;
use std::{
    error::Error,
    path::{Path, PathBuf},
};

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

pub async fn get_sharded_path(mut user_path: PathBuf, file_name: &String) -> PathBuf {
    if file_name.len() >= 4 {
        user_path.push(&file_name[0..2]);
        user_path.push(&file_name[2..4]);
    }

    user_path.push(file_name);

    user_path
}
