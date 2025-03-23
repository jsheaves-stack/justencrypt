use std::path::{Component, Path};

use encryption::{FileEncryptionMetadata, SecretKey};
use image::EncodableLayout;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

pub fn get_schema() -> &'static str {
    "
      BEGIN;
      
      CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_folder_id INTEGER,
        name TEXT NOT NULL,
        FOREIGN KEY (parent_folder_id) REFERENCES folders(id),
        UNIQUE(parent_folder_id, name)
      );

      CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_folder_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        encoded_name TEXT NOT NULL,
        key BLOB NOT NULL,
        buffer_size INTEGER NOT NULL,
        nonce_size INTEGER NOT NULL,
        salt_size INTEGER NOT NULL,
        tag_size INTEGER NOT NULL,
        FOREIGN KEY (parent_folder_id) REFERENCES folders(id),
        UNIQUE(parent_folder_id, name)
      );

      INSERT OR IGNORE INTO folders (id, parent_folder_id, name) VALUES (1, NULL, 'ROOT');

      COMMIT;
    "
}

fn get_folder_id_and_create_if_missing(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<i32, rusqlite::Error> {
    let path = Path::new(folder_path_str.trim_matches('/'));
    let mut current_id = 1;

    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name.to_string_lossy().to_string(),
            Component::RootDir => continue,
            _ => continue,
        };

        let folder_id = db
            .query_row(
                "SELECT id FROM folders WHERE parent_folder_id = ?1 AND name = ?2",
                params![current_id, name],
                |row| row.get(0),
            )
            .optional()?;

        current_id = match folder_id {
            Some(id) => id,
            None => {
                db.execute(
                    "INSERT INTO folders (parent_folder_id, name) VALUES (?1, ?2)",
                    params![current_id, name],
                )?;

                db.query_row("SELECT last_insert_rowid()", [], |row| row.get(0))?
            }
        };
    }

    Ok(current_id)
}

pub fn get_folder_id(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<Option<i32>, rusqlite::Error> {
    let path = Path::new(folder_path_str.trim_matches('/'));
    let mut current_id = 1; // Start from ROOT

    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name.to_string_lossy().to_string(),
            Component::RootDir => continue,
            _ => continue,
        };

        let maybe_id: Option<i32> = db
            .query_row(
                "SELECT id FROM folders WHERE parent_folder_id = ?1 AND name = ?2",
                params![current_id, name],
                |row| row.get(0),
            )
            .optional()?;

        match maybe_id {
            Some(id) => current_id = id,
            None => return Ok(None),
        }
    }

    Ok(Some(current_id))
}

pub fn add_file(
    db_pool: &Pool<SqliteConnectionManager>,
    full_file_path: &str,
    encoded_file_name: &str,
    key: &[u8],
    buffer_size: usize,
    nonce_size: usize,
    salt_size: usize,
    tag_size: usize,
) -> Result<(), rusqlite::Error> {
    let db = db_pool.get().expect("failed to get DB connection");

    let path = Path::new(full_file_path.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let file_name = path
        .file_name()
        .expect("Missing file name")
        .to_string_lossy();

    let parent_folder_id =
        get_folder_id_and_create_if_missing(&db, &parent_path.to_string_lossy())?;

    db.execute(
        "INSERT INTO files 
      (parent_folder_id, name, encoded_name, key, buffer_size, nonce_size, salt_size, tag_size) 
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            parent_folder_id,
            file_name,
            encoded_file_name,
            key,
            buffer_size,
            nonce_size,
            salt_size,
            tag_size
        ],
    )?;

    Ok(())
}

pub fn get_file(
    db_pool: &Pool<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<FileEncryptionMetadata, rusqlite::Error> {
    let db = db_pool.get().expect("failed to get DB connection");

    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));

    let parent_folder_id = get_folder_id(&db, parent_path.to_str().unwrap())
        .unwrap()
        .unwrap();

    let path = Path::new(file_path_str.trim_matches('/'));
    let file_name = path
        .file_name()
        .expect("Missing file name")
        .to_string_lossy();

    let result = db.query_row(
        "SELECT key, buffer_size, nonce_size, salt_size, tag_size
       FROM files
       WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| {
            let key_blob: Vec<u8> = row.get(0)?;
            Ok(FileEncryptionMetadata {
                key: SecretKey::from_slice(&key_blob).unwrap(),
                buffer_size: row.get(1)?,
                nonce_size: row.get(2)?,
                salt_size: row.get(3)?,
                tag_size: row.get(4)?,
            })
        },
    )?;

    Ok(result)
}

pub fn add_folder(
    db_pool: &Pool<SqliteConnectionManager>,
    path_str: &str,
) -> Result<(), rusqlite::Error> {
    let db = db_pool.get().expect("failed to get DB connection");
    get_folder_id_and_create_if_missing(&db, &path_str)?;

    Ok(())
}
