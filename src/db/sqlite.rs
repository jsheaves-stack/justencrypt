use encryption::{FileEncryptionMetadata, SecretKey};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::enums::db_error::DbError;

pub fn create_user_db_connection(
    db_path: PathBuf,
    password: SecretString,
) -> Result<Pool<SqliteConnectionManager>, DbError> {
    let db_manager = SqliteConnectionManager::file(db_path).with_init(move |conn| {
        conn.busy_timeout(Duration::from_millis(60000))?;

        let key_sql = format!("PRAGMA key = '{}';", password.expose_secret());
        let mut stmt = conn.prepare(&key_sql)?;
        let mut result_rows = stmt.query([])?;

        // Iterate through any rows returned to consume them.
        while let Some(_row) = result_rows.next()? {}

        match conn.query_row("PRAGMA journal_mode = WAL;", [], |row| row.get::<_, String>(0)) {
            Ok(mode) => {
                if mode.to_lowercase() != "wal" {
                    warn!("Attempted to set WAL journal_mode, but current mode is: {}. This might impact concurrency.", mode);
                } else {
                    info!("SQLite journal_mode set to WAL.");
                }
            }
            Err(e) => {
                warn!("Failed to set/query journal_mode to WAL: {}. Performance under load might be affected.",e);
            }
        }

        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(get_schema())
    });

    Ok(Pool::new(db_manager)?)
}

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
        file_extension TEXT,
        key BLOB NOT NULL,
        buffer_size INTEGER NOT NULL,
        nonce_size INTEGER NOT NULL,
        salt_size INTEGER NOT NULL,
        tag_size INTEGER NOT NULL,
        FOREIGN KEY (parent_folder_id) REFERENCES folders(id),
        UNIQUE(parent_folder_id, name),
        UNIQUE(encoded_name)
      );

      CREATE TABLE IF NOT EXISTS thumbnails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        encoded_name TEXT NOT NULL,
        file_id INTEGER,
        key BLOB NOT NULL,
        buffer_size INTEGER NOT NULL,
        nonce_size INTEGER NOT NULL,
        salt_size INTEGER NOT NULL,
        tag_size INTEGER NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
        UNIQUE(encoded_name)
      );

      INSERT OR IGNORE INTO folders (id, parent_folder_id, name) VALUES (1, NULL, 'ROOT');

      COMMIT;
    "
}

fn get_folder_id_and_create_if_missing(
    db: &mut PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<i32, DbError> {
    let path = Path::new(folder_path_str.trim_matches('/'));
    let mut current_id = 1;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name.to_string_lossy().to_string(),
            _ => continue,
        };

        let folder_id = match tx
            .query_row(
                "SELECT id FROM folders WHERE parent_folder_id = ?1 AND name = ?2",
                params![current_id, name],
                |row| row.get(0),
            )
            .optional()
        {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to get folder id from the provided path: {}", e);
                return Err(DbError::FailedToGetFolderIdFromPath(e.to_string()));
            }
        };

        current_id = match folder_id {
            Some(id) => id,
            None => {
                tx.execute(
                    "INSERT OR IGNORE INTO folders (parent_folder_id, name) VALUES (?1, ?2)",
                    params![current_id, name],
                )?;

                tx.query_row("SELECT last_insert_rowid()", [], |row| row.get(0))?
            }
        };
    }

    tx.commit()?;

    Ok(current_id)
}

pub fn get_folder_id(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<Option<i32>, DbError> {
    let path = Path::new(folder_path_str.trim_matches('/'));
    let mut current_id = 1;

    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name.to_string_lossy().to_string(),
            _ => continue,
        };

        let folder_id = match db
            .query_row(
                "SELECT id FROM folders WHERE parent_folder_id = ?1 AND name = ?2",
                params![current_id, name],
                |row| row.get(0),
            )
            .optional()
        {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to get folder id from the provided path: {}", e);
                return Err(DbError::FailedToGetFolderIdFromPath(e.to_string()));
            }
        };

        match folder_id {
            Some(id) => current_id = id,
            None => return Ok(None),
        }
    }

    Ok(Some(current_id))
}

pub fn get_encoded_file_name(
    db: &PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
) -> Result<String, DbError> {
    let path = Path::new(full_file_path.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;
    let parent_folder_id = get_folder_id(db, parent_str)?.ok_or(DbError::MissingFileName)?;

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let result = match db.query_row(
        "SELECT encoded_name FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| row.get(0),
    ) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to get encoded file name from the db: {}", e);
            return Err(DbError::FailedToGetFileFromDb(e.to_string()));
        }
    };

    Ok(result)
}

pub fn get_encoded_thumbnail_file_name(
    db: &PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
) -> Result<Option<String>, DbError> {
    let path = Path::new(full_file_path.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;

    let parent_folder_id = get_folder_id(db, parent_str)
        .map_err(|e| {
            error!(
                "Failed to get parent folder id for the provided path: {}",
                e
            );
            DbError::FailedToGetFolderIdFromPath(e.to_string())
        })?
        .ok_or_else(|| {
            error!("No folder id was returned from the db");
            DbError::FailedToGetFolderIdFromPath(
                "No folder id was returned from the db".to_string(),
            )
        })?;

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let file_id: i32 = db.query_row(
        "SELECT id FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| row.get(0),
    )?;

    let result = db
        .query_row(
            "SELECT encoded_name FROM thumbnails WHERE file_id = ?1",
            params![file_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            error!(
                "Failed to get encoded thumbnail file name from the db: {}",
                e
            );
            DbError::FailedToGetFileFromDb(e.to_string())
        })?;

    Ok(result)
}

pub fn add_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
    encoded_file_name: &str,
    metadata: FileEncryptionMetadata,
) -> Result<(), DbError> {
    let path = Path::new(full_file_path.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let file_extension = path
        .extension()
        .map(|ext| ext.to_string_lossy())
        .unwrap_or_default();

    let parent_folder_id = get_folder_id_and_create_if_missing(db, &parent_path.to_string_lossy())?;

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    tx.execute(
        r#"INSERT INTO files
            (parent_folder_id, name, encoded_name, file_extension, key, buffer_size, nonce_size, salt_size, tag_size)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
           ON CONFLICT(parent_folder_id, name) DO UPDATE SET
             encoded_name = excluded.encoded_name,
             file_extension = excluded.file_extension,
             key = excluded.key,
             buffer_size = excluded.buffer_size,
             nonce_size = excluded.nonce_size,
             salt_size = excluded.salt_size,
             tag_size = excluded.tag_size
        "#,
        params![
            parent_folder_id,
            file_name,
            encoded_file_name,
            file_extension,
            metadata.key.unprotected_as_bytes(),
            metadata.buffer_size,
            metadata.nonce_size,
            metadata.salt_size,
            metadata.tag_size
        ],
    ).map(|_| ())
    .map_err(|e| {
        error!("Failed to add or update file in the db: {}", e);
        DbError::FailedToAddFileToDb(e.to_string())
    })?;

    tx.commit()?;

    Ok(())
}

pub fn delete_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<(), DbError> {
    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let parent_folder_id = get_folder_id_and_create_if_missing(db, &parent_path.to_string_lossy())?;

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    tx.execute(
        "DELETE FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
    )
    .map(|_| ())
    .map_err(|e| {
        error!("Failed to delete file from the db: {}", e);
        DbError::FailedToDeleteFileFromDb(e.to_string())
    })?;

    tx.commit()?;

    Ok(())
}

pub fn get_file(
    db: &PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<FileEncryptionMetadata, DbError> {
    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;
    let parent_folder_id = get_folder_id(db, parent_str)?.ok_or(DbError::MissingFileName)?;

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let result = match db.query_row(
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
    ) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to get file from the db: {}", e);
            return Err(DbError::FailedToGetFileFromDb(e.to_string()));
        }
    };

    Ok(result)
}

pub fn add_thumbnail(
    db: &mut PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
    encoded_name: &str,
    metadata: FileEncryptionMetadata,
) -> Result<(), DbError> {
    let path = Path::new(full_file_path.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let parent_folder_id = get_folder_id(db, &parent_path.to_string_lossy())
        .map_err(|e| {
            error!(
                "Failed to get parent folder id for the provided path: {}",
                e
            );
            DbError::FailedToGetFolderIdFromPath(e.to_string())
        })?
        .ok_or_else(|| {
            error!("No folder id was returned from the db");
            DbError::FailedToGetFolderIdFromPath(
                "No folder id was returned from the db".to_string(),
            )
        })?;

    let file_id: i32 = db.query_row(
        "SELECT id FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| row.get(0),
    )?;

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    tx.execute(
        "INSERT OR IGNORE INTO thumbnails 
        (encoded_name, file_id, key, buffer_size, nonce_size, salt_size, tag_size) 
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            encoded_name,
            file_id,
            metadata.key.unprotected_as_bytes(),
            metadata.buffer_size,
            metadata.nonce_size,
            metadata.salt_size,
            metadata.tag_size
        ],
    )
    .map(|_| ())
    .map_err(|e| {
        error!("Failed to add thumbnail file to the db: {}", e);
        DbError::FailedToAddFileToDb(e.to_string())
    })?;

    tx.commit()?;

    Ok(())
}

pub fn get_thumbnail(
    db: &PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<FileEncryptionMetadata, DbError> {
    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;

    let parent_folder_id = get_folder_id(db, parent_str)
        .map_err(|e| {
            error!(
                "Failed to get parent folder id for the provided path: {}",
                e
            );
            DbError::FailedToGetFolderIdFromPath(e.to_string())
        })?
        .ok_or_else(|| {
            error!("No folder id was returned from the db");
            DbError::FailedToGetFolderIdFromPath(
                "No folder id was returned from the db".to_string(),
            )
        })?;

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let file_id: i32 = db.query_row(
        "SELECT id FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| row.get(0),
    )?;

    db.query_row(
        "SELECT key, buffer_size, nonce_size, salt_size, tag_size
        FROM thumbnails
        WHERE file_id = ?1",
        params![file_id],
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
    )
    .map(Ok)
    .map_err(|e| {
        error!("Failed to get thumbnail file from the db: {}", e);
        DbError::FailedToGetFileFromDb(e.to_string())
    })?
}

#[derive(Deserialize, Serialize)]
pub struct File {
    is_file: bool,
    file_extension: Option<String>,
    file_name: String,
}

pub fn get_folder(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<Vec<File>, DbError> {
    let folder_id =
        get_folder_id(db, folder_path_str)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;

    let mut entries = Vec::new();

    let mut folder_stmt = db.prepare("SELECT name FROM folders WHERE parent_folder_id = ?1")?;
    let mut folder_rows = folder_stmt.query(params![folder_id])?;

    while let Some(row) = folder_rows.next()? {
        entries.push(File {
            is_file: false,
            file_extension: None,
            file_name: row.get(0)?,
        });
    }

    let mut file_stmt =
        db.prepare("SELECT name, file_extension FROM files WHERE parent_folder_id = ?1")?;
    let mut file_rows = file_stmt.query(params![folder_id])?;

    while let Some(row) = file_rows.next()? {
        entries.push(File {
            is_file: true,
            file_extension: row.get(1)?,
            file_name: row.get(0)?,
        });
    }

    Ok(entries)
}

pub fn delete_folder(
    db: &mut PooledConnection<SqliteConnectionManager>,
    path_str: &str,
) -> Result<(), DbError> {
    let folder_id = get_folder_id(db, path_str)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    delete_folder_by_id(db, folder_id)
}

pub fn add_folder(
    db: &mut PooledConnection<SqliteConnectionManager>,
    path_str: &str,
) -> Result<(), DbError> {
    get_folder_id_and_create_if_missing(db, path_str)?;
    Ok(())
}

pub fn move_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
    destination_folder_str: &str,
) -> Result<(), DbError> {
    let path = Path::new(file_path_str.trim_matches('/'));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let current_parent_path = path.parent().unwrap_or(Path::new(""));
    let current_parent_folder_id = get_folder_id(db, &current_parent_path.to_string_lossy())?
        .ok_or(DbError::MissingFileName)?;

    let destination_folder_id = get_folder_id_and_create_if_missing(db, destination_folder_str)?;

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    tx.execute(
        "UPDATE files SET parent_folder_id = ?1 WHERE parent_folder_id = ?2 AND name = ?3",
        params![destination_folder_id, current_parent_folder_id, file_name],
    )
    .map(|rows_affected| {
        if rows_affected == 0 {
            error!(
                "No file found to move from parent folder {} with name {}",
                current_parent_folder_id, file_name
            );
        }
    })
    .map_err(|e| {
        error!("Failed to move file in the db: {}", e);
        DbError::FailedToAddFileToDb(e.to_string())
    })?;

    tx.commit()?;

    Ok(())
}

pub fn get_files_in_folder(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_id: i32,
) -> Result<Vec<crate::session::user_session::EncodedFile>, DbError> {
    let mut stmt = db.prepare("SELECT id, encoded_name FROM files WHERE parent_folder_id = ?1")?;
    let mut rows = stmt.query(params![folder_id])?;

    let mut files = Vec::new();

    while let Some(row) = rows.next()? {
        files.push(crate::session::user_session::EncodedFile {
            id: row.get(0)?,
            encoded_name: row.get(1)?,
        });
    }

    Ok(files)
}

pub fn get_child_folders(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_id: i32,
) -> Result<Vec<i32>, DbError> {
    let mut stmt = db.prepare("SELECT id FROM folders WHERE parent_folder_id = ?1")?;
    let mut rows = stmt.query(params![folder_id])?;

    let mut folders = Vec::new();

    while let Some(row) = rows.next()? {
        folders.push(row.get(0)?);
    }

    Ok(folders)
}

pub fn get_encoded_thumbnail_file_name_by_file_id(
    db: &PooledConnection<SqliteConnectionManager>,
    file_id: i32,
) -> Result<Option<String>, DbError> {
    let result = db
        .query_row(
            "SELECT encoded_name FROM thumbnails WHERE file_id = ?1",
            params![file_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            error!(
                "Failed to get encoded thumbnail file name from the db: {}",
                e
            );
            DbError::FailedToGetFileFromDb(e.to_string())
        })?;

    Ok(result)
}

pub fn delete_file_by_id(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_id: i32,
) -> Result<(), DbError> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    tx.execute("DELETE FROM files WHERE id = ?1", params![file_id])
        .map(|_| ())
        .map_err(|e| {
            error!("Failed to delete file from the db: {}", e);
            DbError::FailedToDeleteFileFromDb(e.to_string())
        })?;

    tx.commit()?;

    Ok(())
}

pub fn delete_folder_by_id(
    db: &mut PooledConnection<SqliteConnectionManager>,
    folder_id: i32,
) -> Result<(), DbError> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    tx.execute("DELETE FROM folders WHERE id = ?1", params![folder_id])
        .map(|_| ())
        .map_err(|e| {
            error!("Failed to delete folder from the db: {}", e);
            DbError::FailedToDeleteFileFromDb(e.to_string())
        })?;

    tx.commit()?;

    Ok(())
}
