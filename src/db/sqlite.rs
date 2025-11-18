use crate::db::migrations;
use crate::encryption::FileEncryptionMetadata;
use crate::enums::db_error::DbError;
use orion::kex::SecretKey;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};

pub fn create_user_db_connection(
    db_path: PathBuf,
    password: SecretString,
) -> Result<Pool<SqliteConnectionManager>, DbError> {
    trace!(
        "Entering sqlite::create_user_db_connection with db_path: {:?}",
        db_path
    );

    {
        let mut conn = Connection::open(&db_path)?;

        conn.pragma_update(None, "key", password.expose_secret())?;

        trace!("Running one-time database migrations...");

        match migrations::get_migrations().to_latest(&mut conn) {
            Ok(_) => trace!("Migrations are up to date."),
            Err(e) => {
                error!("{}", e);
                return Err(DbError::MissingFileName);
            }
        };
    }

    let db_manager = SqliteConnectionManager::file(db_path).with_init(move |conn| {
        trace!("Initializing new DB connection.");
        conn.busy_timeout(Duration::from_millis(60000))?;
        trace!("Setting PRAGMA key.");
        conn.pragma_update(None, "key", password.expose_secret())?;
        trace!("PRAGMA key set successfully.");

        conn.query_row("SELECT 1", [], |_| Ok(()))?;

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

        trace!("Setting PRAGMA foreign_keys = ON.");
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        Ok(())
    });

    let pool = Pool::new(db_manager)?;
    trace!("Exiting sqlite::create_user_db_connection successfully.");
    Ok(pool)
}

fn get_folder_id_and_create_if_missing(
    db: &mut PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<i32, DbError> {
    trace!(
        "Entering sqlite::get_folder_id_and_create_if_missing with folder_path_str: '{}'",
        folder_path_str
    );
    let path = Path::new(folder_path_str.trim_matches('/'));
    let mut current_id = 1;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started.");

    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name.to_string_lossy().to_string(),
            _ => continue,
        };
        trace!(
            "Processing path component: '{}', current parent ID: {}",
            name,
            current_id
        );

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
            Some(id) => {
                trace!("Folder '{}' found with ID: {}", name, id);
                id
            }
            None => {
                trace!("Folder '{}' not found, creating it.", name);
                tx.execute(
                    "INSERT OR IGNORE INTO folders (parent_folder_id, name) VALUES (?1, ?2)",
                    params![current_id, name],
                )?;
                let new_id = tx.query_row("SELECT last_insert_rowid()", [], |row| row.get(0))?;
                trace!("New folder '{}' created with ID: {}", name, new_id);
                new_id
            }
        };
    }

    tx.commit()?;
    trace!(
        "Transaction committed. Exiting sqlite::get_folder_id_and_create_if_missing with final folder ID: {}",
        current_id
    );
    Ok(current_id)
}

pub fn get_folder_id(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<Option<i32>, DbError> {
    trace!(
        "Entering sqlite::get_folder_id with folder_path_str: '{}'",
        folder_path_str
    );
    let path = Path::new(folder_path_str.trim_matches('/'));
    let mut current_id = 1;

    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name.to_string_lossy().to_string(),
            _ => continue,
        };
        trace!(
            "Processing path component: '{}', current parent ID: {}",
            name,
            current_id
        );

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
            Some(id) => {
                trace!(
                    "Folder '{}' found with ID: {}. Updating current_id.",
                    name,
                    id
                );
                current_id = id
            }
            None => {
                trace!(
                    "Folder component '{}' not found. Exiting get_folder_id with None.",
                    name
                );
                return Ok(None);
            }
        }
    }

    trace!(
        "Exiting sqlite::get_folder_id with final folder ID: {}",
        current_id
    );
    Ok(Some(current_id))
}

pub fn get_encoded_file_name(
    db: &PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
) -> Result<String, DbError> {
    trace!(
        "Entering sqlite::get_encoded_file_name with full_file_path: '{}'",
        full_file_path
    );
    let path = Path::new(full_file_path.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;
    trace!("Getting parent folder ID for path: '{}'", parent_str);
    let parent_folder_id = get_folder_id(db, parent_str)?.ok_or(DbError::MissingFileName)?;
    trace!("Parent folder ID found: {}", parent_folder_id);

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();
    trace!("Looking for file name: '{}'", file_name);

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

    trace!(
        "Exiting sqlite::get_encoded_file_name with result: '{}'",
        result
    );
    Ok(result)
}

pub fn get_encoded_thumbnail_file_name(
    db: &PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
) -> Result<Option<String>, DbError> {
    trace!(
        "Entering sqlite::get_encoded_thumbnail_file_name with full_file_path: '{}'",
        full_file_path
    );
    let path = Path::new(full_file_path.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;
    trace!("Getting parent folder ID for path: '{}'", parent_str);

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
    trace!("Parent folder ID found: {}", parent_folder_id);

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();
    trace!("Looking for file name: '{}' to get its ID.", file_name);

    let file_id: i32 = db.query_row(
        "SELECT id FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| row.get(0),
    )?;
    trace!("File ID found: {}. Looking for its thumbnail.", file_id);

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

    trace!(
        "Exiting sqlite::get_encoded_thumbnail_file_name with result: {:?}",
        result
    );
    Ok(result)
}

pub fn add_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
    encoded_file_name: &str,
    metadata: FileEncryptionMetadata,
) -> Result<(), DbError> {
    trace!(
        "Entering sqlite::add_file with full_file_path: '{}', encoded_file_name: '{}'",
        full_file_path,
        encoded_file_name
    );
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
    trace!(
        "Parsed file parts: parent_path: '{:?}', file_name: '{}', file_extension: '{}'",
        parent_path,
        file_name,
        file_extension
    );

    let parent_folder_id = get_folder_id_and_create_if_missing(db, &parent_path.to_string_lossy())?;
    trace!("Parent folder ID is: {}", parent_folder_id);

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for adding file.");

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
    trace!("File insert/update executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::add_file successfully.");
    Ok(())
}

pub fn delete_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<(), DbError> {
    trace!(
        "Entering sqlite::delete_file with file_path_str: '{}'",
        file_path_str
    );
    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();
    trace!(
        "Parsed file parts: parent_path: '{:?}', file_name: '{}'",
        parent_path,
        file_name
    );

    let parent_folder_id = get_folder_id_and_create_if_missing(db, &parent_path.to_string_lossy())?;
    trace!("Parent folder ID is: {}", parent_folder_id);

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for deleting file.");

    tx.execute(
        "DELETE FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
    )
    .map(|_| ())
    .map_err(|e| {
        error!("Failed to delete file from the db: {}", e);
        DbError::FailedToDeleteFileFromDb(e.to_string())
    })?;
    trace!("File delete executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::delete_file successfully.");
    Ok(())
}

pub fn get_file(
    db: &PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<FileEncryptionMetadata, DbError> {
    trace!(
        "Entering sqlite::get_file with file_path_str: '{}'",
        file_path_str
    );
    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;
    trace!("Getting parent folder ID for path: '{}'", parent_str);
    let parent_folder_id = get_folder_id(db, parent_str)?.ok_or(DbError::MissingFileName)?;
    trace!("Parent folder ID found: {}", parent_folder_id);

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();
    trace!("Looking for file name: '{}'", file_name);

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

    trace!("Exiting sqlite::get_file successfully.");
    Ok(result)
}

pub fn add_thumbnail(
    db: &mut PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
    encoded_name: &str,
    metadata: FileEncryptionMetadata,
) -> Result<(), DbError> {
    trace!(
        "Entering sqlite::add_thumbnail with full_file_path: '{}', encoded_name: '{}'",
        full_file_path,
        encoded_name
    );
    let path = Path::new(full_file_path.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();
    trace!(
        "Parsed file parts: parent_path: '{:?}', file_name: '{}'",
        parent_path,
        file_name
    );

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
    trace!("Parent folder ID found: {}", parent_folder_id);

    let file_id: i32 = db.query_row(
        "SELECT id FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| row.get(0),
    )?;
    trace!("Associated file ID found: {}", file_id);

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for adding thumbnail.");

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
    trace!("Thumbnail insert executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::add_thumbnail successfully.");
    Ok(())
}

pub fn get_thumbnail(
    db: &PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<FileEncryptionMetadata, DbError> {
    trace!(
        "Entering sqlite::get_thumbnail with file_path_str: '{}'",
        file_path_str
    );
    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;
    trace!("Getting parent folder ID for path: '{}'", parent_str);

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
    trace!("Parent folder ID found: {}", parent_folder_id);

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();
    trace!("Looking for file name: '{}' to get its ID.", file_name);

    let file_id: i32 = db.query_row(
        "SELECT id FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| row.get(0),
    )?;
    trace!(
        "File ID found: {}. Getting its thumbnail metadata.",
        file_id
    );

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
    .map(|metadata| {
        trace!("Exiting sqlite::get_thumbnail successfully.");
        Ok(metadata)
    })
    .map_err(|e| {
        error!("Failed to get thumbnail file from the db: {}", e);
        DbError::FailedToGetFileFromDb(e.to_string())
    })?
}

#[derive(Deserialize, Serialize)]
pub struct FolderEntry {
    is_file: bool,
    file_extension: Option<String>,
    file_name: String,
}

pub fn get_folder(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<Vec<FolderEntry>, DbError> {
    trace!(
        "Entering sqlite::get_folder with folder_path_str: '{}'",
        folder_path_str
    );
    let folder_id =
        get_folder_id(db, folder_path_str)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    trace!("Found folder ID: {}", folder_id);

    let mut entries = Vec::new();

    trace!("Querying for child folders.");
    let mut folder_stmt = db.prepare("SELECT name FROM folders WHERE parent_folder_id = ?1")?;
    let mut folder_rows = folder_stmt.query(params![folder_id])?;

    while let Some(row) = folder_rows.next()? {
        let file_name: String = row.get(0)?;
        trace!("Found child folder: '{}'", file_name);
        entries.push(FolderEntry {
            is_file: false,
            file_extension: None,
            file_name,
        });
    }

    trace!("Querying for files in folder.");
    let mut file_stmt =
        db.prepare("SELECT name, file_extension FROM files WHERE parent_folder_id = ?1")?;
    let mut file_rows = file_stmt.query(params![folder_id])?;

    while let Some(row) = file_rows.next()? {
        let file_name: String = row.get(0)?;
        trace!("Found file: '{}'", file_name);
        entries.push(FolderEntry {
            is_file: true,
            file_extension: row.get(1)?,
            file_name,
        });
    }

    trace!("Exiting sqlite::get_folder with {} entries.", entries.len());
    Ok(entries)
}

pub fn delete_folder(
    db: &mut PooledConnection<SqliteConnectionManager>,
    path_str: &str,
) -> Result<(), DbError> {
    trace!(
        "Entering sqlite::delete_folder with path_str: '{}'",
        path_str
    );
    let folder_id = get_folder_id(db, path_str)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    trace!("Found folder ID to delete: {}", folder_id);
    let result = delete_folder_by_id(db, folder_id);
    trace!("Exiting sqlite::delete_folder.");
    result
}

pub fn add_folder(
    db: &mut PooledConnection<SqliteConnectionManager>,
    path_str: &str,
) -> Result<(), DbError> {
    trace!("Entering sqlite::add_folder with path_str: '{}'", path_str);
    get_folder_id_and_create_if_missing(db, path_str)?;
    trace!("Exiting sqlite::add_folder successfully.");
    Ok(())
}

pub fn rename_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
    new_file_name_str: &str,
) -> Result<(), DbError> {
    trace!(
        "Entering sqlite::rename_file with file_path_str: '{}', new_file_name_str: '{}'",
        file_path_str,
        new_file_name_str
    );
    let path = Path::new(file_path_str.trim_matches('/'));
    let original_file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let current_parent_path = path.parent().unwrap_or(Path::new(""));
    let current_parent_folder_id = get_folder_id(db, &current_parent_path.to_string_lossy())?
        .ok_or(DbError::MissingFileName)?;
    trace!(
        "Found file '{}' in parent folder ID {}",
        original_file_name,
        current_parent_folder_id
    );

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for renaming file.");

    tx.execute(
        "UPDATE files SET name = ?1 WHERE parent_folder_id = ?2 AND name = ?3",
        params![
            new_file_name_str,
            current_parent_folder_id,
            original_file_name
        ],
    )
    .map(|_| ())
    .map_err(|e| {
        error!("Failed to rename file in the db: {}", e);
        DbError::FailedToUpdateFileInDb(e.to_string())
    })?;
    trace!("File rename executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::rename_file successfully.");
    Ok(())
}

pub fn move_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
    destination_folder_str: &str,
) -> Result<(), DbError> {
    trace!(
        "Entering sqlite::move_file with file_path_str: '{}', destination_folder_str: '{}'",
        file_path_str,
        destination_folder_str
    );
    let path = Path::new(file_path_str.trim_matches('/'));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let current_parent_path = path.parent().unwrap_or(Path::new(""));
    let current_parent_folder_id = get_folder_id(db, &current_parent_path.to_string_lossy())?
        .ok_or(DbError::MissingFileName)?;
    trace!(
        "Found file '{}' in source folder ID {}",
        file_name,
        current_parent_folder_id
    );

    let destination_folder_id = get_folder_id_and_create_if_missing(db, destination_folder_str)?;
    trace!("Destination folder ID is {}", destination_folder_id);

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for moving file.");

    tx.execute(
        "UPDATE files SET parent_folder_id = ?1 WHERE parent_folder_id = ?2 AND name = ?3",
        params![destination_folder_id, current_parent_folder_id, file_name],
    )
    .map(|_| ())
    .map_err(|e| {
        error!("Failed to move file in the db: {}", e);
        DbError::FailedToAddFileToDb(e.to_string())
    })?;
    trace!("File move executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::move_file successfully.");
    Ok(())
}

pub fn get_files_in_folder(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_id: i32,
) -> Result<Vec<crate::session::user_session::EncodedFile>, DbError> {
    trace!(
        "Entering sqlite::get_files_in_folder with folder_id: {}",
        folder_id
    );
    let mut stmt = db.prepare("SELECT id, encoded_name FROM files WHERE parent_folder_id = ?1")?;
    let mut rows = stmt.query(params![folder_id])?;

    let mut files = Vec::new();

    while let Some(row) = rows.next()? {
        let file = crate::session::user_session::EncodedFile {
            id: row.get(0)?,
            encoded_name: row.get(1)?,
        };
        trace!(
            "Found file: id={}, encoded_name='{}'",
            file.id,
            file.encoded_name
        );
        files.push(file);
    }

    trace!(
        "Exiting sqlite::get_files_in_folder with {} files.",
        files.len()
    );
    Ok(files)
}

pub fn get_child_folders(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_id: i32,
) -> Result<Vec<i32>, DbError> {
    trace!(
        "Entering sqlite::get_child_folders with folder_id: {}",
        folder_id
    );
    let mut stmt = db.prepare("SELECT id FROM folders WHERE parent_folder_id = ?1")?;
    let mut rows = stmt.query(params![folder_id])?;

    let mut folders = Vec::new();

    while let Some(row) = rows.next()? {
        let id: i32 = row.get(0)?;
        trace!("Found child folder with id: {}", id);
        folders.push(id);
    }

    trace!(
        "Exiting sqlite::get_child_folders with {} folders.",
        folders.len()
    );
    Ok(folders)
}

pub fn get_encoded_thumbnail_file_name_by_file_id(
    db: &PooledConnection<SqliteConnectionManager>,
    file_id: i32,
) -> Result<Option<String>, DbError> {
    trace!(
        "Entering sqlite::get_encoded_thumbnail_file_name_by_file_id with file_id: {}",
        file_id
    );
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

    trace!(
        "Exiting sqlite::get_encoded_thumbnail_file_name_by_file_id with result: {:?}",
        result
    );
    Ok(result)
}

pub fn delete_file_by_id(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_id: i32,
) -> Result<(), DbError> {
    trace!(
        "Entering sqlite::delete_file_by_id with file_id: {}",
        file_id
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for deleting file by ID.");

    tx.execute("DELETE FROM files WHERE id = ?1", params![file_id])
        .map(|_| ())
        .map_err(|e| {
            error!("Failed to delete file from the db: {}", e);
            DbError::FailedToDeleteFileFromDb(e.to_string())
        })?;
    trace!("File delete by ID executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::delete_file_by_id successfully.");
    Ok(())
}

pub fn delete_folder_by_id(
    db: &mut PooledConnection<SqliteConnectionManager>,
    folder_id: i32,
) -> Result<(), DbError> {
    trace!(
        "Entering sqlite::delete_folder_by_id with folder_id: {}",
        folder_id
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for deleting folder by ID.");

    tx.execute("DELETE FROM folders WHERE id = ?1", params![folder_id])
        .map(|_| ())
        .map_err(|e| {
            error!("Failed to delete folder from the db: {}", e);
            DbError::FailedToDeleteFileFromDb(e.to_string())
        })?;
    trace!("Folder delete by ID executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::delete_folder_by_id successfully.");
    Ok(())
}
