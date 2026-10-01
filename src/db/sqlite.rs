use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};

use orion::kex::SecretKey;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    config::DbConfig,
    db::migrations,
    encryption::FileEncryptionMetadata,
    enums::db_error::DbError,
    util::names::{is_valid_entry_name, is_valid_entry_path, INVALID_ENTRY_NAME_MESSAGE},
};

pub fn verify_user_db_password(
    db_path: &Path,
    password: &SecretString,
    config: &DbConfig,
) -> Result<(), DbError> {
    let conn = rusqlite::Connection::open(db_path)?;
    conn.busy_timeout(Duration::from_millis(config.busy_timeout_ms))?;
    conn.pragma_update(None, "key", password.expose_secret())?;

    if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(())) {
        debug!("Failed to verify database password: {}", e);

        return Err(DbError::Rusqlite(e));
    }

    trace!("Password verified successfully.");

    Ok(())
}

/// A one-line description of a migration failure. The error's own `Display`
/// includes the full text of the migration SQL, which is far too long to log.
fn migration_error_summary(error: &rusqlite_migration::Error) -> String {
    match error {
        rusqlite_migration::Error::RusqliteError {
            err: rusqlite::Error::SqlInputError { msg, .. },
            ..
        } => msg.clone(),
        rusqlite_migration::Error::RusqliteError { err, .. } => err.to_string(),
        other => other.to_string(),
    }
}

pub fn create_user_db_connection(
    db_path: PathBuf,
    password: SecretString,
    config: &DbConfig,
) -> Result<Pool<SqliteConnectionManager>, DbError> {
    let busy_timeout = Duration::from_millis(config.busy_timeout_ms);
    let synchronous_mode = config.synchronous_mode.as_sql();
    let cache_size_kb = config.cache_size_kb;
    let temp_store_mode = config.temp_store.as_sql();
    let journal_size_limit_bytes = config.journal_size_limit_bytes;

    // Open a connection to validate the password and run migrations.
    // This fails immediately if the password is wrong, avoiding r2d2's exponential
    // backoff and retry loops.
    {
        trace!("Manually opening DB connection for password validation and migrations.");

        let mut conn = rusqlite::Connection::open(&db_path)?;

        conn.busy_timeout(busy_timeout)?;
        conn.pragma_update(None, "key", password.expose_secret())?;

        if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(())) {
            debug!("Failed to verify database password: {}", e);

            return Err(DbError::Rusqlite(e));
        }

        trace!("Running one-time database migrations...");

        if let Err(e) = migrations::get_migrations().to_latest(&mut conn) {
            let summary = migration_error_summary(&e);

            error!("Database migration failed: {}", summary);

            debug!("Database migration error detail: {:?}", e);

            return Err(DbError::Migration(summary));
        }

        trace!("Migrations are up to date.");
    }

    let db_manager = SqliteConnectionManager::file(db_path).with_init(move |conn| {
        trace!("Initializing new pool DB connection.");

        conn.busy_timeout(busy_timeout)?;
        conn.pragma_update(None, "key", password.expose_secret())?;

        conn.query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))?;

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

        trace!("Applying performance PRAGMAs: synchronous={}, cache_size=-{}, temp_store={}, journal_size_limit={}", synchronous_mode, cache_size_kb, temp_store_mode, journal_size_limit_bytes);

        conn.execute_batch(&format!(
            "PRAGMA synchronous = {}; PRAGMA cache_size = -{}; PRAGMA temp_store = {}; PRAGMA journal_size_limit = {};",
            synchronous_mode, cache_size_kb, temp_store_mode, journal_size_limit_bytes
        ))?;

        Ok(())
    });

    let pool = Pool::builder()
        .max_size(config.max_connections.get())
        .min_idle(Some(config.min_connections))
        .idle_timeout(Some(Duration::from_secs(config.idle_timeout_seconds.get())))
        .connection_timeout(Duration::from_secs(config.connection_timeout_seconds.get()))
        .build(db_manager)
        .map_err(DbError::PoolError)?;

    Ok(pool)
}

/// Resolves `folder_path_str` to a folder id, creating any folders that are
/// missing along the way. It does no transaction handling of its own, so call
/// it inside one: if anything fails part-way through, nothing is left behind.
fn get_or_create_folder(conn: &Connection, folder_path_str: &str) -> Result<i32, DbError> {
    let path = Path::new(folder_path_str.trim_matches('/'));
    let mut current_id = 1;

    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name.to_string_lossy().to_string(),
            _ => continue,
        };

        let folder_id = match conn
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
            },
        };

        current_id = match folder_id {
            Some(id) => id,
            None => {
                conn.execute(
                    "INSERT OR IGNORE INTO folders (parent_folder_id, name, created_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)",
                    params![current_id, name],
                )?;
                let new_id = conn.query_row("SELECT last_insert_rowid()", [], |row| row.get(0))?;
                trace!("Created folder with ID {}", new_id);

                new_id
            },
        };
    }

    Ok(current_id)
}

fn get_folder_id_and_create_if_missing(
    db: &mut PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<i32, DbError> {
    if let Some(id) = get_folder_id(db, folder_path_str)? {
        trace!("Folder already exists with ID {}", id);

        return Ok(id);
    }

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started.");

    let folder_id = get_or_create_folder(&tx, folder_path_str)?;

    tx.commit()?;
    trace!("Created missing folders; final folder ID {}", folder_id);

    Ok(folder_id)
}

pub fn get_folder_id(db: &Connection, folder_path_str: &str) -> Result<Option<i32>, DbError> {
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
            },
        };

        match folder_id {
            Some(id) => current_id = id,
            None => {
                return Ok(None);
            },
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
    trace!("Parent folder ID found: {}", parent_folder_id);

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let result: Option<String> = match db
        .query_row(
            "SELECT encoded_name FROM files WHERE parent_folder_id = ?1 AND name = ?2",
            params![parent_folder_id, file_name],
            |row| row.get(0),
        )
        .optional()
    {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to get encoded file name from the db: {}", e);

            return Err(DbError::FailedToGetFileFromDb(e.to_string()));
        },
    };

    let result = result.ok_or(DbError::NotFound)?;

    Ok(result)
}

/// Stores the file at `full_file_path`, creating any missing parent folders,
/// and returns the encoded name of the blob it replaced, if any.
///
/// The replaced blob is read in the same transaction as the write, so when
/// several writers overwrite the same path each one is told about exactly the
/// blob it displaced, and every old blob is reported to exactly one caller.
pub fn add_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    full_file_path: &str,
    encoded_file_name: &str,
    metadata: FileEncryptionMetadata,
) -> Result<Option<String>, DbError> {
    check_path_names(Some(full_file_path))?;

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

    let total_size = i64::try_from(metadata.total_size)
        .map_err(|_| DbError::InvalidInput("File is too large".to_string()))?;

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for adding file.");

    let parent_folder_id = get_or_create_folder(&tx, &parent_path.to_string_lossy())?;
    trace!("Parent folder ID is: {}", parent_folder_id);

    let replaced_encoded_name: Option<String> = tx
        .query_row(
            "SELECT encoded_name FROM files WHERE parent_folder_id = ?1 AND name = ?2",
            params![parent_folder_id, file_name],
            |row| row.get(0),
        )
        .optional()?;

    tx.execute(
        r#"INSERT INTO files
            (parent_folder_id, name, encoded_name, file_extension, key, encryption_version, total_size)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
           ON CONFLICT(parent_folder_id, name) DO UPDATE SET
             encoded_name = excluded.encoded_name,
             file_extension = excluded.file_extension,
             key = excluded.key,
             encryption_version = excluded.encryption_version,
             total_size = excluded.total_size,
             updated_at = CURRENT_TIMESTAMP
        "#,
        params![
            parent_folder_id,
            file_name,
            encoded_file_name,
            file_extension,
            metadata.key.unprotected_as_bytes(),
            metadata.encryption_version,
            total_size,
        ],
    ).map(|_| ())
    .map_err(|e| {
        error!("Database error in add_file: {}", e);

        DbError::FailedToAddFileToDb(e.to_string())
    })?;
    trace!("File insert/update executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::add_file successfully.");

    Ok(replaced_encoded_name)
}

/// Deletes the file at `file_path_str` and returns the encoded name of its
/// blob, or `None` if there was no such file. The name comes from the deleted
/// row itself, so it is always the blob that row referenced, even if the file
/// was overwritten a moment earlier.
pub fn delete_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<Option<String>, DbError> {
    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    trace!("Transaction started for deleting file.");

    let parent_folder_id = match get_folder_id(&tx, &parent_path.to_string_lossy())? {
        Some(id) => id,
        None => {
            return Ok(None);
        },
    };
    trace!("Parent folder ID is: {}", parent_folder_id);

    let deleted_encoded_name: Option<String> = tx
        .query_row(
            "DELETE FROM files WHERE parent_folder_id = ?1 AND name = ?2 RETURNING encoded_name",
            params![parent_folder_id, file_name],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            error!("Failed to delete file from the db: {}", e);

            DbError::FailedToDeleteFileFromDb(e.to_string())
        })?;
    trace!("File delete executed.");

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::delete_file successfully.");

    Ok(deleted_encoded_name)
}

pub fn get_file_decryption_data(
    db: &PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
) -> Result<(String, FileEncryptionMetadata), DbError> {
    let path = Path::new(file_path_str.trim_matches('/'));
    let parent_path = path.parent().unwrap_or(Path::new(""));
    let parent_str = parent_path.to_str().ok_or(DbError::InvalidPath)?;

    let parent_folder_id = get_folder_id(db, parent_str)?.ok_or(DbError::NotFound)?;

    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy();

    db.query_row(
        "SELECT encoded_name, key, encryption_version, total_size
        FROM files
        WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_folder_id, file_name],
        |row| {
            let encoded_name: String = row.get(0)?;
            let key_blob: Vec<u8> = row.get(1)?;
            let total_size_i64: i64 = row.get(3)?;
            Ok((
                encoded_name,
                FileEncryptionMetadata {
                    key: SecretKey::from_slice(&key_blob).unwrap(),
                    encryption_version: row.get(2)?,
                    total_size: total_size_i64 as u64,
                },
            ))
        },
    )
    .map_err(|e| {
        if let rusqlite::Error::QueryReturnedNoRows = e {
            DbError::NotFound
        } else {
            error!("Database error in get_file_decryption_data: {}", e);

            DbError::FailedToGetFileFromDb(e.to_string())
        }
    })
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum FolderContent {
    File(File),
    Folder(Folder),
}

#[derive(Deserialize, Serialize)]
pub struct File {
    pub file_extension: Option<String>,
    pub file_name: String,
    pub file_size: Option<u64>,
    pub created_date: Option<String>,
    pub last_modified_date: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Folder {
    pub file_name: String,
    pub file_size: Option<u64>,
    pub created_date: Option<String>,
    pub last_modified_date: Option<String>,
    pub file_count: u64,
    pub folder_count: u64,
}

pub fn get_folder(
    db: &PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
) -> Result<Vec<FolderContent>, DbError> {
    let folder_id = get_folder_id(db, folder_path_str)?.ok_or(DbError::NotFound)?;
    trace!("Found folder ID: {}", folder_id);

    let mut entries = Vec::new();

    trace!("Querying for child folders.");

    let mut folder_stmt = db.prepare(
        "SELECT name, total_folder_size, total_file_count, total_folder_count, created_at FROM folders WHERE parent_folder_id = ?1"
    )?;

    let mut folder_rows = folder_stmt.query(params![folder_id])?;

    while let Some(row) = folder_rows.next()? {
        let file_name: String = row.get(0)?;
        let folder_size: i64 = row.get(1)?;
        let file_count: i64 = row.get(2)?;
        let folder_count: i64 = row.get(3)?;
        let created_at: Option<String> = row.get(4)?;
        entries.push(FolderContent::Folder(Folder {
            file_name,
            file_size: Some(folder_size as u64),
            created_date: created_at,
            last_modified_date: None,
            file_count: file_count as u64,
            folder_count: folder_count as u64,
        }));
    }

    trace!("Querying for files in folder.");

    let mut file_stmt = db.prepare(
        "SELECT name, file_extension, total_size, created_at, updated_at FROM files WHERE parent_folder_id = ?1",
    )?;
    let mut file_rows = file_stmt.query(params![folder_id])?;

    while let Some(row) = file_rows.next()? {
        let file_name: String = row.get(0)?;
        let total_size_i64: i64 = row.get(2)?;
        let created_at: Option<String> = row.get(3)?;
        let updated_at: Option<String> = row.get(4)?;

        entries.push(FolderContent::File(File {
            file_extension: row.get(1)?,
            file_name,
            file_size: Some(total_size_i64 as u64),
            created_date: created_at,
            last_modified_date: updated_at,
        }));
    }

    Ok(entries)
}

/// Deletes the folder at `path_str` with everything under it, in one
/// transaction, and returns the encoded names of the blobs of every deleted
/// file. Nothing is deleted if any step fails. The caller removes the blobs
/// after this returns.
///
/// The root folder can't be deleted.
pub fn delete_folder_tree(
    db: &mut PooledConnection<SqliteConnectionManager>,
    path_str: &str,
) -> Result<Vec<String>, DbError> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let folder_id = get_folder_id(&tx, path_str)?.ok_or(DbError::NotFound)?;

    if folder_id == 1 {
        return Err(DbError::InvalidInput(
            "Cannot delete the root folder".to_string(),
        ));
    }

    // Every folder in the subtree, deepest first, so each folder is deleted
    // after its children.
    let subtree: Vec<i32> = {
        let mut stmt = tx.prepare(
            r#"WITH RECURSIVE subtree(id, depth) AS (
                   SELECT ?1, 0
                   UNION
                   SELECT f.id, s.depth + 1 FROM folders f
                   INNER JOIN subtree s ON f.parent_folder_id = s.id
               )
               SELECT id FROM subtree ORDER BY depth DESC"#,
        )?;
        let rows = stmt.query_map(params![folder_id], |row| row.get(0))?;

        rows.collect::<Result<_, _>>()?
    };
    trace!("Deleting {} folder(s)", subtree.len());

    let mut blobs = Vec::new();

    for id in &subtree {
        {
            let mut stmt =
                tx.prepare("SELECT encoded_name FROM files WHERE parent_folder_id = ?1")?;
            let names = stmt.query_map(params![id], |row| row.get::<_, String>(0))?;

            for name in names {
                blobs.push(name?);
            }
        }

        tx.execute("DELETE FROM files WHERE parent_folder_id = ?1", params![id])
            .map_err(|e| DbError::FailedToDeleteFileFromDb(e.to_string()))?;
        tx.execute("DELETE FROM folders WHERE id = ?1", params![id])
            .map_err(|e| DbError::FailedToDeleteFileFromDb(e.to_string()))?;
    }

    tx.commit()?;
    trace!("Deleted folder tree; {} blob(s) to remove", blobs.len());

    Ok(blobs)
}

pub fn add_folder(
    db: &mut PooledConnection<SqliteConnectionManager>,
    path_str: &str,
) -> Result<(), DbError> {
    check_path_names(Some(path_str))?;

    get_folder_id_and_create_if_missing(db, path_str)?;

    Ok(())
}

/// Maps a UNIQUE constraint violation to `Conflict`, and any other error to
/// `FailedToUpdateFileInDb`.
fn update_error(e: rusqlite::Error, what: &str) -> DbError {
    match &e {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            DbError::Conflict(format!("A {what} with that name already exists there"))
        },
        _ => {
            error!("Failed to update {} in the db: {}", what, e);

            DbError::FailedToUpdateFileInDb(e.to_string())
        },
    }
}

fn check_new_name(new_name: Option<&str>) -> Result<(), DbError> {
    match new_name {
        Some(name) if !is_valid_entry_name(name) => Err(DbError::InvalidInput(
            INVALID_ENTRY_NAME_MESSAGE.to_string(),
        )),
        _ => Ok(()),
    }
}

// Every file and folder name a path would create must be a valid name.
fn check_path_names(path: Option<&str>) -> Result<(), DbError> {
    match path {
        Some(path) if !is_valid_entry_path(path) => Err(DbError::InvalidInput(
            INVALID_ENTRY_NAME_MESSAGE.to_string(),
        )),
        _ => Ok(()),
    }
}

/// Renames and/or moves the folder at `folder_path_str`, in one transaction:
/// either both changes happen or neither does, and a destination created for a
/// rejected request is rolled back. Fails with `NotFound` if the folder doesn't
/// exist, `Conflict` if the target name is taken, and `InvalidInput` for an
/// invalid name, the root folder, or a move into the folder's own subtree.
pub fn update_folder(
    db: &mut PooledConnection<SqliteConnectionManager>,
    folder_path_str: &str,
    new_name: Option<&str>,
    destination_folder_str: Option<&str>,
) -> Result<(), DbError> {
    check_new_name(new_name)?;
    check_path_names(destination_folder_str)?;

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let folder_id = get_folder_id(&tx, folder_path_str)?.ok_or(DbError::NotFound)?;

    if folder_id == 1 {
        return Err(DbError::InvalidInput(
            "Cannot rename or move the root folder".to_string(),
        ));
    }

    let (current_name, current_parent_id): (String, i32) = tx.query_row(
        "SELECT name, parent_folder_id FROM folders WHERE id = ?1",
        params![folder_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let target_parent_id = match destination_folder_str {
        Some(destination) => {
            let destination_id = get_or_create_folder(&tx, destination)?;

            // The folder-total triggers walk a folder's ancestors
            // with `UNION ALL`, which never terminates (and grows without bound in
            // memory) if the ancestors form a cycle. Keep the check by id and inside
            // this transaction.
            //
            // `UNION` (not `UNION ALL`) de-duplicates rows, so this walk itself
            // terminates even if the ancestor chain already contains a cycle.
            let creates_cycle: bool = tx.query_row(
                r#"WITH RECURSIVE ancestors(id) AS (
                       SELECT ?1
                       UNION
                       SELECT f.parent_folder_id FROM folders f
                       INNER JOIN ancestors a ON f.id = a.id
                       WHERE f.parent_folder_id IS NOT NULL
                   )
                   SELECT EXISTS (SELECT 1 FROM ancestors WHERE id = ?2)"#,
                params![destination_id, folder_id],
                |row| row.get(0),
            )?;

            if creates_cycle {
                return Err(DbError::InvalidInput(
                    "Cannot move a folder into itself or its subfolders".to_string(),
                ));
            }

            destination_id
        },
        None => current_parent_id,
    };

    tx.execute(
        "UPDATE folders SET name = ?1, parent_folder_id = ?2 WHERE id = ?3",
        params![
            new_name.unwrap_or(&current_name),
            target_parent_id,
            folder_id
        ],
    )
    .map_err(|e| update_error(e, "folder"))?;

    tx.commit()?;

    Ok(())
}

/// Renames and/or moves the file at `file_path_str`, in one transaction:
/// either both changes happen or neither does, and a destination created for a
/// rejected request is rolled back. Fails with `NotFound` if the file doesn't
/// exist, `Conflict` if the target name is taken, and `InvalidInput` for an
/// invalid name.
pub fn update_file(
    db: &mut PooledConnection<SqliteConnectionManager>,
    file_path_str: &str,
    new_name: Option<&str>,
    destination_folder_str: Option<&str>,
) -> Result<(), DbError> {
    check_new_name(new_name)?;
    check_path_names(destination_folder_str)?;

    let path = Path::new(file_path_str.trim_matches('/'));
    let file_name = path
        .file_name()
        .ok_or(DbError::MissingFileName)?
        .to_string_lossy()
        .to_string();
    let parent_path = path.parent().unwrap_or(Path::new(""));

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // The file must exist before anything, including destination folders, is
    // created.
    let parent_id = get_folder_id(&tx, &parent_path.to_string_lossy())?.ok_or(DbError::NotFound)?;
    let file_id: i32 = tx
        .query_row(
            "SELECT id FROM files WHERE parent_folder_id = ?1 AND name = ?2",
            params![parent_id, file_name],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(DbError::NotFound)?;

    let target_parent_id = match destination_folder_str {
        Some(destination) => get_or_create_folder(&tx, destination)?,
        None => parent_id,
    };
    let target_name = new_name.unwrap_or(&file_name);
    let target_extension = Path::new(target_name)
        .extension()
        .map(|ext| ext.to_string_lossy().to_string())
        .unwrap_or_default();

    tx.execute(
        "UPDATE files SET name = ?1, parent_folder_id = ?2, file_extension = ?3, updated_at = CURRENT_TIMESTAMP WHERE id = ?4",
        params![target_name, target_parent_id, target_extension, file_id],
    )
    .map_err(|e| update_error(e, "file"))?;

    tx.commit()?;
    trace!("Transaction committed. Exiting sqlite::update_file successfully.");

    Ok(())
}

pub fn add_active_upload(
    db: &rusqlite::Connection,
    upload_id: &str,
    session_id: &str,
    encoded_file_name: &str,
    file_path: &str,
) -> Result<(), DbError> {
    db.execute(
        "INSERT OR REPLACE INTO active_uploads (upload_id, session_id, encoded_file_name, file_path) VALUES (?1, ?2, ?3, ?4)",
        params![upload_id, session_id, encoded_file_name, file_path],
    )
    .map(|_| {
    })
    .map_err(|e| DbError::FailedToAddFileToDb(e.to_string()))
}

pub fn remove_active_upload(db: &rusqlite::Connection, upload_id: &str) -> Result<(), DbError> {
    db.execute(
        "DELETE FROM active_uploads WHERE upload_id = ?1",
        params![upload_id],
    )
    .map(|_| ())
    .map_err(|e| DbError::FailedToDeleteFileFromDb(e.to_string()))
}

/// The encoded blob name of every file.
pub fn get_all_encoded_names(db: &rusqlite::Connection) -> Result<Vec<String>, DbError> {
    let mut stmt = db
        .prepare("SELECT encoded_name FROM files")
        .map_err(|e| DbError::FailedToQueryDb(e.to_string()))?;
    let names = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| DbError::FailedToQueryDb(e.to_string()))?
        .collect::<Result<Vec<String>, _>>()
        .map_err(|e| DbError::FailedToQueryDb(e.to_string()))?;

    Ok(names)
}

pub fn get_all_active_uploads(
    db: &rusqlite::Connection,
) -> Result<Vec<(String, String, String)>, DbError> {
    let mut stmt = db
        .prepare("SELECT upload_id, session_id, encoded_file_name FROM active_uploads")
        .map_err(|e| DbError::FailedToQueryDb(e.to_string()))?;

    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|e| DbError::FailedToQueryDb(e.to_string()))?;

    let mut uploads = Vec::new();
    for row in rows {
        uploads.push(row.map_err(|e| DbError::FailedToQueryDb(e.to_string()))?);
    }

    Ok(uploads)
}
