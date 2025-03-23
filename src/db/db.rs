use std::path::PathBuf;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use secrecy::{ExposeSecret, SecretString};

use super::sql;

pub fn create_user_db_connection(
    db_path: PathBuf,
    password: SecretString,
) -> Pool<SqliteConnectionManager> {
    let db_manager = SqliteConnectionManager::file(db_path).with_init(move |conn| {
        conn.execute_batch(&format!(
            "PRAGMA key = '{}'; PRAGMA foreign_keys = ON;",
            password.expose_secret()
        ))
        .unwrap();

        conn.execute_batch(sql::get_schema())
    });

    Pool::new(db_manager).unwrap()
}
