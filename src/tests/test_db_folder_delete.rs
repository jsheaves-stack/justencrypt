// Unit tests for `sqlite::delete_folder_tree`, which deletes a folder and
// everything under it in one transaction.

use rusqlite::params;

use super::{migrated_db, Db};
use crate::{db::sqlite, encryption::FileEncryptionMetadata, enums::db_error::DbError};

fn add(db: &mut Db, path: &str, encoded_name: &str, size: u64) {
    let metadata = FileEncryptionMetadata {
        total_size: size,
        ..FileEncryptionMetadata::new()
    };

    sqlite::add_file(db, path, encoded_name, metadata).unwrap();
}

fn folder_id(db: &Db, path: &str) -> Option<i32> {
    sqlite::get_folder_id(db, path).unwrap()
}

// (total size, total files, total folders) of the root, as kept by triggers.
fn root_totals(db: &Db) -> (i64, i64, i64) {
    db.query_row(
        "SELECT total_folder_size, total_file_count, total_folder_count FROM folders WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .unwrap()
}

fn file_count(db: &Db) -> i64 {
    db.query_row("SELECT count(*) FROM files", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn test_delete_folder_tree_returns_every_blob_and_removes_the_subtree() {
    let mut db = migrated_db();
    add(&mut db, "doomed/a.txt", "blob-a", 1);
    add(&mut db, "doomed/sub/b.txt", "blob-b", 10);
    add(&mut db, "doomed/sub/deeper/c.txt", "blob-c", 100);
    add(&mut db, "kept/d.txt", "blob-d", 1000);
    sqlite::add_folder(&mut db, "doomed/empty").unwrap();

    let mut blobs = sqlite::delete_folder_tree(&mut db, "doomed").unwrap();
    blobs.sort();

    assert_eq!(blobs, ["blob-a", "blob-b", "blob-c"]);

    for path in ["doomed", "doomed/sub", "doomed/sub/deeper", "doomed/empty"] {
        assert_eq!(folder_id(&db, path), None, "{} should be gone", path);
    }

    assert!(folder_id(&db, "kept").is_some());
    assert_eq!(file_count(&db), 1);
    assert_eq!(root_totals(&db), (1000, 1, 1));
}

#[test]
fn test_delete_folder_tree_refuses_the_root() {
    let mut db = migrated_db();
    add(&mut db, "a.txt", "blob-a", 1);
    add(&mut db, "docs/b.txt", "blob-b", 1);

    for root in ["", "/", "."] {
        let result = sqlite::delete_folder_tree(&mut db, root);

        assert!(
            matches!(result, Err(DbError::InvalidInput(_))),
            "root {:?}: {:?}",
            root,
            result
        );
    }

    assert_eq!(file_count(&db), 2);
    assert!(folder_id(&db, "docs").is_some());
}

#[test]
fn test_delete_folder_tree_of_a_missing_folder_is_not_found() {
    let mut db = migrated_db();

    let result = sqlite::delete_folder_tree(&mut db, "no/such/folder");

    assert!(matches!(result, Err(DbError::NotFound)), "{:?}", result);
}

// If any step fails, nothing is deleted: here the very last delete (the
// folder itself) is made to fail after everything below it was removed.
#[test]
fn test_delete_folder_tree_is_all_or_nothing() {
    let mut db = migrated_db();
    add(&mut db, "doomed/a.txt", "blob-a", 1);
    add(&mut db, "doomed/sub/b.txt", "blob-b", 10);
    let doomed = folder_id(&db, "doomed").unwrap();
    let totals_before = root_totals(&db);

    db.execute_batch(&format!(
        "CREATE TRIGGER fail_top_delete BEFORE DELETE ON folders WHEN OLD.id = {doomed}
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;"
    ))
    .unwrap();

    let result = sqlite::delete_folder_tree(&mut db, "doomed");

    assert!(result.is_err());
    assert_eq!(folder_id(&db, "doomed/sub").map(|_| ()), Some(()));
    assert_eq!(file_count(&db), 2);
    assert_eq!(root_totals(&db), totals_before);

    let names: Vec<String> = db
        .prepare("SELECT encoded_name FROM files ORDER BY encoded_name")
        .unwrap()
        .query_map(params![], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(names, ["blob-a", "blob-b"]);
}
