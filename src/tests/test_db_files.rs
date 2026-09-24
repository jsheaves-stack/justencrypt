// Unit tests for `sqlite::add_file` and `sqlite::delete_file`.
//
// Both report the blob they replaced or removed, read in the same transaction
// as the write. Routes rely on that to delete exactly the right blob even when
// several requests touch the same path at once (see the M2 race test in
// `test_file.rs`), so these tests pin the contract down deterministically.

use super::{migrated_db, Db};
use crate::{db::sqlite, encryption::FileEncryptionMetadata, enums::db_error::DbError};

fn metadata(total_size: u64) -> FileEncryptionMetadata {
    FileEncryptionMetadata {
        total_size,
        ..FileEncryptionMetadata::new()
    }
}

fn add(db: &mut Db, path: &str, encoded_name: &str) -> Option<String> {
    sqlite::add_file(db, path, encoded_name, metadata(10)).unwrap()
}

#[test]
fn test_add_file_reports_the_blob_it_replaced() {
    let mut db = migrated_db();

    assert_eq!(add(&mut db, "docs/a.txt", "blob-1"), None);
    assert_eq!(
        add(&mut db, "docs/a.txt", "blob-2"),
        Some("blob-1".to_string())
    );
    assert_eq!(
        add(&mut db, "docs/a.txt", "blob-3"),
        Some("blob-2".to_string())
    );
    assert_eq!(
        sqlite::get_encoded_file_name(&db, "docs/a.txt").unwrap(),
        "blob-3"
    );

    // A different path is a different file.
    assert_eq!(add(&mut db, "docs/b.txt", "blob-4"), None);
}

#[test]
fn test_delete_file_reports_the_blob_it_removed() {
    let mut db = migrated_db();
    add(&mut db, "docs/a.txt", "blob-1");
    add(&mut db, "docs/a.txt", "blob-2");

    assert_eq!(
        sqlite::delete_file(&mut db, "docs/a.txt").unwrap(),
        Some("blob-2".to_string())
    );
    assert_eq!(sqlite::delete_file(&mut db, "docs/a.txt").unwrap(), None);
    assert_eq!(
        sqlite::delete_file(&mut db, "docs/never.txt").unwrap(),
        None
    );
    assert_eq!(
        sqlite::delete_file(&mut db, "no/such/folder/a.txt").unwrap(),
        None
    );
}

// Parent folders are created in the same transaction as the file, so a failed
// add leaves nothing behind.
#[test]
fn test_failed_add_file_does_not_leave_new_folders_behind() {
    let mut db = migrated_db();
    add(&mut db, "a.txt", "blob-1");

    // Blob names are unique, so storing the same blob at a second path fails,
    // but only after the parent folders have been created.
    let result = sqlite::add_file(&mut db, "new/deep/b.txt", "blob-1", metadata(10));

    assert!(result.is_err(), "expected a failure, got {result:?}");
    assert_eq!(sqlite::get_folder_id(&db, "new").unwrap(), None);
}

#[test]
fn test_add_file_rejects_a_size_the_database_cannot_store() {
    let mut db = migrated_db();

    let result = sqlite::add_file(&mut db, "new/huge.bin", "blob-1", metadata(u64::MAX));

    assert!(
        matches!(result, Err(DbError::InvalidInput(_))),
        "got {result:?}"
    );
    assert_eq!(sqlite::get_folder_id(&db, "new").unwrap(), None);
}
