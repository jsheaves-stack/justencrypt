// Unit tests for `sqlite::add_file` and `sqlite::delete_file`.
//
// Both report the blob they replaced or removed, read in the same transaction
// as the write. Routes rely on that to delete exactly the right blob even when
// several requests touch the same path at once (see the M2 race test in
// `test_file.rs`), so these tests pin the contract down deterministically.

use super::{migrated_db, Db};
use crate::{
    db::sqlite, encryption::FileEncryptionMetadata, enums::db_error::DbError,
    util::names::is_valid_entry_name,
};

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

fn extension_of(db: &Db, path: &str) -> String {
    let (folder, name) = path.rsplit_once('/').unwrap_or(("", path));
    let folder_id = sqlite::get_folder_id(db, folder).unwrap().unwrap();

    db.query_row(
        "SELECT file_extension FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        rusqlite::params![folder_id, name],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn test_update_file_of_a_missing_file_is_not_found_and_creates_nothing() {
    let mut db = migrated_db();

    for (path, destination) in [("ghost.txt", "auto/dir"), ("no/such/ghost.txt", "auto/dir")] {
        let result = sqlite::update_file(&mut db, path, Some("x.txt"), Some(destination));

        assert!(
            matches!(result, Err(DbError::NotFound)),
            "{path}: {result:?}"
        );
    }

    assert_eq!(sqlite::get_folder_id(&db, "auto").unwrap(), None);
}

#[test]
fn test_update_file_renames_moves_and_keeps_the_extension_in_sync() {
    let mut db = migrated_db();
    add(&mut db, "a.txt", "blob-a");

    sqlite::update_file(&mut db, "a.txt", Some("b.jpg"), Some("pics/2026")).unwrap();

    assert_eq!(
        sqlite::get_encoded_file_name(&db, "pics/2026/b.jpg").unwrap(),
        "blob-a"
    );
    assert!(sqlite::get_encoded_file_name(&db, "a.txt").is_err());
    assert_eq!(extension_of(&db, "pics/2026/b.jpg"), "jpg");
}

#[test]
fn test_update_file_collision_is_a_conflict_and_changes_nothing() {
    let mut db = migrated_db();
    add(&mut db, "x.txt", "blob-x");
    add(&mut db, "dir/z.txt", "blob-z");

    let result = sqlite::update_file(&mut db, "x.txt", Some("z.txt"), Some("dir"));

    assert!(matches!(result, Err(DbError::Conflict(_))), "{result:?}");
    assert_eq!(
        sqlite::get_encoded_file_name(&db, "x.txt").unwrap(),
        "blob-x"
    );
    assert_eq!(
        sqlite::get_encoded_file_name(&db, "dir/z.txt").unwrap(),
        "blob-z"
    );

    // The file is unaffected and can still be moved.
    let result = sqlite::update_file(&mut db, "x.txt", None, Some("fresh/place"));

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        sqlite::get_encoded_file_name(&db, "fresh/place/x.txt").unwrap(),
        "blob-x"
    );
}

#[test]
fn test_update_file_rejects_invalid_names_before_touching_anything() {
    let mut db = migrated_db();
    add(&mut db, "x.txt", "blob-x");

    for name in ["", ".", "..", "a/b", "a\\b", "a\u{0}b"] {
        let result = sqlite::update_file(&mut db, "x.txt", Some(name), None);

        assert!(
            matches!(result, Err(DbError::InvalidInput(_))),
            "{name:?}: {result:?}"
        );
    }

    let result = sqlite::update_file(&mut db, "x.txt", None, Some("ok/bad\u{0}dir"));

    assert!(
        matches!(result, Err(DbError::InvalidInput(_))),
        "{result:?}"
    );
    assert_eq!(sqlite::get_folder_id(&db, "ok").unwrap(), None);
    assert_eq!(
        sqlite::get_encoded_file_name(&db, "x.txt").unwrap(),
        "blob-x"
    );
}

#[test]
fn test_update_folder_collision_is_a_conflict() {
    let mut db = migrated_db();
    sqlite::add_folder(&mut db, "a").unwrap();
    sqlite::add_folder(&mut db, "b").unwrap();
    sqlite::add_folder(&mut db, "dest/a").unwrap();

    for (source, name, destination) in [
        ("a", Some("b"), None),
        ("a", None, Some("dest")),
        ("b", Some("a"), Some("dest")),
    ] {
        let result = sqlite::update_folder(&mut db, source, name, destination);

        assert!(
            matches!(result, Err(DbError::Conflict(_))),
            "{source} -> {name:?} in {destination:?}: {result:?}"
        );
    }

    for path in ["a", "b", "dest/a"] {
        assert!(
            sqlite::get_folder_id(&db, path).unwrap().is_some(),
            "{path}"
        );
    }
}

#[test]
fn test_entry_names() {
    for name in [
        "a",
        "file.txt",
        ".hidden",
        "..double",
        "space name",
        &"n".repeat(255),
    ] {
        assert!(is_valid_entry_name(name), "{name:?} should be valid");
    }

    for name in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a\u{0}b",
        "a\nb",
        &"n".repeat(256),
    ] {
        assert!(!is_valid_entry_name(name), "{name:?} should be invalid");
    }
}
